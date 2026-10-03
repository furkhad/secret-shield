"""Unit tests for :mod:`secret_shield.filters.paths`.

Three things are being decided here, and they are tested separately because they
fail differently:

* **Policy** -- is this path eligible at all? A wrong answer wastes time, or
  hides a file.
* **Safety** -- is following this path safe? A wrong answer here is a security
  bug, not a quality problem: a symlink that escapes the root turns "scan this
  directory" into "scan whatever this directory points at".
* **Validation** -- is this *configuration* well formed? A wrong answer here
  means the ignore list quietly does not do what the caller asked.

The symlink tests are the load-bearing ones. They are written to fail loudly if
the containment check is ever removed, because that is the kind of regression
that looks like a simplification in review.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secret_shield.filters.paths import (
    DEFAULT_IGNORED_DIRECTORIES,
    DEFAULT_IGNORED_EXTENSIONS,
    DEFAULT_IGNORED_FILENAMES,
    Decision,
    PathFilterConfig,
    SkipReason,
    default_path_filter_config,
    is_regular_file,
    is_within,
    matches_ignored_path,
    normalize_relative_path,
    resolve_within,
)


# ---------------------------------------------------------------------------
# Policy: which directories are skipped
# ---------------------------------------------------------------------------


class TestIgnoredDirectories:
    @pytest.mark.parametrize("name", [".git", "node_modules", ".venv", "venv", "env"])
    def test_the_documented_names_are_ignored(self, name: str) -> None:
        """The five the stage brief requires, by name, so none can be dropped."""

        assert PathFilterConfig().ignores_directory_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "envs",
            "environment",
            "env.py",
            "venv_old",
            ".venvrc",
            "node_modules_old",
            "myenv",
            "ENV",
            "GIT",
        ],
    )
    def test_near_misses_are_not_ignored(self, name: str) -> None:
        """Exact match, never substring.

        ``envs`` and ``myenv`` are ordinary source directories. Skipping them
        because they *contain* the letters of ``env`` would be a silent loss.
        """

        assert not PathFilterConfig().ignores_directory_name(name)

    def test_a_regular_directory_is_not_ignored(self) -> None:
        for name in (
            "src",
            "tests",
            "lib",
            "docs",
            "build",
            "dist",
            "vendor",
            "target",
        ):
            assert not PathFilterConfig().ignores_directory_name(name), name

    def test_version_control_metadata_is_ignored(self) -> None:
        for name in (".git", ".hg", ".svn"):
            assert PathFilterConfig().ignores_directory_name(name), name

    def test_tool_caches_are_ignored(self) -> None:
        for name in (
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
        ):
            assert PathFilterConfig().ignores_directory_name(name), name

    def test_build_output_is_not_ignored_by_default(self) -> None:
        """Deliberate, and worth a test.

        Build directories are where a copied ``.env`` or an inlined bundle ends
        up. A scanner that skips them has opted out of looking where leaked
        secrets land. Add them to ``ignored_directories`` if a project prefers
        the trade.
        """

        for name in ("build", "dist", "target", "vendor"):
            assert not PathFilterConfig().ignores_directory_name(name), name

    def test_the_default_set_can_be_replaced_entirely(self) -> None:
        config = PathFilterConfig(ignored_directories=frozenset({"only_this"}))
        assert config.ignores_directory_name("only_this")
        assert not config.ignores_directory_name(".git")
        assert not config.ignores_directory_name("node_modules")

    def test_an_empty_set_ignores_nothing(self) -> None:
        config = PathFilterConfig(ignored_directories=frozenset())
        assert not config.ignores_directory_name(".git")
        assert not config.ignores_directory_name("node_modules")


class TestIgnoredFilenames:
    @pytest.mark.parametrize("name", [".DS_Store", "Thumbs.db", "desktop.ini"])
    def test_operating_system_junk_is_ignored(self, name: str) -> None:
        assert PathFilterConfig().ignores_filename(name)

    def test_dotenv_is_not_an_ignored_filename(self) -> None:
        """``.env`` is the single most likely place for a secret.

        It has no extension, so it can never be caught by the extension filter.
        Filtering it here would be catastrophic, so it is asserted directly.
        """

        assert not PathFilterConfig().ignores_filename(".env")
        assert not PathFilterConfig().ignores_filename(".env.local")
        assert not PathFilterConfig().ignores_filename("id_rsa")

    def test_near_misses_are_not_ignored(self) -> None:
        for name in ("DS_Store", "thumbs.db", "desktop_ini", "my.DS_Store"):
            assert not PathFilterConfig().ignores_filename(name), name


class TestIgnoredExtensions:
    @pytest.mark.parametrize(
        "name", ["a.png", "b.JPG", "c.zip", "d.so", "e.woff2", "f.pdf", "g.mp4"]
    )
    def test_binary_formats_are_ignored(self, name: str) -> None:
        assert PathFilterConfig().ignores_extension(name)

    @pytest.mark.parametrize(
        "name",
        [
            "config.py",
            "settings.yaml",
            "app.js",
            "Dockerfile",
            "Makefile",
            ".env",
            "server.pem",
            "id_rsa",
            "key.p12",
            "notes.md",
        ],
    )
    def test_text_formats_are_not_ignored(self, name: str) -> None:
        """Every one of these can hold a credential.

        ``.pem`` and ``id_rsa`` in particular: a private key is text, and the
        scanner must reach it.
        """

        assert not PathFilterConfig().ignores_extension(name), name

    def test_svg_is_not_ignored_because_it_is_text(self) -> None:
        assert not PathFilterConfig().ignores_extension("logo.svg")

    def test_a_dotfile_has_no_extension(self) -> None:
        """``PurePosixPath(".env").suffix`` is empty, which is what we want."""

        assert not PathFilterConfig().ignores_extension(".env")
        assert not PathFilterConfig().ignores_extension(".gitignore")

    def test_only_the_final_suffix_counts(self) -> None:
        """``.tar.gz`` is judged on ``.gz``; a file merely containing a dot is not."""

        assert PathFilterConfig().ignores_extension("archive.tar.gz")
        assert not PathFilterConfig().ignores_extension("notes.txt.png.md")

    def test_matching_is_case_insensitive(self) -> None:
        assert PathFilterConfig().ignores_extension("IMAGE.PNG")
        assert PathFilterConfig().ignores_extension("Archive.ZIP")

    @pytest.mark.parametrize(
        ("supplied", "stored"),
        [("png", ".png"), (".png", ".png"), (".PNG", ".png"), ("PnG", ".png")],
    )
    def test_extensions_are_normalised(self, supplied: str, stored: str) -> None:
        assert PathFilterConfig(ignored_extensions=[supplied]).ignored_extensions == {
            stored
        }

    def test_a_bare_dot_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="bare dot"):
            PathFilterConfig(ignored_extensions=["."])

    def test_a_path_is_not_an_extension(self) -> None:
        with pytest.raises(ValueError, match="extensions, not paths"):
            PathFilterConfig(ignored_extensions=["a/b"])


# ---------------------------------------------------------------------------
# Policy: ignored paths
# ---------------------------------------------------------------------------


class TestIgnoredPaths:
    @pytest.mark.parametrize(
        ("entry", "path", "ignored"),
        [
            ("build", "build", True),
            ("build", "build/x.py", True),
            ("build", "build/deep/y.py", True),
            ("docs/generated", "docs/generated", True),
            ("docs/generated", "docs/generated/api.md", True),
            ("docs/generated", "docs", False),
            ("docs/generated", "docs/other/api.md", False),
            ("build", "buildings/x.py", False),
            ("build", "rebuild/x.py", False),
            ("build", "src/build/x.py", False),
            ("a/b", "a/b/c/d.py", True),
            ("a/b", "a/bc/d.py", False),
        ],
    )
    def test_matching(self, entry: str, path: str, ignored: bool) -> None:
        config = PathFilterConfig(ignored_paths=(entry,))
        assert config.ignores_path(path) is ignored

    def test_separators_are_normalised(self) -> None:
        assert PathFilterConfig(ignored_paths=("docs\\gen",)).ignored_paths == (
            "docs/gen",
        )

    def test_trailing_separators_are_ignored(self) -> None:
        assert PathFilterConfig(ignored_paths=("build/",)).ignored_paths == ("build",)

    def test_entries_are_deduplicated_and_sorted(self) -> None:
        config = PathFilterConfig(ignored_paths=("z", "a", "z", "a/b"))
        assert config.ignored_paths == ("a", "a/b", "z")

    def test_no_entries_means_nothing_matches(self) -> None:
        assert not PathFilterConfig().ignores_path("build/x.py")

    @pytest.mark.parametrize("entry", ["/etc", "/", "\\windows"])
    def test_an_absolute_entry_is_rejected(self, entry: str) -> None:
        """An ignore list is a statement about what is inside the root.

        An absolute entry would mean something different depending on where the
        scan is rooted, which is exactly the location-dependent behaviour that
        makes results irreproducible.
        """

        with pytest.raises(ValueError, match="relative to the scan root"):
            PathFilterConfig(ignored_paths=(entry,))

    @pytest.mark.parametrize("entry", ["..", "../..", "build/../../etc", "a/../.."])
    def test_an_escaping_entry_is_rejected(self, entry: str) -> None:
        with pytest.raises(ValueError, match="must not escape"):
            PathFilterConfig(ignored_paths=(entry,))

    @pytest.mark.parametrize("entry", ["", "   ", ".", "./"])
    def test_an_empty_entry_is_rejected(self, entry: str) -> None:
        with pytest.raises(ValueError):
            PathFilterConfig(ignored_paths=(entry,))

    def test_a_glob_is_treated_as_a_literal_name(self) -> None:
        """Globs are deliberately unsupported, and this is what that means.

        ``"build/*"`` is one directory name containing an asterisk, so it never
        matches a real path. Silently supporting glob would put a
        pattern-matching surface over attacker-influenced filenames.
        """

        config = PathFilterConfig(ignored_paths=("build/*",))
        assert not config.ignores_path("build/x.py")
        assert config.ignores_path("build/*")

    def test_the_helper_agrees_with_the_method(self) -> None:
        config = PathFilterConfig(ignored_paths=("build", "docs/gen"))
        for path in ("build/a", "docs/gen/b", "src/main.py", "rebuild/a"):
            assert matches_ignored_path(
                path, config.ignored_paths
            ) == config.ignores_path(path)

    def test_the_helper_handles_an_empty_list(self) -> None:
        assert not matches_ignored_path("anything", ())


# ---------------------------------------------------------------------------
# The combined decision
# ---------------------------------------------------------------------------


class TestDecision:
    def test_an_ordinary_file_is_accepted(self) -> None:
        decision = PathFilterConfig().decide(
            "main.py", "src/main.py", is_directory=False
        )
        assert decision.include
        assert decision.reason is None

    def test_an_ordinary_directory_is_accepted(self) -> None:
        assert PathFilterConfig().decide("src", "src", is_directory=True)

    def test_a_directory_name_rule_does_not_apply_to_a_file(self) -> None:
        """A file literally named ``.git`` is accepted, on purpose.

        ``ignored_directories`` is a rule about directories, and applying it to
        files would mean a project with a file called ``env`` silently lost a
        file the author clearly meant to scan. The walk compensates where it
        matters: a *symlink* is judged as a directory, so a link named ``.git``
        is still skipped.
        """

        decision = PathFilterConfig().decide(".git", ".git", is_directory=False)
        assert decision.include
        assert decision.reason is None

    def test_rules_are_applied_most_specific_first(self) -> None:
        """A configured path beats a directory name, and a name beats an extension.

        When several rules match the same entry, the reason reported should be
        the one the caller most likely meant, so each assertion below sets up a
        case where two rules both fire and checks which one wins.
        """

        config = PathFilterConfig(
            ignored_directories=frozenset({"build"}),
            ignored_extensions=frozenset({".png"}),
            ignored_paths=("build", "assets/logo.png"),
        )
        # Both the path rule and the directory rule match.
        assert (
            config.decide("build", "build", is_directory=True).reason
            is SkipReason.IGNORED_PATH
        )
        # Only the directory rule matches: the path rule is anchored at the root.
        assert (
            config.decide("build", "assets/build", is_directory=True).reason
            is SkipReason.IGNORED_DIRECTORY
        )
        # The extension rule is the only one that can match a plain file.
        assert (
            config.decide("logo.png", "assets/logo.png", is_directory=False).reason
            is SkipReason.IGNORED_PATH
        )
        assert (
            config.decide("photo.png", "img/photo.png", is_directory=False).reason
            is SkipReason.IGNORED_EXTENSION
        )

    def test_the_relative_path_is_normalised_before_matching(self) -> None:
        config = PathFilterConfig(ignored_paths=("build",))
        for messy in ("./build", "/build/", "build/", "build//"):
            assert config.decide("x.py", messy, is_directory=False).reason is (
                SkipReason.IGNORED_PATH
            ), messy

    def test_an_unusable_relative_path_falls_back_to_the_name(self) -> None:
        config = PathFilterConfig(ignored_extensions=frozenset({".png"}))
        decision = config.decide("logo.png", "", is_directory=False)
        assert decision.reason is SkipReason.IGNORED_EXTENSION

    def test_a_decision_is_truthy_when_included(self) -> None:
        assert bool(PathFilterConfig().decide("a.py", "a.py", is_directory=False))
        assert not bool(PathFilterConfig().decide("a.png", "a.png", is_directory=False))


class TestDecisionInvariants:
    """A Decision cannot be built in a contradictory state."""

    def test_accept_has_no_reason(self) -> None:
        assert Decision.accept() == Decision(include=True, reason=None)

    def test_reject_has_a_reason(self) -> None:
        assert Decision.reject(SkipReason.BINARY).reason is SkipReason.BINARY

    def test_an_accepted_decision_cannot_carry_a_reason(self) -> None:
        with pytest.raises(ValueError, match="cannot carry a skip reason"):
            Decision(include=True, reason=SkipReason.BINARY)

    def test_a_rejected_decision_must_carry_a_reason(self) -> None:
        with pytest.raises(ValueError, match="must carry a skip reason"):
            Decision(include=False, reason=None)

    @pytest.mark.parametrize("value", ["yes", 1, None])
    def test_include_must_be_a_bool(self, value: object) -> None:
        with pytest.raises(TypeError):
            Decision(include=value)  # type: ignore[arg-type]

    def test_reason_must_be_a_skip_reason(self) -> None:
        with pytest.raises(TypeError):
            Decision(include=False, reason="binary")  # type: ignore[arg-type]

    def test_repr_does_not_leak_a_path(self) -> None:
        text = repr(Decision.reject(SkipReason.SYMLINK_OUTSIDE_ROOT))
        assert "symlink-outside-root" in text
        assert "/" not in text


class TestSkipReason:
    def test_every_reason_has_a_description(self) -> None:
        for reason in SkipReason:
            assert reason.description
            assert reason.description.strip()

    def test_every_reason_has_a_distinct_code(self) -> None:
        codes = [reason.value for reason in SkipReason]
        assert len(codes) == len(set(codes))

    def test_policy_reasons_are_classified(self) -> None:
        policy = {
            SkipReason.IGNORED_PATH,
            SkipReason.IGNORED_DIRECTORY,
            SkipReason.IGNORED_FILENAME,
            SkipReason.IGNORED_EXTENSION,
            SkipReason.IGNORED_DEPTH,
            SkipReason.SYMLINK,
            SkipReason.SYMLINK_OUTSIDE_ROOT,
        }
        for reason in SkipReason:
            assert reason.is_policy is (reason in policy), reason

    def test_filesystem_reasons_are_not_policy(self) -> None:
        for reason in (
            SkipReason.TOO_LARGE,
            SkipReason.BINARY,
            SkipReason.UNDECODABLE,
            SkipReason.UNREADABLE,
            SkipReason.VANISHED,
            SkipReason.NOT_A_REGULAR_FILE,
            SkipReason.CIRCULAR_SYMLINK,
        ):
            assert not reason.is_policy, reason

    def test_reasons_serialise_as_plain_strings(self) -> None:
        assert SkipReason.BINARY.value == "binary"
        assert f"{SkipReason.BINARY}" == "binary"


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


class TestNormalizeRelativePath:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a/b.py", "a/b.py"),
            ("./a/b.py", "a/b.py"),
            ("/a/b.py", "a/b.py"),
            ("a//b.py", "a/b.py"),
            ("a/./b.py", "a/b.py"),
            ("a\\b.py", "a/b.py"),
            ("a/b.py/", "a/b.py"),
        ],
    )
    def test_normalisation(self, raw: str, expected: str) -> None:
        assert normalize_relative_path(raw) == expected

    @pytest.mark.parametrize("raw", ["..", "../..", "/../..", "../"])
    def test_parent_segments_are_removed_not_resolved(self, raw: str) -> None:
        """The result is a reporting key, never a path to open.

        Resolving would mean asking the filesystem, and the value must not be
        able to name anything outside the root. Stripping is also what makes it
        total: ``resolve`` can raise on a loop, and a reporting key never needs
        to reach the filesystem.
        """

        assert normalize_relative_path(raw) == ""

    def test_a_parent_segment_does_not_swallow_its_siblings(self) -> None:
        """``a/../b`` becomes ``a/b``, not ``b``.

        Resolving would give ``b``. Stripping keeps ``a``, which is the
        conservative outcome: it cannot accidentally match an ignore rule the
        caller did not write.
        """

        assert normalize_relative_path("a/../b") == "a/b"

    def test_the_fallback_is_used_only_when_needed(self) -> None:
        assert normalize_relative_path("", fallback="x.py") == "x.py"
        assert normalize_relative_path("a/b.py", fallback="x.py") == "a/b.py"

    def test_both_empty_gives_empty_rather_than_looping(self) -> None:
        assert normalize_relative_path("") == ""
        assert normalize_relative_path("", fallback="") == ""

    def test_a_traversal_produces_a_key_inside_the_root(self) -> None:
        """``..`` cannot make the key escape.

        Every escape attempt lands back on a root-relative-looking key. It may
        not name the file the caller was aiming at, but it can only ever name
        something under the root as a *label*, which is all it is used for.
        """

        assert normalize_relative_path("../../etc/passwd") == "etc/passwd"
        assert not normalize_relative_path("../../etc/passwd").startswith("..")
        assert normalize_relative_path("../../../..") == ""

    def test_the_result_is_never_an_absolute_path(self) -> None:
        for raw in ("/etc/passwd", "//etc//passwd", "a/b", "..", ""):
            assert not normalize_relative_path(raw).startswith("/"), raw


# ---------------------------------------------------------------------------
# Safety: symlinks
# ---------------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A root with a file inside it, and a sibling directory outside it."""

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.txt").write_text("inside\n", encoding="utf-8")
    (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
    return root


class TestResolveWithin:
    def test_a_file_inside_the_root_resolves(self, tree: Path) -> None:
        target = resolve_within(tree / "inside.txt", tree.resolve())
        assert target == (tree / "inside.txt").resolve()

    def test_a_file_outside_the_root_does_not(self, tree: Path) -> None:
        outside = tree.parent / "outside" / "secret.txt"
        assert resolve_within(outside, tree.resolve()) is None

    def test_a_symlink_out_of_the_root_is_refused(self, tree: Path) -> None:
        link = tree / "escape.txt"
        link.symlink_to(tree.parent / "outside" / "secret.txt")
        assert resolve_within(link, tree.resolve()) is None

    def test_a_symlink_into_the_root_is_allowed(self, tree: Path) -> None:
        link = tree / "alias.txt"
        link.symlink_to(tree / "inside.txt")
        resolved = resolve_within(link, tree.resolve())
        assert resolved == (tree / "inside.txt").resolve()

    def test_a_symlink_to_the_root_itself_is_allowed(self, tree: Path) -> None:
        """The root contains itself, which is inside the root."""

        link = tree / "self"
        link.symlink_to(tree)
        assert resolve_within(link, tree.resolve()) is not None

    def test_a_chain_of_links_out_of_the_root_is_refused(self, tree: Path) -> None:
        """Two hops must not be laundered by resolving only the first.

        ``a -> b`` and ``b -> /etc/passwd`` together reach outside the root. A
        check that only inspected the first hop would pass this.
        """

        first = tree / "hop1"
        second = tree / "hop2"
        second.symlink_to(tree.parent / "outside" / "secret.txt")
        first.symlink_to(second)
        assert resolve_within(first, tree.resolve()) is None

    def test_a_parent_relative_escape_is_refused(self, tmp_path: Path) -> None:
        """``../`` inside a link is the classic way out of a root."""

        root = tmp_path / "root"
        root.mkdir()
        (tmp_path / "secret.txt").write_text("outside\n", encoding="utf-8")
        link = root / "up.txt"
        link.symlink_to("../secret.txt")
        assert resolve_within(link, root.resolve()) is None

    def test_a_broken_link_is_refused(self, tree: Path) -> None:
        link = tree / "broken"
        link.symlink_to(tree / "does-not-exist")
        assert resolve_within(link, tree.resolve()) is None

    def test_a_link_loop_is_refused(self, tree: Path) -> None:
        """``RuntimeError`` from the resolver must not escape as an exception."""

        first = tree / "loop1"
        second = tree / "loop2"
        first.symlink_to(second)
        second.symlink_to(first)
        assert resolve_within(first, tree.resolve()) is None

    def test_a_non_path_is_refused(self, tree: Path) -> None:
        assert resolve_within(tree, tree.resolve()) is not None  # the root resolves
        assert resolve_within(Path("\x00invalid"), tree.resolve()) is None


class TestIsWithin:
    def test_the_root_is_within_itself(self, tmp_path: Path) -> None:
        assert is_within(tmp_path, tmp_path)

    def test_a_child_is_within(self, tmp_path: Path) -> None:
        assert is_within(tmp_path / "a" / "b", tmp_path)

    def test_a_sibling_with_a_shared_prefix_is_not_within(self, tmp_path: Path) -> None:
        """``/tmp/root`` must not contain ``/tmp/root-evil``.

        A string ``startswith`` would say it does. This is why the check is
        ``Path.relative_to`` and not a prefix test.
        """

        assert not is_within(tmp_path / "root-evil", tmp_path / "root")

    def test_a_parent_is_not_within(self, tmp_path: Path) -> None:
        assert not is_within(tmp_path, tmp_path / "root")

    def test_a_similar_name_is_not_within(self, tmp_path: Path) -> None:
        root = tmp_path / "app"
        assert not is_within(tmp_path / "app2" / "x", root)
        assert not is_within(tmp_path / "application" / "x", root)


class TestIsRegularFile:
    def test_a_regular_file(self, tree: Path) -> None:
        assert is_regular_file(tree / "inside.txt")

    def test_a_directory_is_not_a_regular_file(self, tree: Path) -> None:
        assert not is_regular_file(tree)

    def test_a_missing_path_is_not(self, tree: Path) -> None:
        assert not is_regular_file(tree / "nope")

    def test_a_symlink_is_not_a_regular_file_by_default(self, tree: Path) -> None:
        """The default is what stops the walk stepping outside the root."""

        link = tree / "alias.txt"
        link.symlink_to(tree / "inside.txt")
        assert not is_regular_file(link)
        assert not is_regular_file(link, follow_symlinks=False)

    def test_a_symlink_to_a_file_is_one_when_following(self, tree: Path) -> None:
        link = tree / "alias.txt"
        link.symlink_to(tree / "inside.txt")
        assert is_regular_file(link, follow_symlinks=True)

    def test_a_broken_symlink_is_not(self, tree: Path) -> None:
        link = tree / "broken"
        link.symlink_to(tree / "nope")
        assert not is_regular_file(link, follow_symlinks=True)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
    def test_a_fifo_is_not_a_regular_file(self, tree: Path) -> None:
        """Opening a FIFO blocks until a writer appears.

        This is why special files are skipped rather than read, and the test
        exists so nobody "simplifies" the check to ``not is_dir()``.
        """

        fifo = tree / "pipe"
        os.mkfifo(fifo)
        assert not is_regular_file(fifo, follow_symlinks=True)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
    def test_a_socket_is_not_a_regular_file(self, tree: Path) -> None:
        import socket

        sock_path = tree / "sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(sock_path))
            assert not is_regular_file(sock_path, follow_symlinks=True)
        finally:
            server.close()

    @pytest.mark.skipif(not os.path.exists("/dev/null"), reason="no /dev/null")
    def test_a_character_device_is_not_a_regular_file(self) -> None:
        assert not is_regular_file(Path("/dev/null"), follow_symlinks=True)


# ---------------------------------------------------------------------------
# Configuration contract
# ---------------------------------------------------------------------------


class TestPathFilterConfigContract:
    def test_defaults_are_the_documented_sets(self) -> None:
        config = PathFilterConfig()
        assert config.ignored_directories == DEFAULT_IGNORED_DIRECTORIES
        assert config.ignored_filenames == DEFAULT_IGNORED_FILENAMES
        assert config.ignored_extensions == DEFAULT_IGNORED_EXTENSIONS
        assert config.ignored_paths == ()
        assert config.follow_symlinks is False
        assert config.max_depth is None

    def test_symlink_following_is_off_by_default(self) -> None:
        """The safe default, asserted so it cannot be flipped by accident."""

        assert PathFilterConfig().follow_symlinks is False

    def test_the_factory_returns_a_fresh_equal_object(self) -> None:
        assert default_path_filter_config() == PathFilterConfig()
        assert default_path_filter_config() is not default_path_filter_config()

    def test_the_config_is_immutable(self) -> None:
        with pytest.raises(Exception):
            PathFilterConfig().follow_symlinks = True  # type: ignore[misc]

    def test_equal_configurations_compare_equal(self) -> None:
        """So "the same configuration" is a checkable statement."""

        assert PathFilterConfig(ignored_paths=("b", "a")) == PathFilterConfig(
            ignored_paths=("a", "b")
        )

    @pytest.mark.parametrize("field", ["ignored_directories", "ignored_filenames"])
    def test_a_name_may_not_contain_a_separator(self, field: str) -> None:
        with pytest.raises(ValueError, match="bare names, not paths"):
            PathFilterConfig(**{field: ("a/b",)})

    @pytest.mark.parametrize("field", ["ignored_directories", "ignored_filenames"])
    def test_an_empty_name_is_rejected(self, field: str) -> None:
        with pytest.raises(ValueError, match="empty name"):
            PathFilterConfig(**{field: ("",)})

    @pytest.mark.parametrize(
        "field", ["ignored_directories", "ignored_filenames", "ignored_extensions"]
    )
    def test_a_bare_string_is_rejected(self, field: str) -> None:
        """A string is iterable, so this would otherwise become a set of letters."""

        with pytest.raises(TypeError, match="not a string"):
            PathFilterConfig(**{field: "png"})

    def test_a_non_string_element_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="only strings"):
            PathFilterConfig(ignored_directories=frozenset({1}))  # type: ignore[arg-type]

    def test_ignored_paths_rejects_a_bare_string(self) -> None:
        with pytest.raises(TypeError, match="not a string"):
            PathFilterConfig(ignored_paths="build")

    def test_a_non_bool_follow_symlinks_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="follow_symlinks must be a bool"):
            PathFilterConfig(follow_symlinks="yes")  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", [-1, -10])
    def test_a_negative_depth_is_rejected(self, value: int) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            PathFilterConfig(max_depth=value)

    @pytest.mark.parametrize("value", [True, 1.0, "2"])
    def test_a_non_integer_depth_is_rejected(self, value: object) -> None:
        with pytest.raises(TypeError, match="max_depth"):
            PathFilterConfig(max_depth=value)  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", [0, 1, 5])
    def test_zero_depth_is_allowed(self, value: int) -> None:
        """``max_depth=0`` means "only the root's own files", which is meaningful."""

        assert PathFilterConfig(max_depth=value).max_depth == value
