"""Unit tests for :mod:`secret_shield.sources.filesystem`.

The walk is the part of a scanner most exposed to the machine it runs on: it
reads directory entries, follows or refuses links, opens files, and runs where
files change underneath it. Every one of those is a place where the honest
answer is "I could not read that", and the tests below are mostly about whether
this module actually says that instead of raising, skipping silently, or
following something it should not.

Two properties are tested hardest because breaking them is quiet:

**Determinism.** Filesystem enumeration order is unspecified and does vary. If
the result order follows it, then two scans of an unchanged tree disagree, a CI
diff becomes noise, and a "fix" appears to fix nothing. The tests here pin the
ordering explicitly rather than only checking that a scan finds things.

**Containment.** "Scan this directory" must not become "scan whatever this
directory points at". The symlink tests are written so that removing the
containment check makes them fail, rather than making them pass vacuously.

Permission-failure tests skip when running as root, because root reads
everything and the failure cannot be provoked. Skipping is honest; pretending
to test it would not be.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from secret_shield.filters.paths import PathFilterConfig, SkipReason
from secret_shield.models import DetectorKind, ScanResult
from secret_shield.scanner import ScanConfig
from secret_shield.sources import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_LINE_LENGTH,
    PathScanConfig,
    WalkResult,
    default_path_scan_config,
    scan_path,
    walk,
)

RUNNING_AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
needs_non_root = pytest.mark.skipif(
    RUNNING_AS_ROOT, reason="root bypasses filesystem permission checks"
)

# Synthetic values. Fabricated for these tests; no real credential appears here.
SYNTHETIC_API_KEY = "sk-proj-" + "A7bC2dE9fG1hJ3kL5mN8pQ4rS6tU0vW"


def config(**overrides: object) -> PathScanConfig:
    """Build a filesystem config with defaults, overriding what a test names."""

    return PathScanConfig(**overrides)  # type: ignore[arg-type]


def finding_keys(result: ScanResult) -> list[tuple[str, str, int, int]]:
    """A stable identity for each finding, for order-sensitive assertions."""

    return [
        (f.rule_id, f.location.path, f.location.line, f.location.column)
        for f in result.sorted_findings()
    ]


def error_codes(result: ScanResult) -> list[str]:
    return sorted({error.code or "" for error in result.errors})


# ---------------------------------------------------------------------------
# Walking a tree
# ---------------------------------------------------------------------------


class TestWalkStructure:
    def test_an_empty_directory_yields_nothing(self, tmp_path: Path) -> None:
        result = walk(tmp_path, config())
        assert result.files == ()
        assert result.skipped == ()
        assert result.errors == ()

    def test_files_are_found_at_every_depth(self, tmp_path: Path) -> None:
        (tmp_path / "top.py").write_text("a = 1\n", encoding="utf-8")
        (tmp_path / "src" / "app").mkdir(parents=True)
        (tmp_path / "src" / "one.py").write_text("a = 1\n", encoding="utf-8")
        (tmp_path / "src" / "app" / "two.py").write_text("a = 1\n", encoding="utf-8")

        relatives = [entry.relative for entry in walk(tmp_path, config()).files]
        assert relatives == ["src/app/two.py", "src/one.py", "top.py"]

    def test_relative_paths_are_posix_and_root_anchored(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "c.py").write_text("a = 1\n", encoding="utf-8")

        relatives = [entry.relative for entry in walk(tmp_path, config()).files]
        assert relatives == ["a/b/c.py"]
        assert "\\" not in relatives[0]
        assert not relatives[0].startswith("/")
        assert tmp_path.name not in relatives[0]

    def test_a_directory_is_never_a_candidate(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        assert walk(tmp_path, config()).files == ()

    def test_the_size_comes_from_the_listing(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text("hello\n", encoding="utf-8")
        assert walk(tmp_path, config()).files[0].size == 6

    def test_the_root_is_reported_as_given(self, tmp_path: Path) -> None:
        assert walk(str(tmp_path), config()).root == str(tmp_path)

    def test_a_string_root_is_accepted(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert len(walk(str(tmp_path), config()).files) == 1

    @pytest.mark.parametrize("value", [42, "config", object(), [], ScanConfig()])
    def test_a_non_config_is_rejected(self, tmp_path: Path, value: object) -> None:
        """A programming error in the caller, so it is loud rather than ignored."""

        with pytest.raises(TypeError, match="PathScanConfig"):
            walk(tmp_path, value)  # type: ignore[arg-type]

    def test_omitting_the_config_uses_the_defaults(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert len(walk(tmp_path).files) == 1


class TestWalkDeterminism:
    def test_results_are_sorted_by_relative_path(self, tmp_path: Path) -> None:
        for name in ("z.py", "a.py", "m.py", "b.py", "y.py"):
            (tmp_path / name).write_text("x = 1\n", encoding="utf-8")

        relatives = [entry.relative for entry in walk(tmp_path, config()).files]
        assert relatives == sorted(relatives)
        assert relatives == ["a.py", "b.py", "m.py", "y.py", "z.py"]

    def test_two_walks_agree_exactly(self, tmp_path: Path) -> None:
        """The literal claim: two scans of an unchanged tree are identical."""

        for index in range(12):
            sub = tmp_path / f"dir{index % 3}"
            sub.mkdir(exist_ok=True)
            (sub / f"file{index}.py").write_text(f"x = {index}\n", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "skipped.py").write_text(
            "x = 1\n", encoding="utf-8"
        )

        first = walk(tmp_path, config())
        second = walk(tmp_path, config())
        assert [f.relative for f in first.files] == [f.relative for f in second.files]
        assert first.counts_by_reason() == second.counts_by_reason()
        assert first == second

    def test_skips_are_sorted_too(self, tmp_path: Path) -> None:
        for name in ("z.png", "a.png", "node_modules", "a.png"):
            pass
        (tmp_path / "z.png").write_bytes(b"\x89PNG")
        (tmp_path / "a.png").write_bytes(b"\x89PNG")
        (tmp_path / "m.png").write_bytes(b"\x89PNG")

        skipped = [entry.relative for entry in walk(tmp_path, config()).skipped]
        assert skipped == sorted(skipped)

    def test_the_result_is_hashable_and_comparable(self, tmp_path: Path) -> None:
        """So a caller can cache or deduplicate on it."""

        first = walk(tmp_path, config())
        second = walk(tmp_path, config())
        assert first == second
        assert hash(first) == hash(second)


class TestWalkFilters:
    def test_ignored_directories_are_not_descended(self, tmp_path: Path) -> None:
        for name in (".git", "node_modules", ".venv", "venv", "env"):
            sub = tmp_path / name / "deep"
            sub.mkdir(parents=True)
            (sub / "leak.py").write_text("x = 1\n", encoding="utf-8")

        assert walk(tmp_path, config()).files == ()

    def test_an_ignored_directory_is_skipped_by_name(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        result = walk(tmp_path, config())
        assert result.skipped_by(SkipReason.IGNORED_DIRECTORY) == (".git",)

    def test_ignored_extensions_are_skipped(self, tmp_path: Path) -> None:
        for name in ("a.png", "b.ZIP", "c.so"):
            (tmp_path / name).write_bytes(b"\x00" * 4)

        result = walk(tmp_path, config())
        assert result.files == ()
        assert len(result.skipped_by(SkipReason.IGNORED_EXTENSION)) == 3

    def test_ignored_filenames_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".DS_Store").write_bytes(b"\x00" * 4)
        result = walk(tmp_path, config())
        assert result.skipped_by(SkipReason.IGNORED_FILENAME) == (".DS_Store",)

    def test_configured_ignored_paths_are_honoured(self, tmp_path: Path) -> None:
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "x.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")

        result = walk(
            tmp_path, config(filters=PathFilterConfig(ignored_paths=("build",)))
        )
        assert [entry.relative for entry in result.files] == ["keep.py"]
        # The directory itself is reported, not each file under it: the walk does
        # not descend, so it never reaches the files to record them individually.
        assert result.skipped_by(SkipReason.IGNORED_PATH) == ("build",)

    def test_dotenv_is_scanned(self, tmp_path: Path) -> None:
        """.env is where secrets actually are. Losing it would be a disaster."""

        (tmp_path / ".env").write_text(
            f'API_KEY="{SYNTHETIC_API_KEY}"\n', encoding="utf-8"
        )
        assert [entry.relative for entry in walk(tmp_path, config()).files] == [".env"]

    def test_private_key_files_are_candidates(self, tmp_path: Path) -> None:
        for name in ("id_rsa", "server.pem", "key.p12", "cert.crt"):
            (tmp_path / name).write_text(
                "-----BEGIN PRIVATE KEY-----\n", encoding="utf-8"
            )
        assert len(walk(tmp_path, config()).files) == 4

    def test_an_oversized_file_is_skipped_before_reading(self, tmp_path: Path) -> None:
        (tmp_path / "big.py").write_text("x = 1\n" * 500, encoding="utf-8")
        (tmp_path / "small.py").write_text("x = 1\n", encoding="utf-8")

        result = walk(tmp_path, config(scan=ScanConfig(max_file_size=100)))
        assert [entry.relative for entry in result.files] == ["small.py"]
        assert result.skipped_by(SkipReason.TOO_LARGE) == ("big.py",)


class TestWalkDepth:
    @pytest.fixture
    def deep(self, tmp_path: Path) -> Path:
        (tmp_path / "top.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "one").mkdir()
        (tmp_path / "one" / "mid.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "one" / "two").mkdir()
        (tmp_path / "one" / "two" / "deep.py").write_text("x = 1\n", encoding="utf-8")
        return tmp_path

    def test_no_limit_walks_everything(self, deep: Path) -> None:
        assert len(walk(deep, config()).files) == 3

    def test_depth_zero_scans_only_the_root(self, deep: Path) -> None:
        result = walk(deep, config(filters=PathFilterConfig(max_depth=0)))
        assert [entry.relative for entry in result.files] == ["top.py"]

    def test_depth_one_includes_one_directory(self, deep: Path) -> None:
        result = walk(deep, config(filters=PathFilterConfig(max_depth=1)))
        assert [entry.relative for entry in result.files] == ["one/mid.py", "top.py"]

    def test_the_excluded_directory_is_reported(self, deep: Path) -> None:
        result = walk(deep, config(filters=PathFilterConfig(max_depth=0)))
        assert result.skipped_by(SkipReason.IGNORED_DEPTH) == ("one",)


# ---------------------------------------------------------------------------
# Symlinks and containment
# ---------------------------------------------------------------------------


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    """A root with content, and a sibling outside it holding the bait."""

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.py").write_text("x = 1\n", encoding="utf-8")
    (outside / "leak.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
    return root, outside


class TestSymlinksAreNotFollowedByDefault:
    def test_a_symlink_is_skipped(self, roots: tuple[Path, Path]) -> None:
        root, _ = roots
        (root / "alias.py").symlink_to(root / "inside.py")

        result = walk(root, config())
        assert [entry.relative for entry in result.files] == ["inside.py"]
        assert result.skipped_by(SkipReason.SYMLINK) == ("alias.py",)

    def test_a_symlinked_directory_is_not_descended(
        self, roots: tuple[Path, Path]
    ) -> None:
        root, _ = roots
        (root / "aliasdir").symlink_to(root)

        result = walk(root, config())
        assert result.skipped_by(SkipReason.SYMLINK) == ("aliasdir",)

    def test_the_default_really_is_off(self, roots: tuple[Path, Path]) -> None:
        """Asserted directly so a flipped default cannot pass unnoticed."""

        root, _ = roots
        (root / "alias.py").symlink_to(root / "inside.py")
        assert PathFilterConfig().follow_symlinks is False
        assert len(walk(root, config()).files) == 1


class TestSymlinksInsideTheRoot:
    def _allowing(self) -> PathScanConfig:
        return config(filters=PathFilterConfig(follow_symlinks=True))

    def test_a_link_to_an_inside_file_is_scanned(
        self, roots: tuple[Path, Path]
    ) -> None:
        root, _ = roots
        (root / "alias.py").symlink_to(root / "inside.py")

        relatives = [entry.relative for entry in walk(root, self._allowing()).files]
        assert relatives == ["alias.py", "inside.py"]

    def test_each_path_is_reported_under_its_own_name(
        self, roots: tuple[Path, Path]
    ) -> None:
        """A link and its target are two paths, so they are two locations.

        Reporting both under the target's name would make the output depend on
        whether a link happened to exist, which is not a property of the code.
        Reporting the link path is also the honest answer: that is the path the
        user must open to see the secret. The cost is that the same content can
        be reported twice; deduping it is Stage 4 fusion's job, and doing it here
        would silently hide one of two real paths.
        """

        root, _ = roots
        (root / "real.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        (root / "alias.py").symlink_to(root / "real.py")

        result = scan_path(root, self._allowing())
        assert result.files_scanned == 3  # inside.py, real.py and the link
        assert {finding.location.path for finding in result.findings} == {
            "real.py",
            "alias.py",
        }

    def test_a_link_out_of_the_root_is_refused(self, roots: tuple[Path, Path]) -> None:
        root, outside = roots
        (root / "escape.py").symlink_to(outside / "leak.py")

        result = walk(root, self._allowing())
        assert [entry.relative for entry in result.files] == ["inside.py"]
        assert result.skipped_by(SkipReason.SYMLINK_OUTSIDE_ROOT) == ("escape.py",)

    def test_nothing_outside_the_root_is_ever_read(
        self, roots: tuple[Path, Path]
    ) -> None:
        """The load-bearing test. Removing containment makes it fail."""

        root, outside = roots
        (root / "escape.py").symlink_to(outside / "leak.py")
        (root / "deep").mkdir()
        (root / "deep" / "up.py").symlink_to("../../outside/leak.py")
        (root / "hop1.py").symlink_to(root / "hop2.py")
        (root / "hop2.py").symlink_to(outside / "leak.py")

        for result in (
            walk(root, self._allowing()),
            walk(root, config()),
            scan_path(root, self._allowing()),
            scan_path(root, config()),
        ):
            texts = [
                getattr(item, "relative", getattr(item, "path", ""))
                for item in getattr(result, "files", ())
            ]
            assert not any("leak" in text for text in texts), texts

    def test_a_broken_link_is_skipped_not_fatal(self, roots: tuple[Path, Path]) -> None:
        root, _ = roots
        (root / "broken.py").symlink_to(root / "gone.py")

        result = walk(root, self._allowing())
        assert [entry.relative for entry in result.files] == ["inside.py"]
        assert result.skipped_by(SkipReason.VANISHED) == ("broken.py",)
        assert result.errors == ()

    def test_a_link_loop_is_broken(self, roots: tuple[Path, Path]) -> None:
        root, _ = roots
        (root / "a").symlink_to(root / "b")
        (root / "b").symlink_to(root / "a")

        result = walk(root, self._allowing())
        assert [entry.relative for entry in result.files] == ["inside.py"]
        assert result.skipped_by(SkipReason.VANISHED)

    def test_a_directory_loop_is_broken(self, roots: tuple[Path, Path]) -> None:
        """``a -> b -> a`` must terminate, not recurse until the stack dies."""

        root, _ = roots
        (root / "a").mkdir()
        (root / "a" / "self").symlink_to(root / "a")

        result = walk(root, self._allowing())
        assert len(result.files) == 1
        assert result.skipped_by(SkipReason.CIRCULAR_SYMLINK) == ("a/self",)

    def test_a_link_to_a_fifo_is_skipped(self, roots: tuple[Path, Path]) -> None:
        root, _ = roots
        fifo = root / "pipe"
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError):  # pragma: no cover - platform dependent
            pytest.skip("no FIFO support")
        (root / "fifo-link").symlink_to(fifo)

        result = walk(root, self._allowing())
        assert "fifo-link" in result.skipped_by(SkipReason.NOT_A_REGULAR_FILE)


class TestSpecialFiles:
    def test_a_fifo_is_not_a_candidate(self, tmp_path: Path) -> None:
        """Opening a FIFO blocks forever waiting for a writer."""

        try:
            os.mkfifo(tmp_path / "pipe")
        except (AttributeError, OSError):  # pragma: no cover - platform dependent
            pytest.skip("no FIFO support")

        result = walk(tmp_path, config())
        assert result.files == ()
        assert result.skipped_by(SkipReason.NOT_A_REGULAR_FILE) == ("pipe",)

    @pytest.mark.skipif(sys.platform == "win32", reason="no /dev/null")
    def test_a_character_device_is_not_a_candidate(self, tmp_path: Path) -> None:
        (tmp_path / "null").symlink_to("/dev/null")
        result = walk(tmp_path, config(filters=PathFilterConfig(follow_symlinks=True)))
        assert result.files == ()


# ---------------------------------------------------------------------------
# Bad roots
# ---------------------------------------------------------------------------


class TestBadRoots:
    def test_a_missing_root_is_reported_not_raised(self, tmp_path: Path) -> None:
        result = walk(tmp_path / "nope", config())
        assert result.files == ()
        assert error_codes(result) == ["not-found"]

    def test_a_file_as_root_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        assert error_codes(walk(target, config())) == ["root-not-a-directory"]

    def test_a_fifo_as_root_is_reported(self, tmp_path: Path) -> None:
        try:
            os.mkfifo(tmp_path / "pipe")
        except (AttributeError, OSError):  # pragma: no cover - platform dependent
            pytest.skip("no FIFO support")
        assert error_codes(walk(tmp_path / "pipe", config())) == [
            "root-not-a-directory"
        ]

    @needs_non_root
    def test_an_unreadable_root_is_reported(self, tmp_path: Path) -> None:
        root = tmp_path / "locked"
        root.mkdir()
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        root.chmod(0o000)
        try:
            result = walk(root, config())
            assert result.files == ()
            assert error_codes(result) == ["read-failed"]
        finally:
            root.chmod(0o755)

    def test_a_link_loop_as_root_is_reported(self, tmp_path: Path) -> None:
        first = tmp_path / "a"
        second = tmp_path / "b"
        first.symlink_to(second)
        second.symlink_to(first)

        result = walk(first, config())
        assert result.files == ()
        assert error_codes(result) == ["stat-failed"]

    def test_an_unreadable_subdirectory_does_not_stop_the_scan(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
        locked = root / "locked"
        locked.mkdir()
        (locked / "hidden.py").write_text("x = 1\n", encoding="utf-8")
        locked.chmod(0o000)
        try:
            if os.geteuid() == 0:  # pragma: no cover - guarded by needs_non_root
                pytest.skip("root bypasses permission checks")
            result = walk(root, config())
            assert [entry.relative for entry in result.files] == ["ok.py"]
            assert error_codes(result) == ["read-failed"]
        finally:
            locked.chmod(0o755)


class TestFilesThatDisappear:
    def test_a_file_removed_during_the_scan_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A build running alongside the scan does this routinely."""

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
        real_lstat = os.lstat

        def lstat_then_fail(path: object, **kwargs: object) -> object:
            if str(path).endswith("b.py"):
                raise FileNotFoundError(path)
            return real_lstat(path)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "lstat", lstat_then_fail)
        result = walk(tmp_path, config())
        assert [entry.relative for entry in result.files] == ["a.py"]
        assert result.skipped_by(SkipReason.VANISHED) == ("b.py",)

    def test_an_unstattable_entry_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One entry failing its ``lstat`` must not end the walk."""

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        real_lstat = os.lstat
        root = str(tmp_path)

        def deny_entries_below_root(path: object, **kwargs: object) -> object:
            # The root is resolved first and must succeed, otherwise the walk
            # never starts and the test would prove nothing about entries.
            if str(path).startswith(root + os.sep):
                raise PermissionError(path)
            return real_lstat(path)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "lstat", deny_entries_below_root)
        result = walk(tmp_path, config())
        assert result.files == ()
        assert result.skipped_by(SkipReason.UNREADABLE) == ("a.py",)
        assert result.errors == ()

    def test_a_directory_removed_mid_walk_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        real_scandir = os.scandir

        def scandir_then_fail(
            path: object = ".", *args: object, **kwargs: object
        ) -> object:
            if str(path).endswith("root"):
                raise FileNotFoundError(path)
            return real_scandir(path)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "scandir", scandir_then_fail)
        result = walk(root, config())
        assert error_codes(result) == ["vanished"]

    def test_an_unreadable_subdirectory_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
        real_scandir = os.scandir

        def scandir_deny_subdirs(
            path: object = ".", *args: object, **kwargs: object
        ) -> object:
            if str(path).endswith("root"):
                raise PermissionError(path)
            return real_scandir(path)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "scandir", scandir_deny_subdirs)
        result = walk(root, config())
        assert error_codes(result) == ["read-failed"]
        assert result.files == ()


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


class TestBounds:
    def test_max_files_caps_the_candidate_list(self, tmp_path: Path) -> None:
        for index in range(10):
            (tmp_path / f"f{index}.py").write_text("x = 1\n", encoding="utf-8")

        result = walk(tmp_path, config(max_files=4))
        assert len(result.files) == 4
        assert result.truncated is True

    def test_truncation_is_an_error_not_a_clean_result(self, tmp_path: Path) -> None:
        """A partial scan must never be mistakable for a clean one."""

        for index in range(10):
            (tmp_path / f"f{index}.py").write_text("x = 1\n", encoding="utf-8")

        result = walk(tmp_path, config(max_files=4))
        assert "too-many-files" in error_codes(result)

    def test_being_under_the_cap_is_not_truncated(self, tmp_path: Path) -> None:
        for index in range(3):
            (tmp_path / f"f{index}.py").write_text("x = 1\n", encoding="utf-8")

        result = walk(tmp_path, config(max_files=4))
        assert result.truncated is False
        assert result.errors == ()

    def test_the_default_cap_is_documented_and_large(self) -> None:
        assert DEFAULT_MAX_FILES == 100_000
        assert DEFAULT_MAX_LINE_LENGTH == 65_536


class TestSymlinkIdentityIsChecked:
    def test_a_swapped_symlink_is_refused_at_read_time(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A link repointed after the walk is the one race we can close.

        The walk resolves the link, records which inode it landed on, and the
        read re-checks that the open file is still that inode. Swapping the link
        in between is then caught instead of silently read.
        """

        root, outside = roots
        link = root / "inside_link.py"
        link.symlink_to(root / "inside.py")
        settings = config(filters=PathFilterConfig(follow_symlinks=True))

        walked = walk(root, settings)
        entry = next(item for item in walked.files if item.relative == "inside_link.py")
        assert entry.identity is not None

        # Now repoint the link at the file outside the root.
        link.unlink()
        link.symlink_to(outside / "leak.py")

        from secret_shield.sources import filesystem

        outcome = filesystem._analyze_file(entry, settings)
        assert outcome.analyzed is False
        assert [error.code for error in outcome.errors] == ["vanished"]

    def test_an_unchanged_symlink_still_scans(self, roots: tuple[Path, Path]) -> None:
        """The check must not reject the good case it was added for."""

        root, _ = roots
        link = root / "inside_link.py"
        link.symlink_to(root / "inside.py")
        settings = config(filters=PathFilterConfig(follow_symlinks=True))

        entry = next(
            item
            for item in walk(root, settings).files
            if item.relative == "inside_link.py"
        )
        assert entry.identity is not None

        from secret_shield.sources import filesystem

        outcome = filesystem._analyze_file(entry, settings)
        assert outcome.analyzed is True
        assert outcome.errors == ()

    def test_a_plain_file_carries_no_identity_to_check(self, tmp_path: Path) -> None:
        """Checking a non-symlink would be a wasted syscall per file."""

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        entry = walk(tmp_path, config()).files[0]
        assert entry.identity is None


# ---------------------------------------------------------------------------
# Configuration contract
# ---------------------------------------------------------------------------


class TestConfigContract:
    def test_defaults_are_the_documented_values(self) -> None:
        settings = config()
        assert settings.max_line_length == DEFAULT_MAX_LINE_LENGTH
        assert settings.max_files == DEFAULT_MAX_FILES
        assert settings.registry is None

    def test_the_factory_returns_a_fresh_equal_object(self) -> None:
        assert default_path_scan_config() == config()
        assert default_path_scan_config() is not default_path_scan_config()

    def test_the_config_is_immutable(self) -> None:
        with pytest.raises(Exception):
            config().max_files = 1  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("field", "value", "error"),
        [
            ("scan", "not a config", TypeError),
            ("filters", "not a config", TypeError),
            ("binary", "not a config", TypeError),
            ("registry", "not a registry", TypeError),
            ("max_line_length", "long", TypeError),
            ("max_files", "many", TypeError),
            ("max_line_length", True, TypeError),
            ("max_files", 1.5, TypeError),
            ("max_line_length", 0, ValueError),
            ("max_files", 0, ValueError),
            ("max_files", -1, ValueError),
        ],
    )
    def test_bad_settings_are_rejected(
        self, field: str, value: object, error: type[Exception]
    ) -> None:
        with pytest.raises(error):
            config(**{field: value})

    def test_the_config_is_hashable(self) -> None:
        assert hash(config()) == hash(config())

    def test_rules_defaults_to_the_shipped_catalog(self) -> None:
        from secret_shield.detectors import default_registry

        assert len(config().rules()) == len(default_registry())

    def test_rules_honours_a_supplied_registry(self) -> None:
        from secret_shield.detectors import default_registry

        registry = default_registry()
        assert config(registry=registry).rules() is registry


class TestWalkResultContract:
    def test_lists_become_tuples(self) -> None:
        result = WalkResult(root="x", files=[], skipped=[], errors=[])
        assert result.files == ()
        assert isinstance(result.files, tuple)

    def test_a_wrong_element_type_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="SkippedEntry"):
            WalkResult(root="x", skipped=["a.py"])  # type: ignore[list-item]

    def test_truncated_must_be_a_bool(self) -> None:
        with pytest.raises(TypeError, match="truncated"):
            WalkResult(root="x", truncated="yes")  # type: ignore[arg-type]

    def test_counts_by_reason_is_sorted_and_zero_for_nothing(self) -> None:
        result = WalkResult(root="x")
        assert result.counts_by_reason() == {}

    def test_skipped_by_returns_paths_for_one_reason(self, tmp_path: Path) -> None:
        (tmp_path / "a.png").write_bytes(b"\x89PNG")
        (tmp_path / "b.png").write_bytes(b"\x89PNG")
        result = walk(tmp_path, config())
        assert result.skipped_by(SkipReason.IGNORED_EXTENSION) == ("a.png", "b.png")
        assert result.skipped_by(SkipReason.BINARY) == ()


# ---------------------------------------------------------------------------
# Reading and scanning
# ---------------------------------------------------------------------------


class TestScanPath:
    def test_a_clean_file_yields_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "ok.py"
        target.write_text("x = 1\n", encoding="utf-8")
        result = scan_path(target, config())
        assert result.findings == ()
        assert result.errors == ()
        assert result.files_scanned == 1
        assert result.bytes_scanned == 6

    def test_a_finding_is_reported_at_the_right_place(self, tmp_path: Path) -> None:
        target = tmp_path / "config.py"
        target.write_text(f'x = 1\nAPI = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        result = scan_path(target, config())
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.location.path == str(target)
        assert finding.location.line == 2

    def test_a_directory_is_scanned(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.py").write_text(
            f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8"
        )

        result = scan_path(tmp_path, config())
        assert result.files_scanned == 2
        assert len(result.findings) == 2

    def test_directory_findings_use_relative_paths(self, tmp_path: Path) -> None:
        """An absolute path in a report leaks the scanner's own directory layout."""

        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "leak.py").write_text(
            f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8"
        )

        result = scan_path(tmp_path, config())
        assert {finding.location.path for finding in result.findings} == {"sub/leak.py"}
        assert str(tmp_path) not in result.findings[0].location.path

    def test_a_string_path_is_accepted(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert scan_path(str(tmp_path), config()).files_scanned == 1

    def test_findings_are_sorted(self, tmp_path: Path) -> None:
        (tmp_path / "z.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        (tmp_path / "a.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")

        paths = [
            finding.location.path
            for finding in scan_path(tmp_path, config()).sorted_findings()
        ]
        assert paths == ["a.py", "z.py"]

    def test_the_result_carries_a_version_and_a_duration(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = scan_path(tmp_path, config())
        assert result.tool_version
        assert result.duration_seconds >= 0.0

    def test_two_scans_produce_identical_findings(self, tmp_path: Path) -> None:
        """The determinism claim, end to end rather than per file."""

        for index in range(8):
            sub = tmp_path / f"d{index % 3}"
            sub.mkdir(exist_ok=True)
            (sub / f"f{index}.py").write_text(
                f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8"
            )

        assert finding_keys(scan_path(tmp_path, config())) == finding_keys(
            scan_path(tmp_path, config())
        )

    def test_an_empty_directory_is_a_clean_result(self, tmp_path: Path) -> None:
        result = scan_path(tmp_path, config())
        assert result.findings == ()
        assert result.files_scanned == 0
        assert result.bytes_scanned == 0

    def test_the_default_config_is_used_when_none_is_given(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "x.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n')
        assert scan_path(tmp_path).files_scanned == 0


class TestScanPathFailures:
    def test_a_missing_path_is_reported_not_raised(self, tmp_path: Path) -> None:
        result = scan_path(tmp_path / "nope", config())
        assert error_codes(result) == ["not-found"]
        assert result.files_scanned == 0

    def test_a_fifo_is_reported_not_opened(self, tmp_path: Path) -> None:
        try:
            os.mkfifo(tmp_path / "pipe")
        except (AttributeError, OSError):  # pragma: no cover - platform dependent
            pytest.skip("no FIFO support")
        assert error_codes(scan_path(tmp_path / "pipe", config())) == [
            "not-a-regular-file"
        ]

    def test_an_unstattable_path_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def always_denied(path: object = ".", **kwargs: object) -> object:
            raise PermissionError(path)

        monkeypatch.setattr(os, "stat", always_denied)
        assert error_codes(scan_path(tmp_path, config())) == ["stat-failed"]

    @needs_non_root
    def test_an_unreadable_file_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.py"
        target.write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        target.chmod(0o000)
        try:
            result = scan_path(target, config())
            assert error_codes(result) == ["read-failed"]
            assert result.findings == ()
            assert result.files_scanned == 0
        finally:
            target.chmod(0o644)

    def test_one_unreadable_file_does_not_stop_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")
        (root / "b.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")

        real_open = open

        def deny_b(path: object, *args: object, **kwargs: object) -> object:
            if str(path).endswith("b.py"):
                raise PermissionError(path)
            return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr("builtins.open", deny_b)
        result = scan_path(root, config())
        assert error_codes(result) == ["read-failed"]
        assert result.files_scanned == 1
        assert len(result.findings) == 1

    def test_a_file_that_vanishes_mid_scan_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "b.py").write_text("x = 1\n", encoding="utf-8")

        real_open = open

        def vanish_on_b(path: object, *args: object, **kwargs: object) -> object:
            if str(path).endswith("b.py"):
                raise FileNotFoundError(path)
            return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr("builtins.open", vanish_on_b)
        assert "vanished" in error_codes(scan_path(root, config()))

    def test_an_oversized_single_file_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "big.py"
        target.write_text("x = 1\n" * 200, encoding="utf-8")
        result = scan_path(target, config(scan=ScanConfig(max_file_size=50)))
        assert error_codes(result) == ["too-large"]
        assert result.files_scanned == 0


class TestBinaryAndEncoding:
    def test_a_binary_file_is_skipped(self, tmp_path: Path) -> None:
        target = tmp_path / "image.bin"
        target.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(32)) + b"\x00\x00")
        result = scan_path(target, config())
        assert error_codes(result) == ["binary"]
        assert result.files_scanned == 0

    def test_an_undecodable_file_is_reported_as_such(self, tmp_path: Path) -> None:
        """Distinct from binary, because the remedy is different.

        A latin-1 log is a text file with the wrong encoding; telling the user
        "binary" would send them to look for a corrupt image.
        """

        target = tmp_path / "old.log"
        target.write_bytes("café naïve".encode("latin-1"))
        assert error_codes(scan_path(target, config())) == ["invalid-encoding"]

    def test_utf8_text_is_scanned(self, tmp_path: Path) -> None:
        target = tmp_path / "i18n.py"
        target.write_text(
            f'# 日本語 ключ 🔐\nK = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8"
        )
        result = scan_path(target, config())
        assert len(result.findings) == 1

    def test_a_byte_order_mark_does_not_shift_columns(self, tmp_path: Path) -> None:
        """A BOM is not content, so it must not offset every column by one.

        ``utf-8-sig`` strips it. Without that, a file's reported columns would
        differ from the same file opened in an editor, and every position in
        every report for BOM'd files would be off by one.
        """

        body = f'K = "{SYNTHETIC_API_KEY}"\n'
        with_bom = tmp_path / "bom.py"
        with_bom.write_bytes(b"\xef\xbb\xbf" + body.encode())
        without = tmp_path / "plain.py"
        without.write_text(body, encoding="utf-8")

        bom_result = scan_path(with_bom, config())
        plain_result = scan_path(without, config())

        assert len(bom_result.findings) == 1
        assert (
            bom_result.findings[0].location.column
            == plain_result.findings[0].location.column
        )
        assert bom_result.findings[0].location.column == 6

    def test_a_binary_file_in_a_directory_does_not_stop_the_scan(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "a.blob").write_bytes(b"\x00\x01\x02\x03" * 50)
        (tmp_path / "b.py").write_text(f'K = "{SYNTHETIC_API_KEY}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config())
        assert error_codes(result) == ["binary"]
        assert result.files_scanned == 1
        assert len(result.findings) == 1


class TestLongLines:
    def test_a_long_line_is_reported_as_a_partial_analysis(
        self, tmp_path: Path
    ) -> None:
        """No silent loss: a capped file says so."""

        target = tmp_path / "bundle.js"
        target.write_text("x" * 500 + "\n", encoding="utf-8")
        result = scan_path(target, config(max_line_length=100))
        assert error_codes(result) == ["line-too-long"]
        assert result.files_scanned == 1

    def test_pattern_rules_still_see_the_whole_file(self, tmp_path: Path) -> None:
        """Truncating for entropy must not truncate a private key block.

        A key body legitimately runs for thousands of characters, so the cap
        definitely fires here. If the cap applied *before* the pattern rules, the
        ``private-key-block`` finding would vanish and this file would report
        only "line too long" -- a certain finding turned into a missed one, which
        is the worst failure this tool can have.
        """

        from tests.vendor_fixtures import PRIVATE_KEY_BLOCK  # type: ignore

        target = tmp_path / "key.pem"
        target.write_text(PRIVATE_KEY_BLOCK, encoding="utf-8")

        capped = scan_path(target, config(max_line_length=64))
        uncapped = scan_path(target, config(max_line_length=DEFAULT_MAX_LINE_LENGTH))

        assert "line-too-long" in error_codes(capped)
        assert capped.findings == uncapped.findings
        assert {finding.rule_id for finding in capped.findings} == {"private-key-block"}

    def test_line_numbers_are_unaffected_by_the_cap(self, tmp_path: Path) -> None:
        """A secret after a long line must still report its true line."""

        target = tmp_path / "bundle.js"
        target.write_text(
            "x" * 500 + "\n" + "y" * 500 + "\n" + f'K = "{SYNTHETIC_API_KEY}"\n',
            encoding="utf-8",
        )
        result = scan_path(target, config(max_line_length=100))
        assert [finding.location.line for finding in result.findings] == [3]

    def test_a_short_file_is_not_capped(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        assert scan_path(target, config(max_line_length=100)).errors == ()

    def test_the_capped_line_count_is_reported(self, tmp_path: Path) -> None:
        """The count is of lines that actually exceeded, not of lines present.

        Three long lines among ten short ones means three, and reporting ten
        would overstate how much analysis was degraded.
        """

        target = tmp_path / "mixed.js"
        target.write_text(
            ("x" * 500 + "\n") * 3 + ("y" * 10 + "\n") * 7, encoding="utf-8"
        )
        result = scan_path(target, config(max_line_length=100))
        assert len(result.errors) == 1
        assert "3 line" in result.errors[0].reason

    def test_many_capped_lines_still_produce_one_error(self, tmp_path: Path) -> None:
        """One error per file, not per line: a bundle must not produce thousands."""

        target = tmp_path / "many.js"
        target.write_text(("x" * 500 + "\n") * 500, encoding="utf-8")
        result = scan_path(target, config(max_line_length=100))
        assert len(result.errors) == 1
        assert "500 line" in result.errors[0].reason

    def test_statistics_still_count_the_whole_file(self, tmp_path: Path) -> None:
        target = tmp_path / "bundle.js"
        target.write_text("x" * 500 + "\n", encoding="utf-8")
        result = scan_path(target, config(max_line_length=100))
        assert result.bytes_scanned == 501

    def test_a_capped_file_is_analysed_unfused(self, tmp_path: Path) -> None:
        """A capped file reports both detectors separately, and says why.

        Fusion compares character offsets between two detectors. Once a line has
        been truncated, the entropy copy and the pattern copy stop sharing
        coordinates -- every offset after the truncation is shifted by a
        different amount -- so there is no correct way to ask whether two spans
        describe one value.

        The chosen degradation is to fuse nothing and report the file as partly
        analysed. That costs a duplicate finding on a line the result already
        flags with ``line-too-long``. Fusing on offsets known to be wrong would
        cost worse: it could file a vendor rule's severity against a value
        nothing matched, which is a confident wrong answer rather than an extra
        honest one.
        """

        from tests.vendor_fixtures import AWS_SECRET_ACCESS_KEY  # type: ignore

        target = tmp_path / "bundle.js"
        target.write_text(
            "x" * 500 + "\n" + f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"\n',
            encoding="utf-8",
        )

        result = scan_path(target, config(max_line_length=100))

        assert error_codes(result) == ["line-too-long"]
        assert {finding.rule_id for finding in result.findings} == {
            "aws-secret-access-key",
            "high-entropy-string",
        }

    def test_raising_the_cap_restores_fusion(self, tmp_path: Path) -> None:
        """The same file, with the line under the limit, fuses as usual.

        Together with the test above this pins that the unfused path is caused by
        the cap and not by something about the file.
        """

        from tests.vendor_fixtures import AWS_SECRET_ACCESS_KEY  # type: ignore

        target = tmp_path / "config.env"
        target.write_text(
            f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"\n', encoding="utf-8"
        )

        result = scan_path(target, config(max_line_length=100))

        assert result.errors == ()
        assert [finding.rule_id for finding in result.findings] == [
            "aws-secret-access-key"
        ]
        assert result.findings[0].detector is DetectorKind.COMPOSITE

    def test_a_capped_file_still_loses_no_detection(self, tmp_path: Path) -> None:
        """Capping adds a finding; it must never remove one.

        The direction of the difference is the whole point. The capped scan
        reports *more* rule ids than the uncapped one, because it declines to
        fuse -- so ``uncapped <= capped`` on rule ids, always. A cap that made
        the result smaller would be a cap that lost detections.
        """

        from tests.vendor_fixtures import AWS_SECRET_ACCESS_KEY  # type: ignore

        target = tmp_path / "bundle.js"
        target.write_text(
            "x" * 500 + "\n" + f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"\n',
            encoding="utf-8",
        )

        capped = scan_path(target, config(max_line_length=100))
        uncapped = scan_path(target, config(max_line_length=DEFAULT_MAX_LINE_LENGTH))
        capped_rules = {finding.rule_id for finding in capped.findings}
        uncapped_rules = {finding.rule_id for finding in uncapped.findings}

        assert uncapped_rules <= capped_rules
        assert "aws-secret-access-key" in capped_rules
        assert capped_rules - uncapped_rules == {"high-entropy-string"}


# ---------------------------------------------------------------------------
# Statistics honesty
# ---------------------------------------------------------------------------


class TestStatistics:
    def test_skipped_files_contribute_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "image.png").write_bytes(b"\x89PNG" + bytes(64))

        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1
        assert result.bytes_scanned == 6

    def test_bytes_match_the_bytes_on_disk(self, tmp_path: Path) -> None:
        expected = 0
        for index in range(4):
            body = f"x = {index}\n"
            (tmp_path / f"f{index}.py").write_text(body, encoding="utf-8")
            expected += len(body.encode())

        result = scan_path(tmp_path, config())
        assert result.bytes_scanned == expected

    def test_a_failed_file_is_not_counted_as_scanned(self, tmp_path: Path) -> None:
        """Statistics must never claim work that did not happen."""

        target = tmp_path / "big.py"
        target.write_text("x = 1\n" * 200, encoding="utf-8")
        result = scan_path(target, config(scan=ScanConfig(max_file_size=50)))
        assert result.files_scanned == 0
        assert result.bytes_scanned == 0

    def test_an_empty_file_is_counted_as_scanned(self, tmp_path: Path) -> None:
        """Zero bytes read, but the file was still opened and searched."""

        target = tmp_path / "empty.py"
        target.write_bytes(b"")
        result = scan_path(target, config())
        assert result.files_scanned == 1
        assert result.bytes_scanned == 0

    def test_files_scanned_can_be_below_the_candidate_count(
        self, tmp_path: Path
    ) -> None:
        """A binary candidate was found but not analysed."""

        (tmp_path / "a.blob").write_bytes(b"\x00" * 100)
        (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")

        assert len(walk(tmp_path, config()).files) == 2
        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1


# ---------------------------------------------------------------------------
# Single-file scans run the full rule set
# ---------------------------------------------------------------------------


class TestSingleFileUsesEveryRule:
    def test_a_single_file_is_scanned_like_a_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The safety argument for running the full set on one file.

        :func:`scan_file` is entropy-only, because that is the Stage 1 API and
        changing it would change history. ``scan_path`` runs everything in both
        modes, because the alternative is that scanning one file reports *less*
        than scanning the directory holding that same file -- a trap with an
        entirely ordinary shape. This test fails loudly if that regresses.
        """

        from tests.vendor_fixtures import GITHUB_OAUTH_TOKEN  # type: ignore

        target = tmp_path / "config.py"
        target.write_text(f'TOKEN = "{GITHUB_OAUTH_TOKEN}"\n', encoding="utf-8")

        settings = config()
        as_file = scan_path(target, settings)
        in_directory = scan_path(target.parent, settings)

        assert len(as_file.findings) == len(in_directory.findings) >= 1
        assert as_file.findings[0].rule_id == in_directory.findings[0].rule_id

    def test_entropy_findings_appear_in_a_single_file_scan(
        self, tmp_path: Path
    ) -> None:
        """The Stage 1 rule still runs, so nothing was lost by adding rules."""

        from secret_shield.scanner import scan_file

        target = tmp_path / "blob.txt"
        body = 'value = "f8Kq2mZ9tR4vX7bN1cL6wY3hJ5pA0sD2fG4hJ6kL8"\n'
        target.write_text(body, encoding="utf-8")

        assert len(scan_file(target).findings) >= 1
        assert len(scan_path(target, config()).findings) >= 1

    def test_scan_file_is_unchanged_by_all_of_this(self, tmp_path: Path) -> None:
        """Stage 1's contract must survive Stage 3 untouched."""

        from tests.vendor_fixtures import GITHUB_OAUTH_TOKEN  # type: ignore

        from secret_shield.scanner import scan_file

        target = tmp_path / "config.py"
        target.write_text(f'TOKEN = "{GITHUB_OAUTH_TOKEN}"\n', encoding="utf-8")
        assert scan_file(target).findings == ()


# ---------------------------------------------------------------------------
# Errors never leak content
# ---------------------------------------------------------------------------


class TestErrorsCarryNoContent:
    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("plain.py", f'K = "{SYNTHETIC_API_KEY}"\n'),
            ("nul.bin", b"before\x00after"),
            ("bad.log", "café".encode("latin-1")),
            ("empty.txt", b""),
        ],
    )
    def test_an_error_message_contains_no_file_content(
        self, tmp_path: Path, name: str, body: bytes | str
    ) -> None:
        target = tmp_path / name
        if isinstance(body, bytes):
            target.write_bytes(body)
        else:
            target.write_text(body, encoding="utf-8")

        for error in scan_path(target, config()).errors:
            assert SYNTHETIC_API_KEY not in error.reason
            assert "caf" not in error.reason.lower() or "caf" not in body

    def test_error_codes_are_from_a_known_set(self, tmp_path: Path) -> None:
        """A typo in a code would be invisible to every consumer otherwise."""

        known = {
            "binary",
            "directory-unreadable",
            "invalid-encoding",
            "is-directory",
            "line-too-long",
            "not-a-regular-file",
            "not-found",
            "read-failed",
            "root-not-a-directory",
            "root-not-found",
            "stat-failed",
            "too-large",
            "too-many-files",
            "vanished",
        }
        (tmp_path / "a.blob").write_bytes(b"\x00" * 40)
        (tmp_path / "b.js").write_text("x" * 900 + "\n", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()

        result = scan_path(tmp_path, config(max_line_length=100))
        for code in error_codes(result):
            assert code in known, code

    def test_a_skip_reason_description_holds_no_path(self, tmp_path: Path) -> None:
        """A hostile filename must not be able to inject into a log line."""

        hostile = "evil\n\x1b[31mFAKE LOG LINE\x1b[0m.py"
        (tmp_path / hostile).write_bytes(b"\x89PNG" + bytes(8))

        result = walk(
            tmp_path, config(filters=PathFilterConfig(ignored_extensions=(".py",)))
        )
        for entry in result.skipped:
            assert "\x1b" not in entry.reason.description
            assert "\n" not in entry.reason.description
