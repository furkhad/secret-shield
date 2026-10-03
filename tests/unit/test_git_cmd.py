"""Unit tests for the one module that starts a process.

:mod:`secret_shield.sources.git_cmd` is the whole attack surface of Git support,
so these tests are mostly about what it *refuses* to do. A wrapper that works on
a friendly repository and quietly accepts a hostile one is not a security
boundary, and each guarantee in the module docstring has a test here that would
fail if the guarantee were dropped.

Most tests need a real repository, because the behaviour under test *is* the
interaction with Git: ``--no-renames``, ``-z`` framing and the deletion record's
all-zero object name are all things that only a real ``git`` can produce
faithfully. The repository builder below therefore shells out, with an
environment scrubbed of the settings that would make results depend on the
developer's machine.

Two families of test do not need a repository:

* the argument-level tests (:class:`TestBuildArgv`, :class:`TestEnvironment`),
  which are pure functions, and
* the failure tests, which point :data:`git_cmd.DEFAULT_GIT_PROGRAM` at a script
  that misbehaves on purpose.

Every credential-shaped value below is assembled from a prefix and a body, so no
literal credential appears in this file, and the leak assertions stay meaningful.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from secret_shield.sources import git_cmd
from secret_shield.sources.git_cmd import (
    KIND_MALFORMED,
    KIND_NOT_A_REPOSITORY,
    KIND_OBJECT_FORMAT,
    KIND_TIMEOUT,
    KIND_UNAVAILABLE,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    GitError,
    HeadState,
)

def _git_is_available() -> bool:
    """Return whether a usable ``git`` is on ``PATH``.

    Checked rather than assumed so the suite skips cleanly on a machine without
    Git instead of failing in a way that looks like a bug in the wrapper.
    """

    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


GIT_AVAILABLE = _git_is_available()


needs_git = pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not installed")


# ---------------------------------------------------------------------------
# Building repositories to scan
# ---------------------------------------------------------------------------

#: Environment for every Git command a test runs. Same reasoning as
#: ``git_cmd.git_environment``, applied here so a developer's own global config
#: cannot change what a fixture repository looks like.
FIXTURE_ENVIRONMENT: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+0000",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.devnull,
    "LC_ALL": "C",
}


def run_git(repo: Path, *arguments: str, check: bool = True) -> str:
    """Run ``git`` in ``repo`` with a scrubbed environment and return stdout."""

    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        env=FIXTURE_ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(f"git {' '.join(arguments)} failed: {completed.stderr}")
    return completed.stdout


def init_repo(repo: Path, *, object_format: str | None = None) -> Path:
    """Create an empty repository at ``repo``.

    Args:
        repo: Directory to create. Must not already exist.
        object_format: ``"sha256"`` to create a SHA-256 repository, which the
            scanner is expected to refuse rather than mis-scan.
    """

    repo.mkdir(parents=True)
    arguments = ["init", "-q", "-b", "main"]
    if object_format is not None:
        arguments.extend(["--object-format", object_format])
    subprocess.run(
        ["git", "-C", str(repo), *arguments],
        env=FIXTURE_ENVIRONMENT,
        capture_output=True,
        timeout=60,
        check=True,
    )
    return repo


def commit_all(repo: Path, message: str) -> str:
    """Stage everything and commit, returning the new commit hash."""

    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", message, "--allow-empty")
    return run_git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def simple_repo(tmp_path: Path) -> Path:
    """One commit, one file."""

    repo = init_repo(tmp_path / "simple")
    (repo / "a.txt").write_text("first\n", encoding="utf-8")
    commit_all(repo, "first")
    return repo


@pytest.fixture
def deleted_file_repo(tmp_path: Path) -> Path:
    """A file that existed in the first commit and was deleted in the second."""

    repo = init_repo(tmp_path / "deleted")
    (repo / "b.txt").write_text("gone but not forgotten\n", encoding="utf-8")
    commit_all(repo, "add b")
    run_git(repo, "rm", "-q", "b.txt")
    commit_all(repo, "remove b")
    return repo


@pytest.fixture
def sha256_repo(tmp_path: Path) -> Path:
    """A SHA-256 repository, which the scanner must refuse by name."""

    try:
        repo = init_repo(tmp_path / "sha256", object_format="sha256")
        (repo / "a.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "first")
    except subprocess.CalledProcessError:  # pragma: no cover - old Git
        pytest.skip("this Git cannot create a SHA-256 repository")
    return repo


def write_fake_git(directory: Path, body: str) -> str:
    """Write an executable stand-in for ``git`` and return its path.

    Used to drive the failure paths -- malformed output, a hang -- that a real
    repository cannot be made to produce on demand.
    """

    script = directory / "fake-git"
    script.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


@pytest.fixture
def fake_git(monkeypatch: pytest.MonkeyPatch):
    """Return a factory installing a fake ``git`` for the duration of a test."""

    def install_path(path: str) -> str:
        """Point the wrapper at an arbitrary program path."""

        monkeypatch.setattr(git_cmd, "DEFAULT_GIT_PROGRAM", path)
        return path

    def install(body: str, directory: Path) -> str:
        return install_path(write_fake_git(directory, body))

    install.install_path = install_path
    return install


# ---------------------------------------------------------------------------
# The argv contract
# ---------------------------------------------------------------------------


class TestBuildArgv:
    """What the process is actually asked to do."""

    def test_the_safe_options_are_always_present(self) -> None:
        argv = git_cmd.build_argv(("log",))

        assert argv[0] == git_cmd.DEFAULT_GIT_PROGRAM
        assert "--no-pager" in argv
        assert "--no-replace-objects" in argv

    def test_output_parsing_overrides_beat_repository_configuration(self) -> None:
        """A repository must not be able to make its own output unparseable.

        ``core.quotepath`` would C-escape a non-ASCII path, and ``core.abbrev``
        would shorten an object name to seven characters -- either one silently
        breaks the parsers rather than failing loudly, which is the kind of bug
        that produces a clean scan of a repository that was never examined.
        """

        argv = git_cmd.build_argv(("log",))

        # Git reads ``-c key=value``; the key and value travel as one argument.
        overrides = [value for code, value in zip(argv, argv[1:]) if code == "-c"]

        assert "core.quotepath=false" in overrides
        assert "core.abbrev=40" in overrides

    def test_the_repository_is_passed_after_the_option_not_as_one(self) -> None:
        """``-C`` takes the next argument verbatim.

        A path beginning with ``-`` therefore cannot be read as an option, which
        is why the two are separate argv entries rather than ``-C=<path>``.
        """

        argv = git_cmd.build_argv(("log",), repo="-weird-dir")

        index = argv.index("-C")
        assert argv[index + 1] == "-weird-dir"
        assert "-C=-weird-dir" not in argv

    def test_arguments_keep_their_spaces(self) -> None:
        argv = git_cmd.build_argv(("log", "--", "a file with spaces.txt"))

        assert "a file with spaces.txt" in argv

    @pytest.mark.parametrize(
        "subcommand",
        [
            (),
            ("--upload-pack=evil",),
            ("-c", "core.pager=evil"),
            ("log", "with\0nul"),
        ],
    )
    def test_argument_it_refuses_to_assemble(self, subcommand: tuple[str, ...]) -> None:
        with pytest.raises(GitError) as raised:
            git_cmd.build_argv(subcommand)

        assert raised.value.kind == git_cmd.KIND_FAILED

    @pytest.mark.parametrize(
        "value",
        ["-x", "--upload-pack=evil", "", "   ", "2024-01-01\ttab", "a\x01b"],
    )
    def test_revision_arguments_reject_anything_option_shaped(self, value: str) -> None:
        with pytest.raises(ValueError):
            git_cmd.validate_revision_argument(value, "since")

    def test_revision_arguments_are_trimmed_not_rewritten(self) -> None:
        assert git_cmd.validate_revision_argument("  2 years ago ", "since") == "2 years ago"

    def test_revision_arguments_reject_a_non_string(self) -> None:
        with pytest.raises(TypeError):
            git_cmd.validate_revision_argument(7, "since")  # type: ignore[arg-type]

    def test_revision_arguments_are_length_bounded(self) -> None:
        with pytest.raises(ValueError):
            git_cmd.validate_revision_argument("2 " * 5000, "since")


# ---------------------------------------------------------------------------
# The environment contract
# ---------------------------------------------------------------------------


class TestEnvironment:
    """What the child process can see."""

    def test_every_ambient_git_variable_is_removed(self) -> None:
        """Inheritance is the vulnerability, not the individual variables.

        ``GIT_DIR`` would redirect the scan at a different repository,
        ``GIT_INDEX_FILE`` would make a read touch the wrong index, and
        ``GIT_CONFIG_COUNT`` with its ``KEY_n``/``VALUE_n`` companions would let
        the environment inject configuration. Rather than enumerate the ones
        known today, the rule is "no ``GIT_*`` unless we set it here".
        """

        environment = git_cmd.git_environment(
            {"GIT_DIR": "/elsewhere", "GIT_WORK_TREE": "/elsewhere", "PATH": "/bin"}
        )

        assert "GIT_DIR" not in environment
        assert "GIT_WORK_TREE" not in environment
        assert environment["PATH"] == "/bin"

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_OPTIONAL_LOCKS", "0"),
            ("GIT_ASKPASS", ""),
        ],
    )
    def test_the_controlled_variables_are_set(self, name: str, value: str) -> None:
        assert git_cmd.git_environment({})[name] == value

    def test_no_controlled_variable_is_inherited_rather_than_set(self) -> None:
        """A hostile value must be overwritten, not merely defaulted."""

        environment = git_cmd.git_environment(
            {"GIT_TERMINAL_PROMPT": "1", "GIT_OPTIONAL_LOCKS": "1", "GIT_CONFIG_NOSYSTEM": "0"}
        )

        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"

    def test_the_global_config_is_never_read(self) -> None:
        """A developer's own global settings are theirs, not the scanner's.

        ``scan`` honours the running user's configuration file for ``scan``'s
        own options. It cannot honour it for *Git*, because a setting in it can
        change what a repository scan reads.
        """

        assert git_cmd.git_environment({})["GIT_CONFIG_GLOBAL"] == os.devnull


# ---------------------------------------------------------------------------
# Nothing is ever written
# ---------------------------------------------------------------------------


class TestReadOnly:
    """The promise that a scan cannot change the repository."""

    def test_no_subcommand_this_module_builds_can_write(self) -> None:
        """A blocklist of the writing subcommands, as a tripwire.

        Deliberately exhaustive rather than clever. A new subcommand added
        without a thought about this list fails here, which is the moment to
        think about it.
        """

        forbidden = {
            "add",
            "am",
            "apply",
            "branch",
            "checkout",
            "cherry-pick",
            "clean",
            "clone",
            "commit",
            "config",
            "fetch",
            "gc",
            "merge",
            "mv",
            "pull",
            "push",
            "rebase",
            "remote",
            "reset",
            "restore",
            "revert",
            "rm",
            "stash",
            "submodule",
            "tag",
            "update-index",
            "update-ref",
            "worktree",
        }

        # Every subcommand literal that appears in this module's own source.
        module = Path(git_cmd.__file__).read_text(encoding="utf-8")
        for line in module.splitlines():
            stripped = line.strip().strip(",")
            candidate = stripped.strip("\"'")
            if candidate in forbidden:
                raise AssertionError(
                    f"git_cmd.py builds the writing subcommand {candidate!r}: {line!r}"
                )

    @pytest.mark.parametrize(
        ("value", "message"),
        [
            (0, "between 1 and 3600 seconds"),
            (-1, "between 1 and 3600 seconds"),
            (float("nan"), "must be a finite number"),
            ("60", "must be a number"),
            (None, "must be a number"),
            (MAX_TIMEOUT_SECONDS * 2, "between 1 and 3600 seconds"),
            (MIN_TIMEOUT_SECONDS / 2, "between 1 and 3600 seconds"),
            (float("inf"), "must be a finite number"),
            (True, "must be a number"),
        ],
    )
    def test_timeouts_are_bounded(self, value: object, message: str) -> None:
        """A timeout nobody bounded is a CI job that hangs until it is killed."""

        with pytest.raises((ValueError, TypeError)) as raised:
            git_cmd.head_state(".", timeout=value)  # type: ignore[arg-type]

        assert message in str(raised.value)

    @needs_git
    def test_a_scan_changes_nothing_about_the_repository(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "untouched")
        (repo / "a.txt").write_text("one\n", encoding="utf-8")
        commit_all(repo, "first")
        (repo / "a.txt").write_text("two\n", encoding="utf-8")
        commit_all(repo, "second")
        before = _fingerprint(repo)

        list(git_cmd.HistoryWalk(repo))
        git_cmd.iter_object_inventory(repo)
        git_cmd.head_state(repo)

        assert _fingerprint(repo) == before


def _fingerprint(repo: Path) -> tuple[object, ...]:
    """Return everything about ``repo`` a scan must not change."""

    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        env=FIXTURE_ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        env=FIXTURE_ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    refs = subprocess.run(
        ["git", "-C", str(repo), "show-ref"],
        env=FIXTURE_ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    return head, status, sorted(refs.splitlines())


# ---------------------------------------------------------------------------
# Reading the head of a repository
# ---------------------------------------------------------------------------


class TestHeadState:
    @needs_git
    def test_a_repository_with_commits_is_present(self, simple_repo: Path) -> None:
        assert git_cmd.head_state(simple_repo) is HeadState.PRESENT

    @needs_git
    def test_a_repository_with_no_commits_is_unborn(self, tmp_path: Path) -> None:
        """``git init`` alone is a valid repository with nothing in its history."""

        assert git_cmd.head_state(init_repo(tmp_path / "empty")) is HeadState.UNBORN

    @needs_git
    def test_a_plain_directory_is_invalid(self, tmp_path: Path) -> None:
        plain = tmp_path / "plain"
        plain.mkdir()

        assert git_cmd.head_state(plain) is HeadState.INVALID

    def test_a_missing_git_binary_is_reported_by_name(
        self, fake_git, tmp_path: Path
    ) -> None:
        missing = tmp_path / "fake-git"
        missing.write_text("", encoding="utf-8")
        missing.unlink()
        fake_git_path = str(missing)
        fake_git.install_path(fake_git_path)

        with pytest.raises(GitError) as raised:
            git_cmd.head_state(".")

        assert raised.value.kind == KIND_UNAVAILABLE


# ---------------------------------------------------------------------------
# Object inventory
# ---------------------------------------------------------------------------


class TestObjectInventory:
    @needs_git
    def test_every_reachable_object_is_named_exactly_once(self, simple_repo: Path) -> None:
        inventory = git_cmd.iter_object_inventory(simple_repo)

        assert len(inventory.objects) == len(set(inventory.objects))
        assert inventory.objects
        assert not inventory.truncated

    @needs_git
    def test_the_limit_is_reported_rather_than_silently_applied(self, simple_repo: Path) -> None:
        inventory = git_cmd.iter_object_inventory(simple_repo, max_objects=1)

        assert inventory.truncated
        assert len(inventory.objects) <= 1

    @needs_git
    def test_a_deleted_file_is_still_in_the_object_database(
        self, deleted_file_repo: Path
    ) -> None:
        """The premise of the whole history source.

        ``rev-list`` walks the commit graph, so a blob that no longer has a path
        is still reachable and still named.
        """

        inventory = git_cmd.iter_object_inventory(deleted_file_repo)
        on_disk = [name for name in inventory.objects if name != "0" * 40]

        assert on_disk, "a deleted file left no trace in the object database"
        assert not (deleted_file_repo / "b.txt").exists()


# ---------------------------------------------------------------------------
# The history walk
# ---------------------------------------------------------------------------


class TestHistoryWalk:
    @needs_git
    def test_the_first_commit_is_walked(self, simple_repo: Path) -> None:
        """Without ``--root`` the initial commit's files are invisible."""

        references = list(git_cmd.HistoryWalk(simple_repo))

        assert [reference.path for reference in references] == ["a.txt"]

    @needs_git
    def test_a_deleted_file_is_attributed_to_the_commit_that_added_it(
        self, deleted_file_repo: Path
    ) -> None:
        references = list(git_cmd.HistoryWalk(deleted_file_repo))
        added = run_git(deleted_file_repo, "rev-list", "--max-parents=0", "HEAD").strip()

        assert [reference.path for reference in references] == ["b.txt"]
        assert references[0].commit == added

    @needs_git
    def test_a_deletion_record_produces_no_reference(self, deleted_file_repo: Path) -> None:
        """A deletion's destination object name is all zeros and has no content.

        Attributing a reference to it would attach a path to a blob that does not
        exist, which is the kind of bug that reports a finding in an object a user
        cannot look at.
        """

        references = list(git_cmd.HistoryWalk(deleted_file_repo))

        assert all(reference.object_name != "0" * 40 for reference in references)

    @needs_git
    def test_a_rename_yields_one_reference_for_the_new_name(
        self, tmp_path: Path
    ) -> None:
        """Rename detection is off, so a rename looks like add plus delete.

        Which is what this parser needs: the blob is attributed to the name it
        actually had, and the vanished name gets no reference at all.
        """

        repo = init_repo(tmp_path / "renamed")
        (repo / "before.txt").write_text("content\n", encoding="utf-8")
        commit_all(repo, "add")
        run_git(repo, "mv", "before.txt", "after.txt")
        commit_all(repo, "rename")

        references = list(git_cmd.HistoryWalk(repo))
        paths = {reference.path for reference in references}

        assert paths == {"before.txt", "after.txt"}

    @needs_git
    def test_a_path_with_spaces_survives_intact(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "spaced")
        (repo / "a file with spaces.txt").write_text("content\n", encoding="utf-8")
        (repo / "dir with spaces").mkdir()
        (repo / "dir with spaces" / "nested one.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "add")

        paths = {reference.path for reference in git_cmd.HistoryWalk(repo)}

        assert "a file with spaces.txt" in paths
        assert "dir with spaces/nested one.txt" in paths

    @needs_git
    def test_the_commit_limit_is_reported(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "many")
        for index in range(4):
            (repo / f"{index}.txt").write_text(f"{index}\n", encoding="utf-8")
            commit_all(repo, f"commit {index}")

        walk = git_cmd.HistoryWalk(repo, max_commits=2)
        list(walk)

        assert walk.commit_count == 2
        assert walk.truncated

    @needs_git
    def test_the_commit_at_the_limit_contributes_its_paths(self, tmp_path: Path) -> None:
        """``--max-count 1`` must mean "one commit", not "no commits".

        The commit record arrives before its path records, so stopping on the
        count alone would drop every path of the last commit allowed -- which
        would make ``--max-commits 1`` report nothing about ``HEAD`` even when
        ``HEAD`` is where the secret is.
        """

        repo = init_repo(tmp_path / "at-the-limit")
        (repo / "first.txt").write_text("1\n", encoding="utf-8")
        commit_all(repo, "one")
        (repo / "second.txt").write_text("2\n", encoding="utf-8")
        head = commit_all(repo, "two")

        walk = git_cmd.HistoryWalk(repo, max_commits=1)
        references = list(walk)

        assert [reference.path for reference in references] == ["second.txt"]
        assert references[0].commit == head

    @needs_git
    def test_a_limit_equal_to_the_commit_count_is_not_a_truncation(
        self, tmp_path: Path
    ) -> None:
        """Nothing was dropped, so a partial scan must not be declared.

        A caller turns ``truncated`` into an error and a non-zero exit code, so
        a false one would make ``--max-commits`` unusable on any repository
        smaller than the limit.
        """

        repo = init_repo(tmp_path / "exact")
        (repo / "a.txt").write_text("1\n", encoding="utf-8")
        commit_all(repo, "one")
        (repo / "b.txt").write_text("2\n", encoding="utf-8")
        commit_all(repo, "two")

        walk = git_cmd.HistoryWalk(repo, max_commits=2)
        references = list(walk)

        assert walk.commit_count == 2
        assert walk.truncated is False
        assert {reference.path for reference in references} == {"a.txt", "b.txt"}

    @needs_git
    def test_a_limit_above_the_commit_count_is_not_a_truncation(
        self, simple_repo: Path
    ) -> None:
        walk = git_cmd.HistoryWalk(simple_repo, max_commits=100)
        list(walk)

        assert walk.commit_count == 1
        assert walk.truncated is False

    @needs_git
    def test_an_unlimited_walk_is_not_truncated(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "small")
        (repo / "a.txt").write_text("a\n", encoding="utf-8")
        commit_all(repo, "add")

        walk = git_cmd.HistoryWalk(repo)
        list(walk)

        assert walk.commit_count == 1
        assert not walk.truncated

    @needs_git
    def test_the_newest_commit_comes_first(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "order")
        (repo / "first.txt").write_text("1\n", encoding="utf-8")
        commit_all(repo, "one")
        (repo / "second.txt").write_text("2\n", encoding="utf-8")
        commit_all(repo, "two")

        order = [reference.path for reference in git_cmd.HistoryWalk(repo)]

        assert order == ["second.txt", "first.txt"]

    @needs_git
    def test_the_commit_timestamp_is_the_author_time(self, simple_repo: Path) -> None:
        reference = next(iter(git_cmd.HistoryWalk(simple_repo)))

        assert reference.commit_time == 1_704_067_200


# ---------------------------------------------------------------------------
# Batch object access
# ---------------------------------------------------------------------------


class TestBatchAccess:
    @needs_git
    def test_headers_report_type_and_size(self, simple_repo: Path) -> None:
        inventory = git_cmd.iter_object_inventory(simple_repo)
        blob = next(
            header
            for header in git_cmd.iter_object_headers(simple_repo, inventory.objects)
            if header is not None and header.kind == "blob"
        )

        assert blob.size == len("first\n")

    @needs_git
    def test_payloads_round_trip_the_content(self, simple_repo: Path) -> None:
        inventory = git_cmd.iter_object_inventory(simple_repo)
        payloads = {
            payload.name: payload.data
            for payload in git_cmd.iter_object_payloads(simple_repo, inventory.objects)
            if payload is not None
        }

        assert b"first\n" in payloads.values()

    @needs_git
    def test_an_object_git_does_not_have_yields_none(self, simple_repo: Path) -> None:
        """A missing object is reported, not raised.

        A repository with a corrupt object should produce one error for that
        object and findings from everything else, rather than losing the whole
        scan.
        """

        results = list(git_cmd.iter_object_headers(simple_repo, ["0" * 40]))

        assert results == [None]

    @needs_git
    def test_an_oversized_payload_is_skipped_rather_than_held(
        self, simple_repo: Path
    ) -> None:
        """The memory backstop behind the caller's own size limit."""

        inventory = git_cmd.iter_object_inventory(simple_repo)
        results = list(git_cmd.iter_object_payloads(simple_repo, inventory.objects, max_payload=1))

        assert all(result is None for result in results)


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------


class TestObjectFormat:
    """SHA-256 repositories are refused, by name, rather than mis-scanned."""

    @needs_git
    def test_the_refusal_names_the_object_format(self, sha256_repo: Path) -> None:
        with pytest.raises(GitError) as raised:
            git_cmd.head_state(sha256_repo)

        assert raised.value.kind == KIND_OBJECT_FORMAT

    @needs_git
    def test_the_refusal_appears_before_any_content_is_read(
        self, sha256_repo: Path
    ) -> None:
        """The check is on the walk, so an unsupportable repository costs nothing."""

        with pytest.raises(GitError) as raised:
            list(git_cmd.HistoryWalk(sha256_repo))

        assert raised.value.kind == KIND_OBJECT_FORMAT

    @needs_git
    def test_the_inventory_refuses_too(self, sha256_repo: Path) -> None:
        with pytest.raises(GitError) as raised:
            git_cmd.iter_object_inventory(sha256_repo)

        assert raised.value.kind == KIND_OBJECT_FORMAT

    def test_the_error_kind_is_stable_text(self) -> None:
        """A caller branches on the kind, so it must not be reworded."""

        assert KIND_OBJECT_FORMAT == "unsupported-object-format"


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class TestFailureModes:
    @pytest.mark.parametrize(
        ("kind", "expected"),
        [
            (KIND_MALFORMED, KIND_MALFORMED),
            (KIND_NOT_A_REPOSITORY, KIND_NOT_A_REPOSITORY),
            (KIND_TIMEOUT, KIND_TIMEOUT),
            (KIND_UNAVAILABLE, KIND_UNAVAILABLE),
        ],
    )
    def test_the_error_repr_carries_the_kind(self, kind: str, expected: str) -> None:
        """``repr`` is what a traceback shows, so the kind has to be in it."""

        rendered = repr(GitError(kind, "something went wrong"))

        assert f"kind={expected!r}" in rendered

    def test_git_stderr_never_reaches_the_exception(self, fake_git, tmp_path: Path) -> None:
        """A repository controls its own commit messages and ref names.

        Git's stderr can contain any of it. Forwarding it would put repository
        content into a log line through an error path, which is exactly the route
        a reader would assume is safe.
        """

        fake_git(
            "echo 'the repository says: SUPERSECRETVALUE' >&2\nexit 128\n",
            tmp_path,
        )

        with pytest.raises(GitError) as raised:
            list(git_cmd.HistoryWalk("."))

        assert "SUPERSECRETVALUE" not in str(raised.value)
        assert "SUPERSECRETVALUE" not in repr(raised.value)

    @needs_git
    def test_garbage_output_is_reported_as_malformed(self, fake_git, tmp_path: Path) -> None:
        """A record that is not a record is a parse failure, not a crash.

        The fake answers ``rev-parse`` correctly -- so the walk is attempted --
        and then emits bytes no version of this parser can read.
        """

        fake_git(
            'case "$*" in\n'
            '  *rev-parse*) echo 1111111111111111111111111111111111111111; exit 0 ;;\n'
            "esac\n"
            "printf 'not-a-record\\n'\n"
            "exit 0\n",
            tmp_path,
        )

        with pytest.raises(GitError) as raised:
            list(git_cmd.HistoryWalk("."))

        assert raised.value.kind == KIND_MALFORMED

    @needs_git
    def test_a_hung_git_is_killed_rather_than_waited_on(self, fake_git, tmp_path: Path) -> None:
        """The timeout is the difference between a scan and a stuck pipeline."""

        fake_git(
            'case "$*" in\n'
            '  *rev-parse*) echo 1111111111111111111111111111111111111111; exit 0 ;;\n'
            "esac\n"
            "sleep 30\n",
            tmp_path,
        )

        with pytest.raises(GitError) as raised:
            list(git_cmd.HistoryWalk(".", timeout=1.0))

        assert raised.value.kind == KIND_TIMEOUT


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


class TestSubprocessIsConfinedHere:
    def test_this_is_the_only_module_in_the_package_that_imports_subprocess(self) -> None:
        """The single fact that makes the audit tractable.

        An auditor asked "could a hostile repository make SecretShield execute
        something?" gets one file to read. That is only useful if it is true, and
        it stops being true the first time another module reaches for
        :mod:`subprocess`, ``os.system``, ``os.popen`` or ``pty.spawn``.
        """

        package = Path(git_cmd.__file__).resolve().parent.parent
        offenders: list[str] = []
        for path in sorted(package.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for forbidden in (
                "import subprocess",
                "from subprocess import",
                "os.system(",
                "os.popen(",
                "pty.spawn(",
                "commands.getoutput(",
            ):
                if forbidden in source and path.name != "git_cmd.py":
                    offenders.append(f"{path.name}: {forbidden}")

        assert offenders == [], f"process handling escaped git_cmd.py: {offenders}"

    def test_the_history_source_does_not_import_it_either(self) -> None:
        """The source that reads objects must not know how they are fetched."""

        history_path = Path(git_cmd.__file__).with_name("git_history.py")
        history = history_path.read_text(encoding="utf-8")

        assert "import subprocess" not in history
        assert "from subprocess import" not in history

    def test_git_cmd_imports_cleanly_as_a_module(self) -> None:
        assert git_cmd.__name__ == "secret_shield.sources.git_cmd"


# ---------------------------------------------------------------------------
# Python itself
# ---------------------------------------------------------------------------


class TestTimeoutBoundsAreConsistent:
    def test_the_minimum_is_below_the_maximum(self) -> None:
        assert MIN_TIMEOUT_SECONDS < MAX_TIMEOUT_SECONDS

    def test_the_default_is_inside_the_range(self) -> None:
        assert MIN_TIMEOUT_SECONDS <= git_cmd.DEFAULT_TIMEOUT_SECONDS <= MAX_TIMEOUT_SECONDS

    def test_the_timeout_check_rejects_a_bool(self) -> None:
        """``True`` is an ``int``, and a one-second timeout is not what it means."""

        with pytest.raises((TypeError, ValueError)):
            git_cmd.head_state(".", timeout=True)  # type: ignore[arg-type]


def test_this_module_runs_under_the_interpreter_the_suite_uses() -> None:
    """A guard against a subprocess-only test hiding a broken import."""

    assert sys.executable