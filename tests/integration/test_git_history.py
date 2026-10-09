"""End-to-end tests for scanning a repository's history.

:mod:`secret_shield.sources.git_history` exists for one case, and this module is
mostly about that case: a credential was committed, the file was deleted, the
working tree is clean, and only the history still holds it. A working-tree scan
that reports nothing is *correct* about the working tree and useless about the
repository, and every assertion here is chosen to make that distinction visible.

The other half of the file is about what must *not* happen while looking for it:
the working tree is byte-identical afterwards, no ref moves, the content is read
once per blob however many commits and paths share it, oversized and binary blobs
are skipped and counted rather than read, and a SHA-256 repository is refused by
name instead of mis-parsed.

Repositories are built by shelling out to ``git`` with a scrubbed environment, so
a developer's own Git configuration cannot change what a fixture looks like.
Every credential-shaped value is imported from :mod:`tests.vendor_fixtures`,
where the literals are fabricated. None of it is a real credential.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
from pathlib import Path

import pytest

from secret_shield.filters.paths import PathFilterConfig
from secret_shield.models import ScanError, ScanResult, SourceKind
from secret_shield.sources import PathScanConfig, git_cmd, scan_path
from secret_shield.sources.git_history import GitScanConfig, HistoryScan, scan_history
from tests.vendor_fixtures import (  # type: ignore
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    GITHUB_OAUTH_TOKEN,
)

#: Every value a test asserts must never appear in output.
LEAKED_VALUES = (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_OAUTH_TOKEN)


def _git_is_available() -> bool:
    try:
        subprocess.run(
            ["git", "--version"], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


GIT_AVAILABLE = _git_is_available()
needs_git = pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not installed")


FIXTURE_ENVIRONMENT: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "History Test",
    "GIT_AUTHOR_EMAIL": "history@example.invalid",
    "GIT_COMMITTER_NAME": "History Test",
    "GIT_COMMITTER_EMAIL": "history@example.invalid",
    "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+0000",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.devnull,
    "LC_ALL": "C",
}


def run_git(repo: Path, *arguments: str, check: bool = True) -> str:
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
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", message, "--allow-empty")
    return run_git(repo, "rev-parse", "HEAD").strip()


def secret_file_text() -> str:
    """A committed file carrying one synthetic AWS key pair."""

    return (
        "# historical configuration, deleted long ago\n"
        f'AWS_ACCESS_KEY_ID = "{AWS_ACCESS_KEY_ID}"\n'
        f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET_ACCESS_KEY}"\n'
    )


def repository_state(repo: Path) -> tuple[object, ...]:
    """Everything about ``repo`` that a scan must leave exactly as it was."""

    tracked = sorted(
        (str(path.relative_to(repo)), path.read_bytes())
        for path in repo.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(repo).parts
    )
    return (
        run_git(repo, "rev-parse", "HEAD").strip(),
        run_git(repo, "symbolic-ref", "HEAD").strip(),
        run_git(repo, "status", "--porcelain"),
        run_git(repo, "rev-list", "--all", "--count").strip(),
        tuple(tracked),
    )


def codes(scan: HistoryScan) -> list[str]:
    return [error.code for error in scan.result.errors if error.code]


def rule_ids(scan: HistoryScan) -> list[str]:
    return [finding.rule_id for finding in scan.findings]


def assert_no_leaked_value(text: str) -> None:
    for value in LEAKED_VALUES:
        assert value not in text, f"a raw credential reached output: {value[:4]}..."


@dataclasses.dataclass(frozen=True)
class Repo:
    """A fixture repository plus the commit names its tests need.

    A ``Path`` cannot carry attributes -- ``__slots__`` -- so the commit a test
    needs to assert against is held here instead of stashed on the object.
    """

    path: Path
    leaky_commit: str = ""


def corrupt_loose_object(repo: Path, name: str) -> bool:
    """Write garbage over the loose object ``name``, returning whether it existed.

    Corruption by content rather than by deletion on purpose: deleting an object
    makes ``rev-list`` itself fail, so the walk never starts. Corrupting the
    bytes leaves every *name* resolvable and only the content unreadable, which
    is the case ``object-unreadable`` exists for.
    """

    path = repo / ".git" / "objects" / name[:2] / name[2:]
    if not path.is_file():
        return False
    path.chmod(0o644)
    path.write_bytes(b"secret-shield deliberately corrupted this object")
    return True


def loose_object_names(repo: Path) -> dict[str, str]:
    """Return ``object name -> type`` for every loose object in ``repo``."""

    found: dict[str, str] = {}
    objects = repo / ".git" / "objects"
    for directory in sorted(objects.iterdir()):
        if not directory.is_dir() or len(directory.name) != 2:
            continue
        for entry in sorted(directory.iterdir()):
            name = directory.name + entry.name
            kind = run_git(repo, "cat-file", "-t", name, check=False).strip()
            found[name] = kind
    return found


def commit_tree_with_path(repo: Path, path: str, content: str) -> None:
    """Commit ``content`` at exactly ``path``, however long or deep that is.

    A path longer than any filesystem accepts cannot be written with ``write``,
    so it goes in through the index instead. ``git mktree`` is no help: it
    refuses a name containing a slash.
    """

    staged = repo / "staged-content"
    staged.write_text(content, encoding="utf-8")
    blob = run_git(repo, "hash-object", "-w", str(staged)).strip()
    staged.unlink()
    completed = subprocess.run(
        ["git", "-C", str(repo), "update-index", "--add", "--index-info"],
        env=FIXTURE_ENVIRONMENT,
        input=f"100644 {blob}\t{path}\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git update-index failed: {completed.stderr}")
    tree = run_git(repo, "write-tree").strip()
    commit = run_git(
        repo, "commit-tree", tree, "-m", "a path no filesystem would accept"
    ).strip()
    run_git(repo, "update-ref", "refs/heads/main", commit)


# ---------------------------------------------------------------------------
# The case this source exists for
# ---------------------------------------------------------------------------


@pytest.fixture
def deleted_secret_repo(tmp_path: Path) -> Repo:
    """A credential committed, then the file deleted. The tree is clean."""

    repo = init_repo(tmp_path / "deleted-secret")
    (repo / "gone.py").write_text(secret_file_text(), encoding="utf-8")
    leaky_commit = commit_all(repo, "add configuration")
    run_git(repo, "rm", "-q", "gone.py")
    commit_all(repo, "remove the configuration file")
    (repo / "README.md").write_text("# a clean working tree\n", encoding="utf-8")
    commit_all(repo, "add a readme")
    return Repo(path=repo, leaky_commit=leaky_commit)


@needs_git
class TestTheDeletedSecret:
    def test_the_working_tree_is_clean(self, deleted_secret_repo: Repo) -> None:
        """The premise. Without it the rest of this class proves nothing."""

        repo = deleted_secret_repo.path

        assert run_git(repo, "status", "--porcelain") == ""
        assert not (repo / "gone.py").exists()

    def test_a_working_tree_scan_finds_nothing(self, deleted_secret_repo: Repo) -> None:
        """Correct about the working tree, useless about the repository."""

        result = scan_path(deleted_secret_repo.path, PathScanConfig())

        assert result.findings == ()
        assert result.files_scanned >= 1, "the scan did look at something"

    def test_the_history_scan_finds_the_secret(self, deleted_secret_repo: Repo) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert "aws-access-key-id" in rule_ids(scan)
        assert "aws-secret-access-key" in rule_ids(scan)

    def test_the_finding_names_the_deleted_path(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert {finding.location.path for finding in scan.findings} == {"gone.py"}

    def test_the_finding_names_the_commit_that_had_it(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert {finding.location.commit for finding in scan.findings} == {
            deleted_secret_repo.leaky_commit
        }

    def test_the_finding_carries_a_commit_time(self, deleted_secret_repo: Repo) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert all(
            finding.location.commit_time is not None for finding in scan.findings
        )
        # The fixture pins every commit to one timestamp.
        assert {finding.location.commit_time for finding in scan.findings} == {
            1_704_067_200
        }

    def test_the_source_kind_says_git(self, deleted_secret_repo: Repo) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert all(
            finding.location.source_kind is SourceKind.GIT for finding in scan.findings
        )

    def test_the_commit_is_a_full_object_name_not_an_abbreviation(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path)

        for finding in scan.findings:
            assert finding.location.commit is not None
            assert len(finding.location.commit) == 40

    def test_the_secret_itself_is_not_in_the_result(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert_no_leaked_value(repr(scan.result))
        for finding in scan.findings:
            assert_no_leaked_value(repr(finding))

    def test_the_working_tree_is_untouched(self, deleted_secret_repo: Repo) -> None:
        """The strong claim: read-only in the sense a CI job can verify."""

        repo = deleted_secret_repo.path
        before = repository_state(repo)

        scan_history(repo)

        assert repository_state(repo) == before

    def test_nothing_was_checked_out(self, deleted_secret_repo: Repo) -> None:
        repo = deleted_secret_repo.path

        scan_history(repo)

        assert not (repo / "gone.py").exists()

    def test_no_new_ref_appeared(self, deleted_secret_repo: Repo) -> None:
        repo = deleted_secret_repo.path
        before = run_git(repo, "for-each-ref").strip()

        scan_history(repo)

        assert run_git(repo, "for-each-ref").strip() == before

    def test_no_reflog_entry_was_written(self, deleted_secret_repo: Repo) -> None:
        """A HEAD reflog entry would be proof that something wrote to the repo."""

        repo = deleted_secret_repo.path
        before = sorted(path.name for path in (repo / ".git" / "logs").rglob("*"))

        scan_history(repo)

        after = sorted(path.name for path in (repo / ".git" / "logs").rglob("*"))
        assert after == before

    def test_it_is_repeatable(self, deleted_secret_repo: Repo) -> None:
        """Two scans of an unchanged repository must agree exactly."""

        repo = deleted_secret_repo.path
        first = scan_history(repo)
        second = scan_history(repo)

        assert first.findings == second.findings
        assert first.blobs_scanned == second.blobs_scanned
        assert first.commits == second.commits

    def test_a_subdirectory_of_a_repository_works(
        self, deleted_secret_repo: Repo
    ) -> None:
        """Git resolves a subdirectory, and so must this."""

        repo = deleted_secret_repo.path
        nested = repo / "docs"
        nested.mkdir()

        assert scan_history(nested).findings == scan_history(repo).findings


# ---------------------------------------------------------------------------
# Deduplication: one blob, many commits, many paths
# ---------------------------------------------------------------------------


@pytest.fixture
def reverted_repo(tmp_path: Path) -> Repo:
    """Two blobs, each reintroduced across four commits.

    A file whose bytes never change is not recorded by later commits at all, so
    the only way to put one blob in several commits is to change the file and
    then change it back. That is also the realistic shape of the problem: an
    incident is "fixed", reintroduced, fixed again.
    """

    repo = init_repo(tmp_path / "reverted")
    line = f'AWS_ACCESS_KEY_ID = "{AWS_ACCESS_KEY_ID}"\n'
    first_text = f"VALUE = 1\n{line}\nRESULT = VALUE\n"
    second_text = f"VALUE = 2\n{line}\nRESULT = VALUE + 1\n"

    (repo / "app.py").write_text(first_text, encoding="utf-8")
    _ = commit_all(repo, "first")
    (repo / "app.py").write_text(second_text, encoding="utf-8")
    _ = commit_all(repo, "edit")
    (repo / "app.py").write_text(first_text, encoding="utf-8")
    latest = commit_all(repo, "revert")
    (repo / "app.py").write_text(second_text, encoding="utf-8")
    commit_all(repo, "edit again")
    return Repo(path=repo, leaky_commit=latest)


@needs_git
class TestDeduplication:
    def test_one_blob_is_scanned_once_however_many_commits_share_it(
        self, reverted_repo: Repo
    ) -> None:
        """The cost argument, and the reason a big repository is affordable."""

        scan = scan_history(reverted_repo.path)

        # Four commits and eight (commit, path) records name only two blobs,
        # because the bytes repeated.
        assert scan.commits == 4
        assert scan.blobs_seen == 2
        assert scan.blobs_scanned == 2

    def test_a_blob_seen_in_two_commits_is_one_finding(
        self, reverted_repo: Repo
    ) -> None:
        scan = scan_history(reverted_repo.path)

        assert len(scan.findings) == 2, "one per distinct blob"
        assert {finding.location.path for finding in scan.findings} == {"app.py"}

    def test_the_finding_names_the_newest_commit_with_that_content(
        self, reverted_repo: Repo
    ) -> None:
        """The commit a user acts on is the one where the secret last stood."""

        scan = scan_history(reverted_repo.path)

        commits = {finding.location.commit for finding in scan.findings}
        assert reverted_repo.leaky_commit in commits

    def test_the_same_blob_at_many_paths_gives_one_finding_each(
        self, tmp_path: Path
    ) -> None:
        repo = init_repo(tmp_path / "many-paths")
        text = f'key = "{AWS_ACCESS_KEY_ID}"\n'
        for name in ("one.env", "two.env", "dir with space/three.env"):
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        commit_all(repo, "the same bytes in three places")

        scan = scan_history(repo)

        assert scan.blobs_seen == 1, "Git stored one blob for three identical files"
        assert {finding.location.path for finding in scan.findings} == {
            "one.env",
            "two.env",
            "dir with space/three.env",
        }

    def test_a_rename_is_reported_at_both_names(self, tmp_path: Path) -> None:
        """``--no-renames`` turns a rename into a delete plus an add.

        The new name appears where it was added and the old name where it was
        added; the deletion record carries no blob and is dropped. Both findings
        are true, and both point at a commit that really held the secret.
        """

        repo = init_repo(tmp_path / "renamed")
        (repo / "before.txt").write_text(
            f'key = "{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        original = commit_all(repo, "before")
        run_git(repo, "mv", "before.txt", "after.txt")
        renamed = commit_all(repo, "renamed")

        scan = scan_history(repo)

        assert scan.findings, "the rename did not hide the secret"
        assert {finding.location.path for finding in scan.findings} == {
            "before.txt",
            "after.txt",
        }
        assert {finding.location.commit for finding in scan.findings} == {
            original,
            renamed,
        }

    def test_a_rename_keeps_one_blob_and_one_analysis(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "renamed-once")
        (repo / "before.txt").write_text(
            f'key = "{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        commit_all(repo, "before")
        run_git(repo, "mv", "before.txt", "after.txt")
        commit_all(repo, "renamed")

        scan = scan_history(repo)

        assert scan.blobs_seen == 1
        assert scan.blobs_scanned == 1
        assert len(scan.findings) == 2

    def test_the_content_is_read_once_not_once_per_path(self, tmp_path: Path) -> None:
        """``blobs_scanned`` counts blobs; a per-path source would inflate it."""

        repo = init_repo(tmp_path / "counted")
        for name in ("a.env", "b.env", "c.env", "d.env"):
            (repo / name).write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "four copies")

        scan = scan_history(repo)

        assert scan.blobs_seen == 1
        assert scan.blobs_scanned == 1
        assert scan.result.files_scanned == 1
        assert len(scan.findings) == 4


# ---------------------------------------------------------------------------
# What gets skipped, and what that costs
# ---------------------------------------------------------------------------


@needs_git
class TestLimits:
    def test_a_commit_limit_stops_the_walk_and_says_so(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "many-commits")
        for index in range(5):
            (repo / f"file{index}.txt").write_text(
                f"content {index}\n", encoding="utf-8"
            )
            commit_all(repo, f"commit {index}")

        scan = scan_history(repo, GitScanConfig(max_commits=2))

        assert scan.truncated is True
        assert scan.commits == 2
        assert "history-truncated" in codes(scan)
        assert scan.truncated_because

    def test_a_commit_limit_that_is_not_reached_truncates_nothing(
        self, reverted_repo: Repo
    ) -> None:
        scan = scan_history(reverted_repo.path, GitScanConfig(max_commits=100))

        assert scan.truncated is False
        assert scan.truncated_because == ()
        assert scan.result.errors == ()

    def test_a_secret_older_than_the_limit_is_not_found(self, tmp_path: Path) -> None:
        """The gap must be a *declared* gap, not a silent miss."""

        repo = init_repo(tmp_path / "old-secret")
        (repo / "old.env").write_text(
            f'AWS_ACCESS_KEY_ID = "{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        leaky = commit_all(repo, "the leaky one")
        for index in range(3):
            (repo / f"new{index}.txt").write_text(
                f"nothing {index}\n", encoding="utf-8"
            )
            commit_all(repo, f"later {index}")

        scan = scan_history(repo, GitScanConfig(max_commits=1))

        assert scan.findings == ()
        assert "history-truncated" in codes(scan)
        assert leaky != run_git(repo, "rev-parse", "HEAD").strip()

    def test_a_blob_over_the_size_limit_is_counted_not_read(
        self, tmp_path: Path
    ) -> None:
        repo = init_repo(tmp_path / "huge")
        (repo / "huge.txt").write_text("x" * (512 * 1024), encoding="utf-8")
        (repo / "small.txt").write_text("fine\n", encoding="utf-8")
        commit_all(repo, "one huge file")

        scan = scan_history(repo, GitScanConfig(max_blob_size=1024))

        assert scan.blobs_too_large == 1
        assert scan.blobs_scanned == 1
        assert scan.result.bytes_scanned < 512 * 1024

    def test_a_secret_in_a_huge_blob_is_declared_not_reported(
        self, tmp_path: Path
    ) -> None:
        """The point of the bound: the caller must be able to tell."""

        repo = init_repo(tmp_path / "huge-secret")
        padding = "x" * (512 * 1024)
        (repo / "big.env").write_text(
            f'{padding}\nAWS_ACCESS_KEY_ID = "{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        commit_all(repo, "a big file with a secret")

        scan = scan_history(repo, GitScanConfig(max_blob_size=1024))

        assert scan.findings == ()
        assert scan.blobs_too_large == 1
        assert scan.blobs_scanned == 0

    def test_a_binary_blob_is_counted_not_scanned(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "binary")
        (repo / "logo.png").write_bytes(bytes(range(256)) * 40)
        (repo / "text.txt").write_text("clean\n", encoding="utf-8")
        commit_all(repo, "an image and a file")

        scan = scan_history(repo)

        assert scan.blobs_binary == 1
        assert scan.blobs_scanned == 1
        assert (
            scan.result.errors == ()
        ), "skipping a binary is a decision, not a failure"

    def test_a_secret_masquerading_as_binary_is_not_reported(
        self, tmp_path: Path
    ) -> None:
        """A NUL byte is enough. The boundary is binary, not plausible."""

        repo = init_repo(tmp_path / "fake-binary")
        (repo / "sneaky.bin").write_bytes(
            f'key="{AWS_ACCESS_KEY_ID}"\n'.encode("ascii") + b"\x00\x00\x00"
        )
        commit_all(repo, "a file with a NUL byte")

        scan = scan_history(repo)

        assert scan.findings == ()
        assert scan.blobs_binary == 1

    def test_an_unborn_repository_is_empty_not_an_error(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "unborn")

        scan = scan_history(repo)

        assert scan.findings == ()
        assert scan.result.errors == ()
        assert scan.commits == 0
        assert scan.blobs_scanned == 0

    def test_a_limit_on_distinct_blobs_stops_the_index(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "many-blobs")
        for index in range(6):
            (repo / f"f{index}.txt").write_text(f"unique {index}\n", encoding="utf-8")
        commit_all(repo, "six files")

        scan = scan_history(repo, GitScanConfig(max_blobs=2))

        assert scan.blobs_seen == 2
        assert scan.truncated is True
        assert "history-truncated" in codes(scan)

    def test_a_limit_on_path_references_stops_the_index(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "many-refs")
        for index in range(4):
            (repo / f"f{index}.txt").write_text("moved\n", encoding="utf-8")
            commit_all(repo, f"tweak {index}")

        scan = scan_history(repo, GitScanConfig(max_refs=1))

        assert scan.truncated is True
        assert "history-truncated" in codes(scan)

    def test_every_limit_is_named_in_the_error(self, tmp_path: Path) -> None:
        """A partial scan that says only "partial" leaves a reader guessing."""

        repo = init_repo(tmp_path / "named")
        (repo / "earlier.txt").write_text("before\n", encoding="utf-8")
        commit_all(repo, "one blob")
        for index in range(3):
            (repo / f"f{index}.txt").write_text(f"unique {index}\n", encoding="utf-8")
        commit_all(repo, "three more blobs")

        scan = scan_history(repo, GitScanConfig(max_commits=1, max_blobs=1))
        truncated = [e for e in scan.result.errors if e.code == "history-truncated"]

        assert len(truncated) == 1
        assert len(scan.truncated_because) == 2
        assert scan.truncated_because == tuple(sorted(scan.truncated_because))
        for reason in scan.truncated_because:
            assert reason in truncated[0].reason


# ---------------------------------------------------------------------------
# Paths a repository controls
# ---------------------------------------------------------------------------


@needs_git
class TestRepositoryControlledPaths:
    def test_a_path_with_spaces_and_quotes_is_reported_verbatim(
        self, tmp_path: Path
    ) -> None:
        repo = init_repo(tmp_path / "awkward")
        name = "dir with space/it's here.env"
        path = repo / name
        path.parent.mkdir(parents=True)
        path.write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "an awkward name")

        scan = scan_history(repo)

        assert [finding.location.path for finding in scan.findings] == [name]

    def test_a_non_ascii_path_is_reported_verbatim(self, tmp_path: Path) -> None:
        """``core.quotepath=false`` exists for exactly this; see ``git_cmd``."""

        repo = init_repo(tmp_path / "unicode")
        name = "café/中文.env"
        path = repo / name
        path.parent.mkdir(parents=True)
        path.write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "a unicode name")

        scan = scan_history(repo)

        assert [finding.location.path for finding in scan.findings] == [name]

    def test_a_rename_with_a_quote_and_a_space_round_trips(
        self, tmp_path: Path
    ) -> None:
        repo = init_repo(tmp_path / "rename-awkward")
        (repo / "a b.env").write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        first = commit_all(repo, "first")
        run_git(repo, "mv", "a b.env", "c 'd'.env")
        renamed = commit_all(repo, "renamed")

        scan = scan_history(repo)

        assert sorted(finding.location.path for finding in scan.findings) == [
            "a b.env",
            "c 'd'.env",
        ]
        assert {finding.location.commit for finding in scan.findings} == {
            first,
            renamed,
        }

    def test_a_path_with_a_control_character_is_stripped(self, tmp_path: Path) -> None:
        """A repository must not be able to repaint the CI log of a scanner."""

        repo = init_repo(tmp_path / "control")
        (repo / "evil\x1b[31mFAKE.env").write_text(
            f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        commit_all(repo, "a hostile filename")

        scan = scan_history(repo)

        assert scan.findings, "the file was still scanned"
        for finding in scan.findings:
            assert "\x1b" not in finding.location.path
            assert "FAKE" in finding.location.path
        assert_no_leaked_value(repr(scan.result))

    def test_path_filters_are_off_by_default(self, tmp_path: Path) -> None:
        """Today's ignore rules do not describe what was committed years ago."""

        repo = init_repo(tmp_path / "ignored")
        path = repo / "node_modules" / "pkg" / "index.env"
        path.parent.mkdir(parents=True)
        path.write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "a vendored file with a secret")

        scan = scan_history(repo)

        assert scan.paths_filtered == 0
        assert [finding.location.path for finding in scan.findings] == [
            "node_modules/pkg/index.env"
        ]

    def test_path_filters_can_be_opted_into(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "opted-in")
        path = repo / "node_modules" / "pkg" / "index.env"
        path.parent.mkdir(parents=True)
        path.write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        (repo / "src").mkdir()
        (repo / "src" / "app.env").write_text(
            f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        commit_all(repo, "two files")

        scan = scan_history(repo, GitScanConfig(path_filters=PathFilterConfig()))

        assert scan.paths_filtered == 1
        assert [finding.location.path for finding in scan.findings] == ["src/app.env"]

    def test_a_configured_path_prefix_filters_by_hand(self, tmp_path: Path) -> None:
        """A history index has no traversal order, so ancestors are applied
        manually; this is the case that only works if they are."""

        repo = init_repo(tmp_path / "prefix-filter")
        path = repo / "build" / "deep" / "x.env"
        path.parent.mkdir(parents=True)
        path.write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "built")

        scan = scan_history(
            repo, GitScanConfig(path_filters=PathFilterConfig(ignored_paths=("build",)))
        )

        assert scan.findings == ()
        assert scan.paths_filtered == 1

    def test_a_path_too_long_to_report_is_declared(self, tmp_path: Path) -> None:
        """Longer than any filesystem accepts, so it can only be a tree entry."""

        repo = init_repo(tmp_path / "long-path")
        run_git(repo, "config", "user.name", "x")
        run_git(repo, "config", "user.email", "x@example.invalid")
        # 45 segments of 100 characters: over MAX_PATH_LENGTH, and no longer
        # nested than Git will descend.
        long_name = "/".join("a" * 100 for _ in range(45)) + "/leaf.env"
        commit_tree_with_path(repo, long_name, f'k="{AWS_ACCESS_KEY_ID}"\n')

        scan = scan_history(repo)

        assert scan.findings == ()
        assert scan.truncated is True
        assert "history-truncated" in codes(scan)
        assert scan.truncated_because == (
            "a path in the history was too long to report at",
        )

    def test_a_path_just_under_the_limit_is_reported(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "long-enough")
        run_git(repo, "config", "user.name", "x")
        run_git(repo, "config", "user.email", "x@example.invalid")
        long_name = "/".join("b" * 100 for _ in range(20)) + "/leaf.env"
        commit_tree_with_path(repo, long_name, f'k="{AWS_ACCESS_KEY_ID}"\n')

        scan = scan_history(repo)

        assert scan.truncated is False
        assert [finding.location.path for finding in scan.findings] == [long_name]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


@needs_git
class TestFailures:
    def test_a_sha256_repository_is_refused_by_name(self, tmp_path: Path) -> None:
        """Named, not guessed at: a 64-character object name is not a SHA-1 name."""

        try:
            repo = init_repo(tmp_path / "sha256", object_format="sha256")
        except subprocess.CalledProcessError:  # pragma: no cover - old Git
            pytest.skip("this Git cannot create a SHA-256 repository")
        (repo / "a.env").write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "a secret in a SHA-256 repository")

        scan = scan_history(repo)

        assert scan.findings == ()
        assert codes(scan) == [git_cmd.KIND_OBJECT_FORMAT]
        assert codes(scan) == ["unsupported-object-format"]
        assert scan.result.files_scanned == 0

    def test_the_refusal_explains_the_limitation(self, tmp_path: Path) -> None:
        try:
            repo = init_repo(tmp_path / "sha256-message", object_format="sha256")
        except subprocess.CalledProcessError:  # pragma: no cover - old Git
            pytest.skip("this Git cannot create a SHA-256 repository")
        (repo / "a.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "first")

        scan = scan_history(repo)

        reason = scan.result.errors[0].reason
        assert "SHA-1" in reason
        assert "history" in reason

    def test_a_plain_directory_is_not_a_repository(self, tmp_path: Path) -> None:
        plain = tmp_path / "plain"
        plain.mkdir()

        scan = scan_history(plain)

        assert scan.findings == ()
        assert codes(scan) == ["not-a-git-repository"]

    def test_a_missing_path_is_not_found(self, tmp_path: Path) -> None:
        scan = scan_history(tmp_path / "no-such-repo")

        assert codes(scan) == ["not-found"]

    def test_a_missing_git_is_reported_by_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = init_repo(tmp_path / "no-git")
        (repo / "a.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "first")
        monkeypatch.setattr(
            git_cmd, "DEFAULT_GIT_PROGRAM", str(tmp_path / "there-is-no-git-here")
        )

        scan = scan_history(repo)

        assert codes(scan) == ["git-unavailable"]
        assert scan.findings == ()

    def test_a_hung_git_is_killed_at_the_timeout(self, tmp_path: Path) -> None:
        """A wrapper without a timeout is a CI job that waits forever."""

        repo = init_repo(tmp_path / "hangs")
        (repo / "a.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "first")
        fake = tmp_path / "slow-git"
        fake.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
        fake.chmod(0o755)
        original = git_cmd.DEFAULT_GIT_PROGRAM
        git_cmd.DEFAULT_GIT_PROGRAM = str(fake)
        try:
            scan = scan_history(repo, GitScanConfig(timeout=1))
        finally:
            git_cmd.DEFAULT_GIT_PROGRAM = original

        assert codes(scan) == ["git-timeout"]
        assert scan.findings == ()
        assert scan.result.files_scanned == 0

    def test_an_unreadable_object_is_an_error_not_a_skip(self, tmp_path: Path) -> None:
        """Unlike a binary blob, an unreadable object is a failure.

        Corrupted by content rather than by deletion: a deleted object makes
        ``rev-list`` itself fail, so the walk would never begin.
        """

        repo = init_repo(tmp_path / "damaged")
        (repo / "a.txt").write_text("clean\n", encoding="utf-8")
        commit_all(repo, "first")
        blobs = [
            name for name, kind in loose_object_names(repo).items() if kind == "blob"
        ]
        assert corrupt_loose_object(repo, blobs[0]) is True

        scan = scan_history(repo)

        assert codes(scan) == ["object-unreadable"]
        assert scan.blobs_unreadable == 1
        assert scan.blobs_scanned == 0
        assert_no_leaked_value(repr(scan.result))

    def test_a_corrupt_object_does_not_lose_the_other_findings(
        self, tmp_path: Path
    ) -> None:
        """One bad object must not cost the results of every other one."""

        repo = init_repo(tmp_path / "partly-damaged")
        (repo / "clean.txt").write_text("nothing here\n", encoding="utf-8")
        (repo / "good.env").write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "first")
        blobs = [
            name for name, kind in loose_object_names(repo).items() if kind == "blob"
        ]
        doomed = next(
            name
            for name in blobs
            if run_git(repo, "cat-file", "-p", name) == "nothing here\n"
        )
        assert corrupt_loose_object(repo, doomed) is True

        scan = scan_history(repo)

        assert "object-unreadable" in codes(scan)
        assert "aws-access-key-id" in rule_ids(
            scan
        ), "the readable blob was still scanned"
        assert scan.blobs_scanned == 1

    def test_no_error_message_ever_contains_a_credential(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path, GitScanConfig(max_commits=1))

        for error in scan.result.errors:
            assert isinstance(error, ScanError)
            assert_no_leaked_value(error.reason)
            assert_no_leaked_value(error.path or "")

    def test_git_stderr_never_reaches_the_caller(self, tmp_path: Path) -> None:
        """A repository can put anything in a diagnostic; none of it may pass."""

        repo = init_repo(tmp_path / "noisy")
        (repo / "a.txt").write_text("x\n", encoding="utf-8")
        commit_all(repo, "first")
        noisy = tmp_path / "noisy-git"
        noisy.write_text(
            f'#!/bin/sh\necho "{AWS_ACCESS_KEY_ID}" >&2\nexit 128\n', encoding="utf-8"
        )
        noisy.chmod(0o755)
        original = git_cmd.DEFAULT_GIT_PROGRAM
        git_cmd.DEFAULT_GIT_PROGRAM = str(noisy)
        try:
            scan = scan_history(repo)
        finally:
            git_cmd.DEFAULT_GIT_PROGRAM = original

        assert_no_leaked_value(repr(scan.result))


# ---------------------------------------------------------------------------
# The date window
# ---------------------------------------------------------------------------


@needs_git
class TestDateWindow:
    @pytest.fixture(autouse=True)
    def _dated_repo(self, tmp_path: Path) -> None:
        self.repo = init_repo(tmp_path / "dated")
        (self.repo / "old.env").write_text(
            f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )
        env = dict(FIXTURE_ENVIRONMENT)
        env["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00+0000"
        env["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00+0000"
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "-A"],
            env=env,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "old secret"],
            env=env,
            capture_output=True,
            check=True,
        )

    def test_a_since_before_the_secret_includes_it(self) -> None:
        scan = scan_history(self.repo, GitScanConfig(since="2019-01-01"))

        assert "aws-access-key-id" in rule_ids(scan)

    def test_a_since_after_the_secret_excludes_it(self) -> None:
        """The boundary of the window, and a place a scan can be empty on purpose."""

        scan = scan_history(self.repo, GitScanConfig(since="2021-01-01"))

        assert scan.findings == ()
        assert scan.result.errors == (), "an empty window is not a failure"

    def test_a_since_is_not_read_as_an_option(self) -> None:
        with pytest.raises(ValueError):
            GitScanConfig(since="--all")

    def test_an_unusable_date_is_refused_before_any_git_runs(self) -> None:
        """Fail on the setting, not halfway through a large history."""

        with pytest.raises(ValueError):
            GitScanConfig(since="-x")


# ---------------------------------------------------------------------------
# What a history scan reports
# ---------------------------------------------------------------------------


@needs_git
class TestTheResult:
    def test_blobs_scanned_is_the_file_count_of_the_result(
        self, deleted_secret_repo: Repo
    ) -> None:
        scan = scan_history(deleted_secret_repo.path)

        assert scan.blobs_scanned == scan.result.files_scanned
        assert scan.blobs_scanned > 0

    def test_the_counters_add_up_to_what_was_seen(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "tallied")
        (repo / "a.txt").write_text("clean\n", encoding="utf-8")
        (repo / "b.png").write_bytes(bytes(range(256)) * 4)
        (repo / "c.env").write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "first")

        scan = scan_history(repo)

        assert scan.blobs_seen == 3
        assert (
            scan.blobs_scanned + scan.blobs_binary + scan.blobs_too_large
            == scan.blobs_seen
        )

    def test_findings_are_sorted_deterministically(self, tmp_path: Path) -> None:
        repo = init_repo(tmp_path / "sorted")
        for name in ("z.env", "a.env", "m.env"):
            (repo / name).write_text(f'k="{AWS_ACCESS_KEY_ID}"\n', encoding="utf-8")
        commit_all(repo, "first")

        scan = scan_history(repo)

        paths = [finding.location.path for finding in scan.findings]
        assert paths == sorted(paths)

    def test_the_result_is_an_ordinary_scan_result(
        self, deleted_secret_repo: Repo
    ) -> None:
        """One reporter for every source, so no source gets its own envelope."""

        result = scan_history(deleted_secret_repo.path).result

        assert isinstance(result, ScanResult)
        assert set(result.to_dict()) == {
            "schema_version",
            "tool",
            "summary",
            "findings",
            "errors",
        }

    def test_the_tool_version_is_recorded(self, deleted_secret_repo: Repo) -> None:
        assert scan_history(deleted_secret_repo.path).result.tool_version

    def test_a_history_scan_of_a_clean_repository_is_clean(
        self, tmp_path: Path
    ) -> None:
        repo = init_repo(tmp_path / "clean")
        (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        commit_all(repo, "first")

        scan = scan_history(repo)

        assert scan.findings == ()
        assert scan.result.errors == ()
        assert scan.blobs_scanned == 1
