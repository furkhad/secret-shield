"""End-to-end tests for scanning a directory tree.

The unit tests in ``test_filesystem_source.py`` check each mechanism in
isolation. This module checks the thing that actually matters to a user: that
building a realistic tree, scanning it, and scanning it again produce the same
answer, and that the answer points at the right file.

The fixtures here are synthetic. Every credential-shaped value is assembled from
a prefix constant and a body constant, so the literal never appears in this file
as one string. Nothing here is a real credential.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from secret_shield.filters.paths import PathFilterConfig
from secret_shield.models import Confidence, DetectorKind, ScanResult, Severity
from secret_shield.scanner import ScanConfig
from secret_shield.sources import PathScanConfig, scan_path, walk
from tests.vendor_fixtures import (  # type: ignore
    AWS_SECRET_ACCESS_KEY,
    GITHUB_OAUTH_TOKEN,
    OPENAI_PROJECT_KEY,
    PRIVATE_KEY_BLOCK,
    STRIPE_PREFIXES,
    STRIPE_BODY,
)

RUNNING_AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
needs_non_root = pytest.mark.skipif(
    RUNNING_AS_ROOT, reason="root bypasses filesystem permission checks"
)


def config(**overrides: object) -> PathScanConfig:
    return PathScanConfig(**overrides)  # type: ignore[arg-type]


def stripe_live_key() -> str:
    """One synthetic Stripe key, assembled so the literal never sits in source."""

    return STRIPE_PREFIXES[0] + STRIPE_BODY


def identifiers(result: ScanResult) -> list[tuple[str, str, int]]:
    """A stable identity per finding, for order-sensitive assertions."""

    return [
        (f.rule_id, f.location.path, f.location.line) for f in result.sorted_findings()
    ]


# ---------------------------------------------------------------------------
# A realistic tree
# ---------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A tree shaped like a real repository, with secrets in the usual places.

    Every secret-shaped value is inside a file that *should* be scanned. The
    copies inside skipped directories exist to prove the skips work, and the
    scanner must find neither them nor their keys.
    """

    root = tmp_path / "project"
    root.mkdir()

    (root / "README.md").write_text("# Example\n\nNo secrets here.\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "example"\nversion = "0.1.0"\n', encoding="utf-8"
    )

    app = root / "src" / "example"
    app.mkdir(parents=True)
    (app / "__init__.py").write_text('__all__ = ["main"]\n', encoding="utf-8")
    (app / "settings.py").write_text(
        f'OPENAI = "{OPENAI_PROJECT_KEY}"\nRETRIES = 3\n', encoding="utf-8"
    )
    (app / "client.py").write_text(
        "import urllib.request\n\n\ndef fetch(url):\n    return urllib.request.urlopen(url)\n",
        encoding="utf-8",
    )

    tests = root / "tests"
    tests.mkdir()
    (tests / "conftest.py").write_text("import pytest\n", encoding="utf-8")

    # Real credential-shaped files that must be found.
    (root / ".env").write_text(
        f"GITHUB_TOKEN={GITHUB_OAUTH_TOKEN}\nSTRIPE={stripe_live_key()}\n", encoding="utf-8"
    )
    (root / "deploy.pem").write_text(PRIVATE_KEY_BLOCK, encoding="utf-8")
    (root / "config" ).mkdir()
    (root / "config" / "aws.ini").write_text(
        f"[default]\naws_secret_access_key = {AWS_SECRET_ACCESS_KEY}\n", encoding="utf-8"
    )

    # Copies inside paths that must be skipped.
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_text(
        f'const k = "{OPENAI_PROJECT_KEY}";\n', encoding="utf-8"
    )
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(f'key = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
    (root / "assets").mkdir()
    (root / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))

    # Noise that must not be reported.
    (root / "src" / "example" / "notes.txt").write_text(
        "Remember to rotate the credentials before the demo.\n", encoding="utf-8"
    )
    (root / "src" / "example" / "unicode.py").write_text(
        f'# 日本語コメント 🔐\nHEADER = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8"
    )

    return root


class TestScanningARealisticProject:
    def test_every_secret_is_found(self, project: Path) -> None:
        """The load-bearing test: nothing planted is missed.

        Six distinct credentials across five files, found once each.

        Before Stage 4 this list held a seventh entry: a second
        ``high-entropy-string`` finding on the AWS line, because the entropy
        rule and the vendor rule were both right about the same 40 characters
        and neither knew about the other. Fusion collapses that pair, and the
        AWS credential is now reported as a single composite finding carrying
        the vendor rule's identity. The detection is not lost -- there is one
        finding fewer because there is one secret, not because anything stopped
        looking.
        """

        result = scan_path(project, config())
        assert identifiers(result) == [
            ("github-pat-classic", ".env", 1),
            ("stripe-secret-key-live", ".env", 2),
            ("aws-secret-access-key", "config/aws.ini", 2),
            ("private-key-block", "deploy.pem", 1),
            ("openai-api-key", "src/example/settings.py", 1),
            ("openai-api-key", "src/example/unicode.py", 2),
        ]

    def test_the_aws_line_is_reported_once_not_twice(self, project: Path) -> None:
        """The overlap that motivated fusion, asserted on its own.

        The entropy rule and ``aws-secret-access-key`` see identical bytes here.
        The result must be one finding, and it must be the vendor's: the
        anonymous entropy finding would file a CRITICAL AWS credential as a
        MEDIUM anonymous string and give a reviewer nothing to act on.
        """

        result = scan_path(project, config())
        aws_line = [
            finding
            for finding in result.findings
            if finding.location.path == "config/aws.ini" and finding.location.line == 2
        ]

        assert len(aws_line) == 1
        assert aws_line[0].rule_id == "aws-secret-access-key"
        assert aws_line[0].detector is DetectorKind.COMPOSITE
        assert aws_line[0].severity is Severity.CRITICAL
        # Entropy corroboration promotes a PROBABLE vendor match, but never past
        # the ceiling: nothing here has been checked against AWS.
        assert aws_line[0].confidence is Confidence.HIGH_CONFIDENCE

    def test_each_planted_credential_is_reported_by_a_vendor_rule(self, project: Path) -> None:
        """Every rule that fired names a vendor.

        Asserted as a set of rule ids so a future change that adds or removes a
        detector is visible here rather than silently absorbed. ``high-entropy-
        string`` was on this list until Stage 4: it was there only as the
        duplicate of the AWS match, and fusion removed the duplicate rather than
        the detection.
        """

        rules = {finding.rule_id for finding in scan_path(project, config()).findings}
        assert rules == {
            "github-pat-classic",
            "stripe-secret-key-live",
            "aws-secret-access-key",
            "private-key-block",
            "openai-api-key",
        }

    def test_every_planted_file_is_covered(self, project: Path) -> None:
        """No planted file is missing from the findings, whatever the rule ids."""

        found_paths = {finding.location.path for finding in scan_path(project, config()).findings}
        assert found_paths == {
            ".env",
            "config/aws.ini",
            "deploy.pem",
            "src/example/settings.py",
            "src/example/unicode.py",
        }

    def test_nothing_inside_a_skipped_directory_is_found(self, project: Path) -> None:
        result = scan_path(project, config())
        paths = {finding.location.path for finding in result.findings}
        assert not any(path.startswith(("node_modules/", ".git/")) for path in paths)
        assert not any(OPENAI_PROJECT_KEY in f.masked_value for f in result.findings)

    def test_the_skips_are_reported_with_reasons(self, project: Path) -> None:
        result = walk(project, config())
        counts = result.counts_by_reason()
        assert counts["ignored-directory"] == 2
        assert counts["ignored-extension"] == 1

    def test_prose_about_credentials_is_not_a_finding(self, project: Path) -> None:
        """"Rotate the credentials" is not a credential."""

        result = scan_path(project, config())
        assert not any(
            finding.location.path.endswith("notes.txt") for finding in result.findings
        )

    def test_clean_files_are_counted_but_produce_nothing(self, project: Path) -> None:
        """The count is asserted, not the absence of findings.

        Nine text files: three source files plus ``notes.txt`` and ``unicode.py``
        under ``src/example``, ``conftest.py``, ``README.md``,
        ``pyproject.toml``, ``.env``, ``deploy.pem`` and ``config/aws.ini``.
        Everything else is skipped before reading.
        """

        result = scan_path(project, config())
        clean = {"README.md", "pyproject.toml", "src/example/__init__.py", "src/example/client.py"}
        assert result.files_scanned == 11
        assert not any(finding.location.path in clean for finding in result.findings)

    def test_the_candidate_count_matches_the_scanned_count(self, project: Path) -> None:
        """Nothing in the tree is a regular file that was silently dropped."""

        walked = walk(project, config())
        result = scan_path(project, config())
        assert [entry.relative for entry in walked.files] == sorted(
            entry.relative for entry in walked.files
        )
        assert result.files_scanned == len(walked.files) == 11
        assert result.errors == ()

    def test_statistics_add_up(self, project: Path) -> None:
        expected = 0
        walked = walk(project, config())
        for entry in walked.files:
            expected += entry.size

        result = scan_path(project, config())
        assert result.bytes_scanned == expected
        assert result.files_scanned == len(walked.files)

    def test_no_errors_on_a_healthy_tree(self, project: Path) -> None:
        assert scan_path(project, config()).errors == ()

    def test_findings_are_sorted_by_path(self, project: Path) -> None:
        paths = [finding.location.path for finding in scan_path(project, config()).sorted_findings()]
        assert paths == sorted(paths, key=lambda p: (p,))


class TestDeterminismEndToEnd:
    def test_two_scans_are_identical(self, project: Path) -> None:
        first = identifiers(scan_path(project, config()))
        second = identifiers(scan_path(project, config()))
        assert first == second

    def test_a_rescan_after_a_rebuild_is_identical(self, project: Path) -> None:
        """Rewrite every file, then scan again.

        Content is byte-identical, so the answer must be too. If it is not, the
        scan is depending on something beyond the files -- timestamps, inode
        order, hash seed.
        """

        before = identifiers(scan_path(project, config()))
        for path in sorted(project.rglob("*")):
            if path.is_file() and not path.is_symlink():
                path.write_bytes(path.read_bytes())
        after = identifiers(scan_path(project, config()))
        assert before == after

    def test_the_order_does_not_depend_on_creation_order(self, tmp_path: Path) -> None:
        """Create the same tree with names in opposite orders.

        Filesystem enumeration order commonly follows creation order on some
        filesystems. If the result order tracked it, the two trees would
        disagree.
        """

        forward = tmp_path / "forward"
        backward = tmp_path / "backward"
        names = ["alpha.py", "zulu.py", "mike.py", "bravo.py", "yankee.py"]

        for root, order in ((forward, names), (backward, list(reversed(names)))):
            root.mkdir()
            for name in order:
                (root / name).write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")

        assert identifiers(scan_path(forward, config())) == identifiers(
            scan_path(backward, config())
        )

    def test_repeated_walks_of_a_real_tree_agree(self, project: Path) -> None:
        first = walk(project, config())
        for _ in range(3):
            assert walk(project, config()) == first

    def test_the_process_hash_seed_does_not_matter(self, project: Path) -> None:
        """Runs the scan in a fresh interpreter with a different hash seed."""

        import subprocess

        script = (
            "import sys; sys.path.insert(0, 'src'); sys.path.insert(0, 'tests')\n"
            "from secret_shield.sources import scan_path\n"
            f"r = scan_path({str(project)!r})\n"
            "for f in r.sorted_findings():\n"
            "    print(f.rule_id, f.location.path, f.location.line)\n"
        )
        outputs = set()
        for seed in ("0", "1", "12345"):
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONHASHSEED": seed},
                check=True,
            )
            outputs.add(result.stdout)

        assert len(outputs) == 1
        assert outputs.pop().strip()


class TestMixedContent:
    def test_a_binary_file_among_text_files_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        (tmp_path / "b.blob").write_bytes(b"\x00\x01\x02" * 100)
        (tmp_path / "c.py").write_text(f'K = "{GITHUB_OAUTH_TOKEN}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config())
        assert result.files_scanned == 2
        assert {error.code for error in result.errors} == {"binary"}
        assert len(result.findings) == 2

    def test_an_undecodable_file_is_distinguished_from_a_binary_one(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "legacy.log").write_bytes("café".encode("latin-1"))
        (tmp_path / "modern.py").write_text("x = 1\n", encoding="utf-8")

        result = scan_path(tmp_path, config())
        assert {error.code for error in result.errors} == {"invalid-encoding"}

    def test_an_empty_file_is_scanned_and_finds_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "empty.py").write_bytes(b"")
        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1
        assert result.bytes_scanned == 0
        assert result.errors == ()

    def test_a_large_but_legal_file_is_scanned(self, tmp_path: Path) -> None:
        """The default cap is generous; ordinary big files must not be refused."""

        filler = "# a comment line of ordinary text\n"
        body = filler * 4000 + f'K = "{OPENAI_PROJECT_KEY}"\n'
        target = tmp_path / "big.py"
        target.write_text(body, encoding="utf-8")

        assert target.stat().st_size > 100_000
        result = scan_path(target, config())
        assert result.files_scanned == 1
        assert len(result.findings) == 1

    def test_a_file_over_the_size_cap_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "huge.py"
        target.write_text(f'K = "{OPENAI_PROJECT_KEY}"\n' * 100, encoding="utf-8")
        result = scan_path(target, config(scan=ScanConfig(max_file_size=200)))
        assert [error.code for error in result.errors] == ["too-large"]
        assert result.files_scanned == 0

    def test_utf8_without_a_bom_and_with_one_agree(self, tmp_path: Path) -> None:
        body = f'K = "{OPENAI_PROJECT_KEY}"\n'
        (tmp_path / "plain.py").write_text(body, encoding="utf-8")
        (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbf" + body.encode())

        result = scan_path(tmp_path, config())
        columns = {
            finding.location.path: finding.location.column for finding in result.findings
        }
        assert columns["plain.py"] == columns["bom.py"]


class TestPartialFailure:
    @needs_non_root
    def test_an_unreadable_file_does_not_hide_the_others(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        (root / "locked.py").write_text(f'K = "{GITHUB_OAUTH_TOKEN}"\n', encoding="utf-8")
        (root / "c.py").write_text(f'K = "{AWS_SECRET_ACCESS_KEY}"\n', encoding="utf-8")
        (root / "locked.py").chmod(0o000)
        try:
            result = scan_path(root, config())
            assert result.files_scanned == 2
            assert [error.code for error in result.errors] == ["read-failed"]
            assert [error.path for error in result.errors] == ["locked.py"]
            assert len(result.findings) == 2
        finally:
            (root / "locked.py").chmod(0o644)

    @needs_non_root
    def test_an_unreadable_directory_does_not_hide_the_others(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        (root / "visible.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        locked = root / "locked"
        locked.mkdir()
        (locked / "hidden.py").write_text(f'K = "{GITHUB_OAUTH_TOKEN}"\n', encoding="utf-8")
        locked.chmod(0o000)
        try:
            result = scan_path(root, config())
            assert result.files_scanned == 1
            assert len(result.findings) == 1
            assert [error.path for error in result.errors] == ["locked"]
        finally:
            locked.chmod(0o755)

    def test_a_truncated_scan_says_so(self, tmp_path: Path) -> None:
        """A capped scan must never be reportable as a clean one."""

        for index in range(10):
            (tmp_path / f"f{index}.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config(max_files=3))
        assert [error.code for error in result.errors] == ["too-many-files"]
        assert result.files_scanned == 3

    def test_errors_and_findings_coexist(self, tmp_path: Path) -> None:
        """One failure must not discard the results that did arrive."""

        (tmp_path / "a.blob").write_bytes(b"\x00" * 50)
        (tmp_path / "b.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        result = scan_path(tmp_path, config())
        assert result.errors and result.findings


class TestHostileTree:
    """Repository contents are data, never instructions.

    Nothing here is executed, interpreted, or matched as a pattern. The tests
    check that a tree crafted to confuse a scanner is merely scanned.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "a" * 200 + ".py",
            "file\nwith\nnewlines.py",
            "tab\tand\tspaces.py",
            "emoji-\U0001f510-key.py",
            ".hidden",
            "-rf.py",
            "--output.py",
            "quote'and\"quote.py",
            "semi;colon&amp.py",
            "$HOME.py",
            "pipe|and>redirect.py",
            "..leading-dots.py",
        ],
        ids=[
            "long",
            "newlines",
            "tabs",
            "emoji",
            "dotfile",
            "dash",
            "double-dash",
            "quotes",
            "shell-metachars",
            "variable",
            "redirects",
            "leading-dots",
        ],
    )
    def test_a_hostile_filename_is_handled(self, tmp_path: Path, name: str) -> None:
        """No exception, no escape from the root, no crash in a log line.

        Every name here is legal on Linux and would be trouble for a tool that
        interpolated it into a shell command or read it from a glob. Nothing in
        this scanner does either.
        """

        target = tmp_path / name
        target.write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1
        assert len(result.findings) == 1

        path = result.findings[0].location.path
        # The reported path is sanitised, so it cannot repaint a terminal.
        assert "\x00" not in path
        assert "\n" not in path
        assert "\t" not in path

    def test_a_nul_byte_in_a_name_is_rejected_by_the_platform(
        self, tmp_path: Path
    ) -> None:
        """No POSIX filesystem accepts a NUL in a name; the test says so."""

        with pytest.raises(ValueError):
            (tmp_path / "null\x00byte.py").write_text("x = 1\n", encoding="utf-8")

    def test_a_deeply_nested_tree_terminates(self, tmp_path: Path) -> None:
        """Depth is bounded by the filesystem, not by anything the scanner adds."""

        current = tmp_path / "root"
        current.mkdir()
        for depth in range(60):
            current = current / f"d{depth}"
        current.mkdir(parents=True)
        (current / "deep.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1
        assert len(result.findings) == 1

    def test_a_name_matching_an_ignore_rule_is_not_confused_by_a_prefix(
        self, tmp_path: Path
    ) -> None:
        """``env`` is ignored; ``environment`` and ``envrc`` are not."""

        (tmp_path / "env").mkdir()
        (tmp_path / "env" / "leak.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        (tmp_path / "environment").mkdir()
        (tmp_path / "environment" / "ok.py").write_text(
            f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8"
        )

        result = scan_path(tmp_path, config())
        assert [finding.location.path for finding in result.findings] == ["environment/ok.py"]

    def test_a_file_that_looks_like_a_glob_is_literal(self, tmp_path: Path) -> None:
        (tmp_path / "*.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "real.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")

        result = scan_path(tmp_path, config(filters=PathFilterConfig()))
        assert result.files_scanned == 2

    def test_a_regex_metacharacter_in_a_name_is_not_interpreted(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "a(b|c)[d].py"
        target.write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        result = scan_path(tmp_path, config())
        assert result.files_scanned == 1
        assert result.findings[0].location.path == "a(b|c)[d].py"

    def test_a_control_character_in_a_name_is_not_scanned(
        self, tmp_path: Path
    ) -> None:
        """A name the terminal would interpret is refused, not executed.

        A filename carrying an ANSI escape is the cheapest possible way to forge
        a line in someone's CI log. The file is skipped rather than reported, so
        no such name ever reaches a report.
        """

        hostile = "evil\x1b[31mFAKE\x1b[0m.py"
        try:
            target = tmp_path / hostile
            target.write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        except (ValueError, OSError):  # pragma: no cover - platform dependent
            pytest.skip("the filesystem rejects this name")

        result = scan_path(tmp_path, config())
        for finding in result.findings:
            assert "\x1b" not in finding.location.path
        for error in result.errors:
            assert "\x1b" not in error.path


class TestNoSecretIsEverRetained:
    @pytest.fixture
    def leaked_tree(self, tmp_path: Path) -> Path:
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        (root / "b.log").write_bytes(b"\x00" + OPENAI_PROJECT_KEY.encode() + b"\x00")
        (root / "c.ini").write_text(f"x = {AWS_SECRET_ACCESS_KEY}\n", encoding="utf-8")
        return root

    def test_no_finding_carries_the_value(self, leaked_tree: Path) -> None:
        for finding in scan_path(leaked_tree, config()).findings:
            assert OPENAI_PROJECT_KEY not in finding.masked_value
            assert AWS_SECRET_ACCESS_KEY not in finding.masked_value
            assert "\x00" not in finding.masked_value

    def test_the_result_repr_carries_no_value(self, leaked_tree: Path) -> None:
        """A result is the object most likely to be logged or serialised."""

        text = repr(scan_path(leaked_tree, config()))
        assert OPENAI_PROJECT_KEY not in text
        assert AWS_SECRET_ACCESS_KEY not in text

    def test_the_rendered_report_carries_no_value(self, leaked_tree: Path) -> None:
        from secret_shield.report import render_text

        text = render_text(scan_path(leaked_tree, config()))
        assert OPENAI_PROJECT_KEY not in text
        assert AWS_SECRET_ACCESS_KEY not in text

    def test_findings_are_redacted_at_construction(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text(f'K = "{OPENAI_PROJECT_KEY}"\n', encoding="utf-8")
        finding = scan_path(target, config()).findings[0]
        assert finding.masked_value
        assert set(finding.masked_value) == {"*"}
        assert OPENAI_PROJECT_KEY not in finding.masked_value


class TestScanningThisRepository:
    def test_a_directory_scan_of_the_repo_runs(self) -> None:
        """A smoke test on a real repository, not a synthetic tree.

        Skips the assertion on the finding count: the test suite deliberately
        contains credential-shaped fixtures, so a handful of findings here are
        correct behaviour rather than a defect.
        """

        repo_root = Path(__file__).resolve().parent.parent.parent
        result = scan_path(repo_root, config())
        assert result.files_scanned > 0
        assert result.bytes_scanned > 0

    def test_the_package_source_produces_nothing(self) -> None:
        """The load-bearing precision test, now over a whole tree.

        Every file under ``src/`` is documentation, regular expressions and
        ordinary code. A finding here means a threshold, filter or tokenizer has
        started crying wolf, and the failure lists exactly which values did it.
        """

        package = Path(__file__).resolve().parent.parent.parent / "src"
        offenders = [
            f"{finding.location.path}:{finding.location.line}"
            for finding in scan_path(package, config()).findings
        ]
        assert offenders == [], f"false positives in our own source: {offenders}"

    def test_a_scan_of_the_tests_tree_reports_only_expected_paths(self) -> None:
        """Test fixtures hold credential-shaped values by design.

        They must still be *found* -- that is what proves the detectors work --
        so this asserts the finding count is bounded and every path is inside
        the test tree, rather than asserting a number that changes whenever a
        fixture is added.
        """

        tests = Path(__file__).resolve().parent.parent
        result = scan_path(tests, config())
        assert len(result.findings) < 200
        for finding in result.findings:
            assert not finding.location.path.startswith(("/", "../"))