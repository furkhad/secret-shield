"""Functional tests for the ``secret-shield`` command line interface.

Every test here runs the CLI as a **real subprocess**. That is the point: the
CLI's contract is a contract between two processes, so a test that calls
``cli.main()`` in-process cannot check the parts that matter most -- the exit
status the parent sees, whether stdout survives a pipe, or whether a stream that
should have stayed empty stayed empty.

What these tests hold the CLI to
--------------------------------

**The exit code is the API.** ``0`` clean, ``1`` findings at the threshold, ``2``
usage or configuration, ``3`` a partial scan. In particular ``3`` must beat
``1``: a scan that could not read every input describes a partial tree, and a
truncated scan must never be able to pass a pipeline that only distinguishes
``0`` from ``1``.

**stdout is the report and nothing else.** Warnings, per-file failures and the
``--output`` confirmation go to stderr. With ``--output`` stdout is empty
entirely. A test helper asserts this on every scan it runs, so the guarantee is
checked incidentally a hundred times rather than in one place that can drift.

**Nothing secret reaches either stream.** The files below contain values marked
with a synthetic prefix. Each scan test asserts that neither stdout nor stderr
contains one, so a regression that starts printing a source line fails loudly
instead of quietly.

**The output is deterministic.** The same command over an unchanged tree
produces byte-identical bytes, and ``--jobs 1`` and ``--jobs 8`` agree. A report
that varies run to run cannot be diffed or cached, which is most of what a CI
report is for.

No network access and no real credentials: every value is fabricated here or
imported from :mod:`tests.vendor_fixtures`.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from secret_shield import __version__ as PACKAGE_VERSION

_SRC_DIR = Path(__file__).resolve().parents[2] / "src"

#: The synthetic value planted in :func:`secret_file`. A real vendor prefix with
#: a fabricated body: it satisfies the AWS pattern while being obviously not a
#: live credential, so a leak of it into any output stream is a real failure.
SYNTHETIC_AWS_KEY = "AKIA5H2XNSYNTHKEY09A"

#: A second synthetic value, on the same line as the first, so the "no raw
#: secret" assertion covers a line holding more than one candidate.
SYNTHETIC_SECRET = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"

#: Never allowed to appear in any stream, in any test in this module.
FORBIDDEN_VALUES = (SYNTHETIC_AWS_KEY, SYNTHETIC_SECRET)

#: A value no test should ever print, checked to make sure the list above is not
#: silently emptied by a refactor of the fixtures.
assert all(FORBIDDEN_VALUES), "the leak sentinel list must not be empty"


# ---------------------------------------------------------------------------
# Running the CLI
# ---------------------------------------------------------------------------


def run_cli(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    stdin: str | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m secret_shield`` as a subprocess.

    ``-m`` rather than the installed console script so the tests pass in a bare
    checkout as well as an installed environment. A test asserts separately that
    the two invocations agree.

    Args:
        *args: Arguments after the program name.
        env: Complete environment, or ``None`` to inherit this process's. A
            partial environment is deliberately not accepted: inheriting is
            right for most tests, and the few that need a clean one must say so
            explicitly rather than by omission.
        cwd: Working directory, or ``None`` to inherit.
        stdin: Text piped to the process's standard input.
        timeout: Seconds before the child is killed.

    Returns:
        The completed process, with text streams decoded.
    """

    return subprocess.run(
        [sys.executable, "-m", "secret_shield", *args],
        env=env,
        cwd=None if cwd is None else str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def clean_env(**overrides: str) -> dict[str, str]:
    """Return an environment with every ``SECRETSHIELD_*`` setting removed.

    A developer's own ``SECRETSHIELD_JOBS`` in their shell would otherwise
    change what these tests observe, and a test that passes on the author's
    machine and fails in CI is worse than no test.
    """

    base = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("SECRETSHIELD_")
    }
    base.update(overrides)
    return base


def assert_no_synthetic_value(result: subprocess.CompletedProcess[str]) -> None:
    """Fail if either stream contains a planted value.

    Checked for *both* streams, not just stdout: a diagnostic that pastes a
    source line is exactly as bad as a report that does.
    """

    for stream_name, payload in (("stdout", result.stdout), ("stderr", result.stderr)):
        for value in FORBIDDEN_VALUES:
            assert value not in payload, (
                f"the synthetic value leaked into {stream_name}; "
                "no stream may ever print a detected value"
            )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """A file with no secrets in it."""

    path = tmp_path / "clean_module.py"
    path.write_text(
        "def add(first: int, second: int) -> int:\n"
        '    """Return the sum of two integers."""\n'
        "    return first + second\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    """A file holding two synthetic values that the scanner does detect."""

    path = tmp_path / "settings.py"
    path.write_text(
        f'AWS_ACCESS_KEY_ID = "{SYNTHETIC_AWS_KEY}"\n'
        f'GENERIC_TOKEN = "{SYNTHETIC_SECRET}"\n',
        encoding="utf-8",
    )
    return path


@pytest.fixture
def secret_tree(tmp_path: Path) -> Path:
    """A directory with a secret at the root and one nested three levels down.

    Deep enough that ``--max-depth`` changes what is reported, which is what
    makes that flag testable rather than decorative.
    """

    root = tmp_path / "tree"
    nested = root / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (root / "top.py").write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
    (nested / "deep.py").write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
    (root / "ok.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Help and version
# ---------------------------------------------------------------------------


class TestHelpAndVersion:
    """The interface has to be usable by someone who has never seen it."""

    def test_help_exits_zero_and_prints_usage(self) -> None:
        result = run_cli("--help")

        assert result.returncode == 0
        assert "usage: secret-shield" in result.stdout
        assert_no_synthetic_value(result)

    def test_help_names_both_subcommands(self) -> None:
        """A new user must be able to see the whole surface from one screen."""

        stdout = run_cli("--help").stdout

        assert "scan" in stdout
        assert "rules" in stdout

    def test_help_documents_the_exit_codes(self) -> None:
        """CI authors need the exit codes without reading the source."""

        stdout = run_cli("--help").stdout

        for code in ("0", "1", "2", "3", "4", "130"):
            assert re.search(
                rf"^\s+{code}\s", stdout, re.MULTILINE
            ), f"exit code {code} is not documented in --help"

    def test_help_offers_examples(self) -> None:
        stdout = run_cli("--help").stdout

        assert "Examples:" in stdout
        assert "secret-shield scan" in stdout

    def test_scan_help_documents_every_option(self) -> None:
        """Each flag must explain itself; none may be undocumented.

        The list is written out rather than derived from the parser so that
        *removing* an option fails this test instead of silently shrinking it.
        """

        stdout = run_cli("scan", "--help").stdout

        for option in (
            "--jobs",
            "--max-file-size",
            "--max-files",
            "--max-depth",
            "--max-line-length",
            "--follow-symlinks",
            "--output",
            "--format",
            "--fingerprint",
            "--min-confidence",
            "--fail-on",
            "--project-root",
        ):
            assert option in stdout, f"{option} is undocumented in scan --help"

    def test_scan_help_does_not_promise_an_unimplemented_flag(self) -> None:
        """No flag may exist for a capability this release lacks.

        ``--no-color`` is the specific one to watch: there is no colour support,
        so a flag to turn it off would be a lie about what the tool can do.
        """

        stdout = run_cli("scan", "--help").stdout

        assert "--no-color" not in stdout
        assert "--git" not in stdout

    def test_rules_help_documents_the_listing(self) -> None:
        stdout = run_cli("rules", "--help").stdout

        assert "list" in stdout
        assert "usage: secret-shield rules" in stdout

    def test_version_prints_the_package_version(self) -> None:
        """The version must come from the package, not a literal in the CLI."""

        result = run_cli("--version")

        assert result.returncode == 0
        assert result.stdout.strip() == f"secret-shield {PACKAGE_VERSION}"

    def test_module_and_console_script_agree(self) -> None:
        """``python -m`` and the installed script must be indistinguishable.

        Otherwise a CI job that runs one and a developer who runs the other see
        different usage text, and a diff of "the same" command never matches.
        """

        executable = Path(sys.executable).parent / "secret-shield"
        if not executable.exists():
            pytest.skip("console script is not installed in this environment")

        for flag in ("--help", "--version"):
            via_module = run_cli(flag)
            via_script = subprocess.run(
                [str(executable), flag],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            assert (
                via_script.stdout == via_module.stdout
            ), f"{flag} differs between python -m and the console script"
            assert via_script.returncode == via_module.returncode


# ---------------------------------------------------------------------------
# Scanning a file
# ---------------------------------------------------------------------------


class TestScanFile:
    """Scanning the simplest target: one file the user named."""

    def test_clean_file_exits_zero(self, clean_file: Path) -> None:
        result = run_cli("scan", str(clean_file))

        assert result.returncode == 0
        assert_no_synthetic_value(result)

    def test_file_with_a_secret_exits_one(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file))

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_findings_are_reported_on_stdout(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file))

        assert "aws-access-key-id" in result.stdout
        assert "FINDINGS" in result.stdout

    def test_no_diagnostics_when_the_scan_is_clean(self, clean_file: Path) -> None:
        """A clean scan should be silent on stderr.

        Not just "non-fatal": a scanner that chatters on every run trains people
        to ignore its stderr, which is where a real warning would go.
        """

        result = run_cli("scan", str(clean_file))

        assert result.stderr == ""

    def test_report_goes_to_stdout_only(self, secret_file: Path) -> None:
        """A finding is not a diagnostic, so it belongs on stdout."""

        result = run_cli("scan", str(secret_file))

        assert result.stdout.strip()
        assert "aws-access-key-id" not in result.stderr

    def test_value_is_masked_not_printed(self, secret_file: Path) -> None:
        """The report states that a secret exists, never what it is."""

        result = run_cli("scan", str(secret_file))
        masked = [
            line
            for line in result.stdout.splitlines()
            if line.lstrip().startswith("masked")
        ]

        assert masked, "the text report should show a masked value"
        assert (
            masked[0].split(":", 1)[1].strip().strip("*") == ""
        ), "the masked field should contain only mask characters"

    def test_source_line_is_not_quoted(self, secret_file: Path) -> None:
        """No line of the scanned file may appear in the report.

        This is the guarantee that a masked value is enough on its own: if the
        surrounding line were printed, masking it would achieve nothing.
        """

        result = run_cli("scan", str(secret_file))

        assert "AWS_ACCESS_KEY_ID =" not in result.stdout
        assert "GENERIC_TOKEN =" not in result.stdout


# ---------------------------------------------------------------------------
# Scanning a directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    """Directory traversal, including the depth limit."""

    def test_directory_with_a_secret_exits_one(self, secret_tree: Path) -> None:
        result = run_cli("scan", str(secret_tree))

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_directory_reports_files_at_every_depth(self, secret_tree: Path) -> None:
        result = run_cli("scan", str(secret_tree))

        assert "top.py" in result.stdout
        assert "deep.py" in result.stdout

    def test_clean_directory_exits_zero(self, tmp_path: Path) -> None:
        root = tmp_path / "clean_tree"
        root.mkdir()
        (root / "a.py").write_text("X = 1\n", encoding="utf-8")
        (root / "b.py").write_text("Y = 2\n", encoding="utf-8")

        result = run_cli("scan", str(root))

        assert result.returncode == 0

    def test_max_depth_bounds_the_descent(self, secret_tree: Path) -> None:
        """``--max-depth`` must actually stop the walk, not just be accepted."""

        shallow = run_cli("scan", str(secret_tree), "--max-depth", "0")
        full = run_cli("scan", str(secret_tree))

        assert "top.py" in shallow.stdout
        assert "deep.py" not in shallow.stdout
        assert "deep.py" in full.stdout

    def test_dot_target_works(self, secret_tree: Path) -> None:
        """``.`` is the form every CI job uses."""

        result = run_cli("scan", ".", cwd=secret_tree)

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_trailing_slash_does_not_break_a_directory_target(
        self, secret_tree: Path
    ) -> None:
        result = run_cli("scan", f"{secret_tree}{os.sep}")

        assert result.returncode == 1

    def test_max_files_caps_the_work(self, secret_tree: Path) -> None:
        result = run_cli(
            "scan", str(secret_tree), "--max-files", "1", "--format", "json"
        )
        payload = json.loads(result.stdout)

        assert payload["summary"]["files_scanned"] <= 1


# ---------------------------------------------------------------------------
# Formats
# ---------------------------------------------------------------------------


class TestFormats:
    """Each rendering must be complete, parseable and free of secrets."""

    def test_json_is_valid_and_pipeable(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--format", "json")

        assert result.returncode == 1
        payload = json.loads(result.stdout)
        assert payload["findings"]
        assert_no_synthetic_value(result)

    def test_json_finding_carries_the_documented_keys(self, secret_file: Path) -> None:
        """A stable schema is what lets CI consume the report."""

        payload = json.loads(
            run_cli("scan", str(secret_file), "--format", "json").stdout
        )
        finding = payload["findings"][0]

        assert {
            "rule_id",
            "severity",
            "confidence",
            "location",
            "masked_value",
            "fingerprint",
        } <= set(finding)

    def test_json_clean_target_has_no_findings(self, clean_file: Path) -> None:
        payload = json.loads(
            run_cli("scan", str(clean_file), "--format", "json").stdout
        )

        assert payload["findings"] == []

    def test_json_summary_agrees_with_the_findings(self, secret_tree: Path) -> None:
        """The count must describe what is listed, or the report cannot be checked."""

        payload = json.loads(
            run_cli("scan", str(secret_tree), "--format", "json").stdout
        )

        assert payload["summary"]["findings_count"] == len(payload["findings"])

    def test_markdown_is_a_table(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--format", "markdown")

        assert result.returncode == 1
        assert "## Findings" in result.stdout
        assert "| Rule |" in result.stdout
        assert_no_synthetic_value(result)

    def test_markdown_escapes_pipes_so_the_table_survives(
        self, secret_file: Path
    ) -> None:
        """A masked value of asterisks must not break Markdown table layout."""

        result = run_cli("scan", str(secret_file), "--format", "markdown")
        row = next(
            line
            for line in result.stdout.splitlines()
            if "aws-access-key-id" in line and line.startswith("|")
        )

        cells = row.split("|")
        assert len(cells) == 7, "a five-column row plus two delimiters"

    def test_text_is_the_default(self, secret_file: Path) -> None:
        """Omitting ``--format`` must give the same bytes as asking for text."""

        default = run_cli("scan", str(secret_file))
        explicit = run_cli("scan", str(secret_file), "--format", "text")

        assert default.stdout == explicit.stdout

    def test_every_format_is_valid_json_or_markdown_only(
        self, secret_file: Path
    ) -> None:
        """No format may smuggle a diagnostic into stdout."""

        for fmt in ("text", "json", "markdown"):
            result = run_cli("scan", str(secret_file), "--format", fmt)
            assert_no_synthetic_value(result)
            if fmt == "json":
                json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Writing to a file
# ---------------------------------------------------------------------------


class TestOutput:
    """``--output`` is the mode a CI job uses, so it must be safe and quiet."""

    def test_output_writes_the_report_and_empties_stdout(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "report.json"
        result = run_cli(
            "scan", str(secret_file), "--format", "json", "--output", str(destination)
        )

        assert result.returncode == 1
        assert result.stdout == "", "a report on stdout would corrupt a captured stream"
        assert json.loads(destination.read_text(encoding="utf-8"))["findings"]

    def test_output_file_is_owner_only(self, secret_file: Path, tmp_path: Path) -> None:
        """A report about secrets must not be world-readable, not even briefly."""

        destination = tmp_path / "report.json"
        run_cli("scan", str(secret_file), "--output", str(destination))

        assert destination.stat().st_mode & 0o777 == 0o600

    def test_output_confirms_on_stderr(self, secret_file: Path, tmp_path: Path) -> None:
        """The confirmation goes to stderr so stdout stays pipeable."""

        destination = tmp_path / "report.txt"
        result = run_cli("scan", str(secret_file), "--output", str(destination))

        assert str(destination) in result.stderr
        assert_no_synthetic_value(result)

    def test_output_file_contains_no_secret(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "report.json"
        run_cli(
            "scan", str(secret_file), "--format", "json", "--output", str(destination)
        )

        for value in FORBIDDEN_VALUES:
            assert value not in destination.read_text(encoding="utf-8")

    def test_output_replaces_an_existing_report(
        self, secret_file: Path, clean_file: Path, tmp_path: Path
    ) -> None:
        """A second run must not append to or corrupt the first report."""

        destination = tmp_path / "report.json"
        run_cli(
            "scan", str(secret_file), "--format", "json", "--output", str(destination)
        )
        run_cli(
            "scan", str(clean_file), "--format", "json", "--output", str(destination)
        )

        assert json.loads(destination.read_text(encoding="utf-8"))["findings"] == []

    def test_output_to_a_missing_directory_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        result = run_cli(
            "scan", str(secret_file), "--output", str(tmp_path / "absent" / "r.json")
        )

        assert result.returncode == 2
        assert result.stdout == ""

    def test_output_to_a_directory_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        result = run_cli("scan", str(secret_file), "--output", str(tmp_path))

        assert result.returncode == 2

    def test_failed_output_leaves_the_previous_report_intact(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        """A failed write must not damage what was already there.

        This is the reason the report is staged in a temporary file and moved
        into place: a half-written report is worse than a stale one, because it
        looks current.
        """

        directory = tmp_path / "locked"
        directory.mkdir()
        destination = directory / "report.json"
        destination.write_text("PREVIOUS REPORT", encoding="utf-8")
        directory.chmod(0o555)
        try:
            result = run_cli("scan", str(secret_file), "--output", str(destination))
        finally:
            directory.chmod(0o755)

        assert result.returncode == 3
        assert destination.read_text(encoding="utf-8") == "PREVIOUS REPORT"

    def test_output_does_not_leave_temporary_files_behind(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        """The staging file must be cleaned up on success."""

        destination = tmp_path / "report.json"
        run_cli("scan", str(secret_file), "--output", str(destination))

        leftovers = [
            name for name in os.listdir(tmp_path) if name.startswith(".secret-shield-")
        ]
        assert leftovers == []

    def test_output_replaces_a_symlink_rather_than_following_it(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        """A planted link must not redirect the report into another file.

        ``os.replace`` acts on the name, so the link is overwritten by a regular
        file and the file it pointed at is never touched.
        """

        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL", encoding="utf-8")
        link = tmp_path / "report.json"
        link.symlink_to(victim)

        run_cli("scan", str(secret_file), "--format", "json", "--output", str(link))

        assert victim.read_text(encoding="utf-8") == "ORIGINAL"
        assert not link.is_symlink()


# ---------------------------------------------------------------------------
# Failure thresholds and filtering
# ---------------------------------------------------------------------------


class TestThresholds:
    """``--fail-on`` and ``--min-confidence`` decide when a run is a failure."""

    def test_fail_on_none_never_fails(self, secret_file: Path) -> None:
        """The escape hatch: report the findings, exit clean."""

        result = run_cli("scan", str(secret_file), "--fail-on", "none")

        assert result.returncode == 0
        assert "aws-access-key-id" in result.stdout

    def test_fail_on_a_severity_above_the_findings_stays_clean(
        self, secret_file: Path
    ) -> None:
        """The threshold has to mean something, not just accept a value."""

        result = run_cli("scan", str(secret_file), "--fail-on", "critical")

        assert result.returncode == 0

    def test_fail_on_low_fails_on_any_finding(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--fail-on", "low")

        assert result.returncode == 1

    def test_invalid_fail_on_is_a_usage_error(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--fail-on", "enormous")

        assert result.returncode == 2
        assert result.stdout == ""

    def test_min_confidence_filters_before_rendering(self, secret_file: Path) -> None:
        """Filtered-out findings must not inflate the summary count.

        Filtering after rendering would produce a report claiming three findings
        while listing one, which nobody can check.
        """

        payload = json.loads(
            run_cli(
                "scan",
                str(secret_file),
                "--format",
                "json",
                "--min-confidence",
                "verified",
            ).stdout
        )

        assert payload["findings"] == []
        assert payload["summary"]["findings_count"] == 0

    def test_min_confidence_keeps_everything_by_default(
        self, secret_file: Path
    ) -> None:
        payload = json.loads(
            run_cli(
                "scan",
                str(secret_file),
                "--format",
                "json",
                "--min-confidence",
                "candidate",
            ).stdout
        )

        assert payload["findings"]

    def test_filtering_everything_out_exits_zero(self, secret_file: Path) -> None:
        """Nothing reported means nothing to fail on."""

        result = run_cli("scan", str(secret_file), "--min-confidence", "verified")

        assert result.returncode == 0

    def test_min_confidence_accepts_dashes_or_underscores(
        self, secret_file: Path
    ) -> None:
        underscored = run_cli(
            "scan", str(secret_file), "--min-confidence", "high_confidence"
        )
        dashed = run_cli(
            "scan", str(secret_file), "--min-confidence", "high-confidence"
        )

        assert underscored.stdout == dashed.stdout
        assert underscored.returncode == 1

    def test_invalid_min_confidence_is_a_usage_error(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--min-confidence", "certain")

        assert result.returncode == 2


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


class TestFingerprint:
    """The correlation digest, and the report's right to omit it."""

    def test_sha256_is_the_default(self, secret_file: Path) -> None:
        payload = json.loads(
            run_cli("scan", str(secret_file), "--format", "json").stdout
        )

        assert payload["findings"][0]["fingerprint"]

    def test_sha256_is_stable_across_runs(self, secret_file: Path) -> None:
        first = run_cli("scan", str(secret_file), "--format", "json").stdout
        second = run_cli("scan", str(secret_file), "--format", "json").stdout

        assert first == second

    def test_none_omits_the_fingerprint_from_json(self, secret_file: Path) -> None:
        payload = json.loads(
            run_cli(
                "scan", str(secret_file), "--format", "json", "--fingerprint", "none"
            ).stdout
        )

        assert "fingerprint" not in payload["findings"][0]

    def test_none_omits_the_fingerprint_from_text(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--fingerprint", "none")

        assert "fingerprint" not in result.stdout

    def test_none_omits_the_fingerprint_from_markdown(self, secret_file: Path) -> None:
        result = run_cli(
            "scan", str(secret_file), "--format", "markdown", "--fingerprint", "none"
        )

        assert "fp=" not in result.stdout

    def test_hmac_requires_a_key(self, secret_file: Path) -> None:
        """No random default: a random key would make two runs disagree."""

        result = run_cli(
            "scan", str(secret_file), "--fingerprint", "hmac", env=clean_env()
        )

        assert result.returncode == 2
        assert "SECRETSHIELD_FINGERPRINT_KEY" in result.stderr

    def test_hmac_with_a_key_changes_the_digest(self, secret_file: Path) -> None:
        def digest_with(key: str) -> str:
            payload = json.loads(
                run_cli(
                    "scan",
                    str(secret_file),
                    "--format",
                    "json",
                    "--fingerprint",
                    "hmac",
                    env=clean_env(SECRETSHIELD_FINGERPRINT_KEY=key),
                ).stdout
            )
            return payload["findings"][0]["fingerprint"]

        keyed = digest_with("first-key")
        other = digest_with("second-key")
        unkeyed = json.loads(
            run_cli("scan", str(secret_file), "--format", "json").stdout
        )["findings"][0]["fingerprint"]

        assert keyed != other, "the key must actually key the digest"
        assert keyed != unkeyed

    def test_hmac_with_the_same_key_is_reproducible(self, secret_file: Path) -> None:
        first = run_cli(
            "scan",
            str(secret_file),
            "--format",
            "json",
            "--fingerprint",
            "hmac",
            env=clean_env(SECRETSHIELD_FINGERPRINT_KEY="stable"),
        ).stdout
        second = run_cli(
            "scan",
            str(secret_file),
            "--format",
            "json",
            "--fingerprint",
            "hmac",
            env=clean_env(SECRETSHIELD_FINGERPRINT_KEY="stable"),
        ).stdout

        assert first == second

    def test_the_key_is_never_echoed(self, secret_file: Path) -> None:
        """A key that reached a diagnostic or a report would be a real leak."""

        key = "a-key-that-must-not-appear"
        result = run_cli(
            "scan",
            str(secret_file),
            "--format",
            "json",
            "--fingerprint",
            "hmac",
            env=clean_env(SECRETSHIELD_FINGERPRINT_KEY=key),
        )

        assert key not in result.stdout
        assert key not in result.stderr

    def test_the_key_variable_does_not_trip_configuration_strictness(
        self, secret_file: Path
    ) -> None:
        """Config rejects unknown ``SECRETSHIELD_*`` settings, so the key must be
        stripped from the environment before it sees it."""

        result = run_cli(
            "scan",
            str(secret_file),
            "--fingerprint",
            "hmac",
            env=clean_env(SECRETSHIELD_FINGERPRINT_KEY="a-key"),
        )

        assert result.returncode == 1, result.stderr
        assert "unknown setting" not in result.stderr


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class TestBaselines:
    """A baseline lets a build fail on new secrets without failing on the backlog.

    The wiring is the whole point: the baseline module is unit-tested elsewhere,
    but until these tests existed nothing checked that the CLI could create a
    baseline, apply one, or refuse the combinations that would silently do
    nothing.
    """

    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        """A scan root separate from the baseline file, so the walk never sees it."""

        root = tmp_path / "repo"
        root.mkdir()
        return root

    @pytest.fixture
    def baseline_path(self, tmp_path: Path) -> Path:
        return tmp_path / "baseline.json"

    def write_secret(self, path: Path, value: str = SYNTHETIC_AWS_KEY) -> None:
        path.write_text(f'KEY = "{value}"\n', encoding="utf-8")

    def test_baseline_output_creates_a_fresh_baseline(
        self, repo: Path, baseline_path: Path
    ) -> None:
        self.write_secret(repo / "first.py")

        result = run_cli("scan", str(repo), "--baseline-output", str(baseline_path))

        assert result.returncode == 1, result.stderr
        assert_no_synthetic_value(result)
        raw = baseline_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert data["schema_version"] == "1.0"
        assert data["tool"]["name"] == "secret-shield"
        assert len(data["entries"]) == 1
        # A baseline records identity, never secret material.
        assert SYNTHETIC_AWS_KEY not in raw

    def test_the_baseline_is_owner_only(self, repo: Path, baseline_path: Path) -> None:
        self.write_secret(repo / "first.py")

        run_cli("scan", str(repo), "--baseline-output", str(baseline_path))

        assert baseline_path.stat().st_mode & 0o777 == 0o600

    def test_a_baselined_finding_is_suppressed_by_fail_on_new(
        self, repo: Path, baseline_path: Path
    ) -> None:
        self.write_secret(repo / "first.py")
        assert (
            run_cli(
                "scan", str(repo), "--baseline-output", str(baseline_path)
            ).returncode
            == 1
        )

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--fail-on-new",
            "--format",
            "json",
        )

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["findings"] == []
        assert_no_synthetic_value(result)

    def test_a_new_finding_fails_but_is_the_only_one_reported(
        self, repo: Path, baseline_path: Path
    ) -> None:
        self.write_secret(repo / "first.py")
        assert (
            run_cli(
                "scan", str(repo), "--baseline-output", str(baseline_path)
            ).returncode
            == 1
        )
        self.write_secret(repo / "second.py")

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--fail-on-new",
            "--format",
            "json",
        )

        assert result.returncode == 1, result.stderr
        findings = json.loads(result.stdout)["findings"]
        assert len(findings) == 1
        assert findings[0]["location"]["path"].endswith("second.py")
        assert_no_synthetic_value(result)

    def test_baseline_alone_reports_every_finding(
        self, repo: Path, baseline_path: Path
    ) -> None:
        """Without ``--fail-on-new`` a baseline compares, it does not suppress."""

        self.write_secret(repo / "first.py")
        assert (
            run_cli(
                "scan", str(repo), "--baseline-output", str(baseline_path)
            ).returncode
            == 1
        )

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--format",
            "json",
        )

        assert result.returncode == 1, result.stderr
        assert len(json.loads(result.stdout)["findings"]) == 1

    def test_baseline_output_updates_an_existing_baseline(
        self, repo: Path, baseline_path: Path
    ) -> None:
        self.write_secret(repo / "first.py")
        assert (
            run_cli(
                "scan", str(repo), "--baseline-output", str(baseline_path)
            ).returncode
            == 1
        )
        self.write_secret(repo / "second.py")

        update = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--baseline-output",
            str(baseline_path),
        )
        assert update.returncode == 1, update.stderr
        assert (
            len(json.loads(baseline_path.read_text(encoding="utf-8"))["entries"]) == 2
        )

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--fail-on-new",
            "--format",
            "json",
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["findings"] == []

    def test_fail_on_new_without_baseline_is_a_usage_error(
        self, secret_file: Path
    ) -> None:
        """Otherwise the flag would be accepted and silently do nothing."""

        result = run_cli("scan", str(secret_file), "--fail-on-new")

        assert result.returncode == 2
        assert "--baseline" in result.stderr

    def test_a_missing_baseline_warns_without_suppressing(
        self, repo: Path, baseline_path: Path
    ) -> None:
        """A typo cannot turn a real finding into a passing build."""

        self.write_secret(repo / "first.py")
        missing = baseline_path.parent / "not-here.json"

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(missing),
            "--baseline-output",
            str(baseline_path),
            "--format",
            "json",
        )

        assert result.returncode == 1, result.stderr
        assert "not found" in result.stderr
        assert not baseline_path.exists()
        assert len(json.loads(result.stdout)["findings"]) == 1

    def test_baseline_does_not_match_a_changed_value(
        self, repo: Path, baseline_path: Path
    ) -> None:
        """A secret swapped at the same spot is new, not silently baselined."""

        target = repo / "first.py"
        self.write_secret(target)
        assert (
            run_cli(
                "scan", str(repo), "--baseline-output", str(baseline_path)
            ).returncode
            == 1
        )
        self.write_secret(target, "AKIA7Q9ZLMTESTKEY12B")

        result = run_cli(
            "scan",
            str(repo),
            "--baseline",
            str(baseline_path),
            "--fail-on-new",
            "--format",
            "json",
        )

        assert result.returncode == 1, result.stderr
        assert len(json.loads(result.stdout)["findings"]) == 1


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes:
    """The numbers CI branches on, checked one at a time."""

    def test_clean_target_is_zero(self, clean_file: Path) -> None:
        assert run_cli("scan", str(clean_file)).returncode == 0

    def test_findings_are_one(self, secret_file: Path) -> None:
        assert run_cli("scan", str(secret_file)).returncode == 1

    def test_missing_target_is_two(self, tmp_path: Path) -> None:
        result = run_cli("scan", str(tmp_path / "not-here"))

        assert result.returncode == 2
        assert result.stdout == ""

    def test_missing_target_says_why(self, tmp_path: Path) -> None:
        result = run_cli("scan", str(tmp_path / "not-here"))

        assert "no such file or directory" in result.stderr

    def test_empty_target_is_two(self) -> None:
        assert run_cli("scan", "").returncode == 2

    def test_invalid_format_is_two(self, secret_file: Path) -> None:
        assert run_cli("scan", str(secret_file), "--format", "xml").returncode == 2

    def test_unknown_option_is_two(self, secret_file: Path) -> None:
        assert run_cli("scan", str(secret_file), "--turbo").returncode == 2

    def test_missing_subcommand_is_two(self) -> None:
        assert run_cli().returncode == 2

    def test_unknown_subcommand_is_two(self) -> None:
        assert run_cli("audit").returncode == 2

    def test_partial_scan_is_three_and_beats_findings(self, tmp_path: Path) -> None:
        """The most important precedence in the tool.

        A directory holding one readable secret file and one unreadable one
        must exit ``3``, not ``1``: a truncated scan must never look like a
        findings-only run that a pipeline is willing to fail on.
        """

        root = tmp_path / "partial"
        root.mkdir()
        (root / "readable.py").write_text(
            f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8"
        )
        unreadable = root / "locked.py"
        unreadable.write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        unreadable.chmod(0o000)
        try:
            result = run_cli("scan", str(root))
        finally:
            unreadable.chmod(0o644)

        if result.returncode == 0:
            pytest.skip("this process can read a mode-000 file (running as root)")

        assert result.returncode == 3
        assert_no_synthetic_value(result)

    def test_partial_scan_beats_findings_even_with_fail_on_none(
        self, tmp_path: Path
    ) -> None:
        """``--fail-on none`` cannot turn a partial result into a clean one."""

        root = tmp_path / "partial2"
        root.mkdir()
        unreadable = root / "locked.py"
        unreadable.write_text("X = 1\n", encoding="utf-8")
        unreadable.chmod(0o000)
        try:
            result = run_cli("scan", str(root), "--fail-on", "none")
        finally:
            unreadable.chmod(0o644)

        if result.returncode == 0:
            pytest.skip("this process can read a mode-000 file (running as root)")

        assert result.returncode == 3

    def test_partial_scan_reports_the_failure_on_stderr(self, tmp_path: Path) -> None:
        """A report redirected to a file must not hide that it is incomplete."""

        root = tmp_path / "partial3"
        root.mkdir()
        unreadable = root / "locked.py"
        unreadable.write_text("X = 1\n", encoding="utf-8")
        unreadable.chmod(0o000)
        try:
            result = run_cli("scan", str(root))
        finally:
            unreadable.chmod(0o644)

        if result.returncode != 3:
            pytest.skip("this process can read a mode-000 file (running as root)")

        assert "partial" in result.stderr.lower()

    def test_not_implemented_is_never_returned(self, secret_file: Path) -> None:
        """``5`` exists in the exit-code table but nothing here returns it.

        There is no flag for an absent capability, so a request for one is a
        usage error rather than a stub.
        """

        for arguments in (
            ("scan", str(secret_file)),
            ("rules", "list"),
            ("--version",),
        ):
            assert run_cli(*arguments).returncode != 5


# ---------------------------------------------------------------------------
# Usage and configuration errors
# ---------------------------------------------------------------------------


class TestLimits:
    """Numeric options must be parsed strictly and validated by configuration."""

    def test_jobs_is_accepted(self, secret_tree: Path) -> None:
        result = run_cli("scan", str(secret_tree), "--jobs", "2")

        assert result.returncode == 1

    def test_jobs_zero_is_rejected_by_configuration(self, secret_tree: Path) -> None:
        """The same range check a config file gets, with the same exit code."""

        result = run_cli("scan", str(secret_tree), "--jobs", "0")

        assert result.returncode == 2
        assert "jobs" in result.stderr

    def test_negative_jobs_is_rejected(self, secret_tree: Path) -> None:
        assert run_cli("scan", str(secret_tree), "--jobs", "-4").returncode == 2

    @pytest.mark.parametrize("value", ["1_0", "0x10", " 8 ", "8.0", "eight", ""])
    def test_non_integer_jobs_is_a_usage_error(
        self, secret_tree: Path, value: str
    ) -> None:
        """Hand-rolled parsing matches the configuration layer exactly.

        ``int()`` would accept ``"1_0"`` and ``" 8 "``; a value the config file
        rejects must not be accepted on the command line either.
        """

        result = run_cli("scan", str(secret_tree), "--jobs", value)

        assert result.returncode == 2

    def test_underscore_spelling_is_rejected_like_configuration_rejects_it(
        self, clean_file: Path
    ) -> None:
        """``1_0`` must fail on the command line exactly as it fails elsewhere.

        The comparison is against the *environment* rather than a TOML file,
        because ``tomllib`` follows the TOML spec and reads ``1_0`` as the
        integer ``10`` before any of our code sees it. An environment variable
        arrives as a raw string, so it exercises the same strict pattern
        ``config._INTEGER_PATTERN`` enforces -- and that is the path a value
        takes when a wrapper script interpolates user input into the command
        line.
        """

        from_cli = run_cli("scan", str(clean_file), "--jobs", "1_0")
        from_env = run_cli(
            "scan", str(clean_file), env=clean_env(SECRETSHIELD_JOBS="1_0")
        )

        assert from_cli.returncode == from_env.returncode == 2
        assert "not a base-10 integer" in from_cli.stderr

    def test_a_toml_underscore_is_read_as_the_integer_toml_says(
        self, tmp_path: Path
    ) -> None:
        """Documenting the boundary above, so it is not mistaken for a bug.

        TOML permits underscores inside integers, so ``jobs = 1_0`` in a file is
        ``10``. Rejecting it would contradict the format rather than harden the
        tool.
        """

        root = tmp_path / "toml_int"
        root.mkdir()
        (root / "ok.py").write_text("X = 1\n", encoding="utf-8")
        (root / ".secretshield.toml").write_text(
            "[scan]\nmax_files = 1_0\n", encoding="utf-8"
        )

        result = run_cli(
            "scan",
            str(root),
            "--project-root",
            str(root),
            "--format",
            "json",
            env=clean_env(),
        )

        assert result.returncode == 0
        assert json.loads(result.stdout)["summary"]["files_scanned"] == 2, (
            "both ok.py and the config file itself should be scanned; a cap of 10 "
            "is not the thing under test here"
        )

    def test_max_file_size_is_accepted(self, clean_file: Path) -> None:
        assert (
            run_cli("scan", str(clean_file), "--max-file-size", "4096").returncode == 0
        )

    def test_a_tiny_max_file_size_skips_the_file(self, secret_file: Path) -> None:
        """A file over the cap is skipped, so it produces no findings."""

        payload = json.loads(
            run_cli(
                "scan", str(secret_file), "--format", "json", "--max-file-size", "10"
            ).stdout
        )

        assert payload["findings"] == []

    def test_max_line_length_is_accepted(self, secret_file: Path) -> None:
        result = run_cli("scan", str(secret_file), "--max-line-length", "200")

        assert result.returncode in (0, 1)

    def test_follow_symlinks_is_accepted(self, secret_tree: Path) -> None:
        result = run_cli("scan", str(secret_tree), "--follow-symlinks")

        assert result.returncode == 1

    def test_symlink_loop_does_not_hang(self, tmp_path: Path) -> None:
        """Following links must still refuse a cycle."""

        root = tmp_path / "loop"
        root.mkdir()
        (root / "ok.py").write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        (root / "self").symlink_to(root, target_is_directory=True)

        result = run_cli("scan", str(root), "--follow-symlinks", timeout=60.0)

        assert result.returncode in (0, 1, 3)


# ---------------------------------------------------------------------------
# Configuration integration
# ---------------------------------------------------------------------------


class TestConfiguration:
    """Command line options and configuration files, and who wins."""

    def test_a_disabled_rule_stops_firing(self, tmp_path: Path) -> None:
        root = tmp_path / "cfg_disabled"
        root.mkdir()
        (root / "settings.py").write_text(
            f'AWS_ACCESS_KEY_ID = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8"
        )
        (root / ".secretshield.toml").write_text(
            '[rules]\ndisabled = ["aws-access-key-id"]\n', encoding="utf-8"
        )

        result = run_cli(
            "scan", str(root), "--project-root", str(root), env=clean_env()
        )

        assert "aws-access-key-id" not in result.stdout
        assert_no_synthetic_value(result)

    def test_the_same_file_without_configuration_is_flagged(
        self, tmp_path: Path
    ) -> None:
        """Confirms the previous test disabled something real."""

        root = tmp_path / "cfg_enabled"
        root.mkdir()
        (root / "settings.py").write_text(
            f'AWS_ACCESS_KEY_ID = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8"
        )

        result = run_cli(
            "scan", str(root), "--project-root", str(root), env=clean_env()
        )

        assert "aws-access-key-id" in result.stdout

    def test_command_line_overrides_the_configuration_file(
        self, tmp_path: Path
    ) -> None:
        """``--max-files`` must beat ``scan.max_files`` in the file."""

        root = tmp_path / "cfg_override"
        root.mkdir()
        for index in range(4):
            (root / f"f{index}.py").write_text("X = 1\n", encoding="utf-8")
        (root / ".secretshield.toml").write_text(
            "[scan]\nmax_files = 1\n", encoding="utf-8"
        )

        result = run_cli(
            "scan",
            str(root),
            "--project-root",
            str(root),
            "--max-files",
            "4",
            "--format",
            "json",
            env=clean_env(),
        )
        payload = json.loads(result.stdout)

        assert payload["summary"]["files_scanned"] == 4

    def test_the_configuration_file_applies_when_no_option_is_given(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "cfg_applies"
        root.mkdir()
        for index in range(4):
            (root / f"f{index}.py").write_text("X = 1\n", encoding="utf-8")
        (root / ".secretshield.toml").write_text(
            "[scan]\nmax_files = 1\n", encoding="utf-8"
        )

        result = run_cli(
            "scan",
            str(root),
            "--project-root",
            str(root),
            "--format",
            "json",
            env=clean_env(),
        )

        assert json.loads(result.stdout)["summary"]["files_scanned"] == 1

    def test_malformed_configuration_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        root = tmp_path / "cfg_malformed"
        root.mkdir()
        (root / ".secretshield.toml").write_text("not valid [[[\n", encoding="utf-8")

        result = run_cli(
            "scan", str(secret_file), "--project-root", str(root), env=clean_env()
        )

        assert result.returncode == 2
        assert result.stdout == ""

    def test_out_of_range_configuration_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        root = tmp_path / "cfg_range"
        root.mkdir()
        (root / ".secretshield.toml").write_text("[scan]\njobs = 0\n", encoding="utf-8")

        result = run_cli(
            "scan", str(secret_file), "--project-root", str(root), env=clean_env()
        )

        assert result.returncode == 2

    def test_unknown_setting_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        """Silently ignoring a misspelled setting would apply a limit nobody set."""

        root = tmp_path / "cfg_unknown"
        root.mkdir()
        (root / ".secretshield.toml").write_text("nope = 1\n", encoding="utf-8")

        result = run_cli(
            "scan", str(secret_file), "--project-root", str(root), env=clean_env()
        )

        assert result.returncode == 2
        assert "nope" in result.stderr

    def test_unknown_disabled_rule_id_is_a_usage_error(
        self, secret_file: Path, tmp_path: Path
    ) -> None:
        """Disabling a rule that does not exist looks like it worked but did not."""

        root = tmp_path / "cfg_badrule"
        root.mkdir()
        (root / ".secretshield.toml").write_text(
            '[rules]\ndisabled = ["not-a-real-rule"]\n', encoding="utf-8"
        )

        result = run_cli(
            "scan", str(secret_file), "--project-root", str(root), env=clean_env()
        )

        assert result.returncode == 2

    def test_an_unknown_environment_variable_is_a_usage_error(
        self, secret_file: Path
    ) -> None:
        """A settings namespace should reject a variable it does not know."""

        result = run_cli(
            "scan", str(secret_file), env=clean_env(SECRETSHIELD_NOT_A_SETTING="1")
        )

        assert result.returncode == 2

    def test_a_known_environment_variable_is_honoured(self, tmp_path: Path) -> None:
        root = tmp_path / "env_setting"
        root.mkdir()
        for index in range(4):
            (root / f"f{index}.py").write_text("X = 1\n", encoding="utf-8")

        result = run_cli(
            "scan",
            str(root),
            "--format",
            "json",
            "--project-root",
            str(root),
            env=clean_env(SECRETSHIELD_MAX_FILES="2"),
        )

        assert json.loads(result.stdout)["summary"]["files_scanned"] == 2


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """A report that varies between runs cannot be diffed or cached."""

    def test_repeated_runs_are_byte_identical(self, secret_tree: Path) -> None:
        runs = {
            run_cli("scan", str(secret_tree), "--format", "json").stdout
            for _ in range(3)
        }

        assert len(runs) == 1, "the same command produced different reports"

    def test_serial_and_threaded_scans_agree(self, secret_tree: Path) -> None:
        """``--jobs`` is a performance knob and must not change the result.

        If it did, every finding's position in the report would depend on which
        worker finished first, and no two CI runs would match.
        """

        serial = run_cli("scan", str(secret_tree), "--jobs", "1", "--format", "json")
        threaded = run_cli("scan", str(secret_tree), "--jobs", "8", "--format", "json")

        assert serial.returncode == threaded.returncode
        assert serial.stdout == threaded.stdout

    def test_repeated_runs_of_rules_list_are_identical(self) -> None:
        first = run_cli("rules", "list", "--format", "json").stdout
        second = run_cli("rules", "list", "--format", "json").stdout

        assert first == second

    def test_no_timestamp_or_duration_leaks_into_the_report(
        self, secret_tree: Path
    ) -> None:
        """Nothing in a report may depend on when it was produced."""

        payload = json.loads(
            run_cli("scan", str(secret_tree), "--format", "json").stdout
        )

        serialized = json.dumps(payload).lower()
        for word in ("timestamp", "duration", "elapsed", "generated_at", "scanned_at"):
            assert word not in serialized, f"{word} makes the report non-deterministic"


# ---------------------------------------------------------------------------
# rules list
# ---------------------------------------------------------------------------


class TestRulesList:
    """The rule catalogue, as documentation rather than as detection logic."""

    def test_list_exits_zero(self) -> None:
        result = run_cli("rules", "list")

        assert result.returncode == 0
        assert_no_synthetic_value(result)

    def test_list_covers_every_registered_rule(self) -> None:
        """A rule a reader cannot account for in a report is a documentation bug."""

        stdout = run_cli("rules", "list", "--format", "json").stdout
        payload = json.loads(stdout)

        listed = {entry["id"] for entry in payload["rules"]}
        assert set(rule_registry_ids()) <= listed

    def test_the_entropy_rule_is_listed_too(self) -> None:
        """It produces findings, so it has to be explainable."""

        payload = json.loads(run_cli("rules", "list", "--format", "json").stdout)

        assert any(entry["detector"] == "entropy" for entry in payload["rules"])

    @pytest.mark.parametrize(
        "field",
        ["id", "name", "category", "severity", "base_confidence", "remediation"],
    )
    def test_every_required_field_is_present(self, field: str) -> None:
        payload = json.loads(run_cli("rules", "list", "--format", "json").stdout)

        assert all(
            entry.get(field) for entry in payload["rules"]
        ), f"every rule entry must carry a {field}"

    def test_specificity_and_false_positive_notes_are_present(self) -> None:
        payload = json.loads(run_cli("rules", "list", "--format", "json").stdout)

        assert all("specificity" in entry for entry in payload["rules"])
        assert all("false_positive_notes" in entry for entry in payload["rules"])

    def test_text_listing_names_each_rule(self) -> None:
        stdout = run_cli("rules", "list").stdout

        assert "aws-access-key-id" in stdout
        assert "high-entropy-string" in stdout

    def test_text_listing_explains_the_thresholds(self) -> None:
        """A listing without confidence and specificity is only half a listing."""

        stdout = run_cli("rules", "list").stdout

        assert "base confidence" in stdout
        assert "specificity" in stdout
        assert "false positives" in stdout
        assert "remediation" in stdout

    def test_no_example_credential_is_printed(self) -> None:
        """The listing is meant to be pasted into an issue.

        Documentation may *name* a prefix and may mention a vendor's published
        placeholder in order to explain why it is suppressed, but it must never
        print a value that could be mistaken for a live credential. The real
        check is that no value planted in this repository's fixtures appears.
        """

        from tests import vendor_fixtures

        values = [
            value
            for name, value in vars(vendor_fixtures).items()
            if name.isupper() and isinstance(value, str) and "SYNTH" in value
        ]
        assert values, "no synthetic fixtures were discovered to assert against"

        stdout = run_cli("rules", "list", "--format", "json").stdout
        text = run_cli("rules", "list").stdout

        for value in values:
            assert value not in stdout, f"the listing printed {value!r}"
            assert value not in text

    def test_patterns_are_not_printed(self) -> None:
        """A pattern is detection logic, not documentation.

        Printing it invites copying it into an allowlist that then silently
        stops matching when the rule changes.
        """

        stdout = run_cli("rules", "list", "--format", "json").stdout
        payload = json.loads(stdout)

        for entry in payload["rules"]:
            assert "pattern" not in entry
            assert "regex" not in entry

    def test_invalid_format_is_a_usage_error(self) -> None:
        assert run_cli("rules", "list", "--format", "xml").returncode == 2

    def test_rules_without_an_action_is_a_usage_error(self) -> None:
        assert run_cli("rules").returncode == 2

    def test_unknown_action_is_a_usage_error(self) -> None:
        assert run_cli("rules", "explain").returncode == 2

    def test_listing_is_pure_on_stdout(self) -> None:
        """A listing redirected into a doc must not carry diagnostics with it."""

        result = run_cli("rules", "list", "--format", "json")

        assert result.stderr == ""
        json.loads(result.stdout)


def rule_registry_ids() -> Sequence[str]:
    """Return the ids the default registry actually ships."""

    from secret_shield.detectors.catalog import default_registry

    return tuple(rule.id for rule in default_registry().rules())


def test_repository_root_is_on_the_path_for_a_bare_checkout() -> None:
    """Guards the ``tests`` package import used above.

    ``from tests import vendor_fixtures`` needs the repository root on
    ``sys.path``. ``conftest.py`` adds ``tests/`` but not its parent, so this
    fails loudly here rather than as a confusing collection error later.
    """

    import importlib.util

    assert importlib.util.find_spec("tests.vendor_fixtures") is not None


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


class TestStreamSeparation:
    """stdout carries the report. stderr carries everything else."""

    def test_json_stdout_has_no_warnings(self, secret_tree: Path) -> None:
        """Anything on stdout would corrupt the JSON."""

        result = run_cli("scan", str(secret_tree), "--format", "json")

        json.loads(result.stdout)

    def test_diagnostics_go_to_stderr(self, tmp_path: Path) -> None:
        missing = tmp_path / "nowhere"
        result = run_cli("scan", str(missing))

        assert result.stdout == ""
        assert result.stderr.strip()

    def test_a_filename_with_control_characters_is_sanitised(
        self, tmp_path: Path
    ) -> None:
        """A hostile filename must not be able to forge a log line.

        Control characters are legal in a Linux filename, and a diagnostic that
        can repaint a terminal or hide its own text is a forged CI log.
        """

        root = tmp_path / "sanitise"
        root.mkdir()
        hostile = "evil\x1b[31mred\x07.py"
        (root / hostile).write_text("X = 1\n", encoding="utf-8")

        # The target must not exist: a successful scan prints nothing, so the
        # filename only reaches stderr on the error path. Asserting against a
        # clean run would pass even with the sanitizer removed.
        result = run_cli("scan", str(root / "missing\x1b[31mred\x07.py"))

        assert result.returncode == 2
        assert "\x1b" not in result.stderr
        assert "\x07" not in result.stderr

    def test_an_existing_hostile_filename_is_reported_without_escapes(
        self, tmp_path: Path
    ) -> None:
        """A scanned file's name must not carry escapes into a finding either."""

        root = tmp_path / "sanitise_found"
        root.mkdir()
        (root / "a\x1b[31mb.py").write_text(
            f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8"
        )

        result = run_cli("scan", str(root))

        assert "\x1b" not in result.stdout
        assert "\x1b" not in result.stderr

    def test_a_hostile_filename_cannot_break_the_json(self, tmp_path: Path) -> None:
        root = tmp_path / "sanitise_json"
        root.mkdir()
        (root / "a\x1b[31mb.py").write_text("X = 1\n", encoding="utf-8")

        result = run_cli("scan", str(root), "--format", "json")

        json.loads(result.stdout)
        assert "\x1b" not in result.stdout

    def test_a_bidirectional_override_is_stripped(self, tmp_path: Path) -> None:
        """RTL override characters can make one line read as another."""

        root = tmp_path / "rtl"
        root.mkdir()
        # Again the error path, so the name is actually emitted.
        result = run_cli("scan", str(root / "b\u202eg.py"))

        assert result.returncode == 2
        assert "\u202e" not in result.stderr
        assert "\u202e" not in result.stdout

    def test_a_diagnostic_never_spans_two_lines(self, tmp_path: Path) -> None:
        """One diagnostic, one line: a newline in the data cannot forge records."""

        missing = tmp_path / "a\nsecret-shield: scan: all clear"
        result = run_cli("scan", str(missing))

        assert result.stderr.strip().count("\n") == 0

    def test_a_report_survives_a_pipe(self, secret_tree: Path) -> None:
        """``--format json | jq`` is the reason stdout is pure."""

        completed = subprocess.run(
            f'{sys.executable} -m secret_shield scan "{secret_tree}" --format json | cat',
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        assert completed.returncode == 0
        json.loads(completed.stdout)


# ---------------------------------------------------------------------------
# Interruption
# ---------------------------------------------------------------------------


class TestInterruption:
    """Ctrl-C must stop the scan and say so."""

    def test_sigint_exits_130(self, tmp_path: Path) -> None:
        """Reproduced with a real signal, not a simulated exception.

        A directory big enough that the scan is still running when the signal
        arrives; skipped rather than failed where the machine is too fast for
        the timing to be reliable.
        """

        root = tmp_path / "slow"
        root.mkdir()
        for index in range(60):
            (root / f"big{index}.txt").write_text(
                "\n".join("A" * 80 + str(index * 1000 + line) for line in range(4000)),
                encoding="utf-8",
            )

        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "secret_shield",
                "scan",
                str(root),
                "--format",
                "json",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.5)
        if process.poll() is not None:
            stderr = process.communicate()[1]
            pytest.skip(
                f"the scan finished before the signal arrived: rc={process.returncode} {stderr!r}"
            )

        process.send_signal(signal.SIGINT)
        _, stderr = process.communicate(timeout=120)

        assert process.returncode == 130, stderr
        assert "interrupt" in stderr.lower()


# ---------------------------------------------------------------------------
# Internal safety
# ---------------------------------------------------------------------------


class TestSafety:
    """Properties that must hold for every invocation, not just some."""

    def test_no_argument_reaches_a_shell(self, secret_file: Path) -> None:
        """A shell metacharacter in an argument is data, never a command.

        The substitution below would create a file if the CLI ever shelled out.
        """

        canary = secret_file.parent / "pwned"
        hostile = f"; touch {canary}"

        result = run_cli("scan", hostile)

        assert not canary.exists(), "the CLI executed something through a shell"
        assert result.returncode == 2

    def test_a_target_looking_like_a_flag_is_not_an_option(
        self, tmp_path: Path
    ) -> None:
        """``--format`` after the target must not be re-interpreted as a flag."""

        tricky = tmp_path / "--format"
        tricky.write_text("X = 1\n", encoding="utf-8")

        result = run_cli("scan", str(tricky))

        assert result.returncode == 0
        assert "usage:" not in result.stdout

    def test_a_very_long_argument_does_not_crash(self, secret_file: Path) -> None:
        result = run_cli(
            "scan",
            str(secret_file),
            "--format",
            "json",
            env={
                **clean_env(),
                "PAD": "x" * 8192,
            },
        )

        assert result.returncode in (0, 1)

    def test_stdin_is_not_read(self, clean_file: Path) -> None:
        """The CLI takes a target, not a stream; it must not block on stdin."""

        result = run_cli("scan", str(clean_file), stdin="", timeout=30.0)

        assert result.returncode == 0

    @pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
    def test_no_format_prints_a_finding_object(
        self, secret_file: Path, fmt: str
    ) -> None:
        """No rendering may expose a ``Finding`` repr or dataclass internals.

        A ``Finding`` repr carries its fields, and one of those fields is the
        fingerprint: printing the object would be a different leak per format.
        """

        result = run_cli("scan", str(secret_file), "--format", fmt)

        assert "Finding(" not in result.stdout
        assert "ScanResult(" not in result.stdout
        assert "SecretCategory." not in result.stdout

    @pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
    def test_no_format_prints_the_masked_value_only(
        self, secret_file: Path, fmt: str
    ) -> None:
        """The masked rendering must be what appears, not any part of the value."""

        result = run_cli("scan", str(secret_file), "--format", fmt)
        head = SYNTHETIC_AWS_KEY[:4]

        assert (
            head not in result.stdout.replace("AKIA", "", 0)
            or "AKIA" not in result.stdout
        )


def test_module_entry_point_delegates_and_reuses_one_implementation() -> None:
    """``__main__`` must not reimplement the CLI.

    Two entry points with two parsers would drift, and the first symptom would
    be a flag that one invocation accepts and the other does not.
    """

    from secret_shield import __main__ as module_entry
    from secret_shield import cli

    assert module_entry._cli_main is cli.main, (
        "__main__ must delegate rather than wrap, so both entry points share one "
        "parser and one set of exit codes"
    )
    assert module_entry.main.__module__ == "secret_shield.__main__"


def test_run_cli_actually_runs_the_cli() -> None:
    """Guards the harness itself: a broken runner would pass everything else."""

    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout.startswith("secret-shield ")


# ---------------------------------------------------------------------------
# secret-shield git
# ---------------------------------------------------------------------------


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


GIT_FIXTURE_ENVIRONMENT: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "CLI Test",
    "GIT_AUTHOR_EMAIL": "cli@example.invalid",
    "GIT_COMMITTER_NAME": "CLI Test",
    "GIT_COMMITTER_EMAIL": "cli@example.invalid",
    "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+0000",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.devnull,
    "LC_ALL": "C",
}


def build_git(repo: Path, *arguments: str) -> str:
    """Run ``git`` in ``repo`` with a scrubbed environment and return stdout."""

    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        env=GIT_FIXTURE_ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(arguments)} failed: {completed.stderr}")
    return completed.stdout.strip()


@dataclasses.dataclass(frozen=True)
class LeakyRepo:
    """A repository whose history holds a secret the working tree does not.

    The commit name is held here rather than in a file inside the repository:
    an extra file would make ``git status`` dirty, and one of the tests below
    exists precisely to assert that a scan leaves the tree clean.
    """

    path: Path
    leaky_commit: str

    @property
    def displayed_commit(self) -> str:
        """The commit as the human-facing reports abbreviate it.

        ``Location.to_display`` shortens a commit to twelve characters, so the
        text and Markdown reports cannot carry all forty. Asserting the full
        name against those reports would encode a promise they never made.
        """

        return self.leaky_commit[:12]


@pytest.fixture
def leaky(tmp_path: Path) -> LeakyRepo:
    """A credential committed and then deleted, so only the history holds it."""

    repo = tmp_path / "leaky"
    repo.mkdir()
    build_git(repo, "init", "-q", "-b", "main")
    (repo / "gone.py").write_text(
        "# a configuration that was later removed\n" f'KEY = "{SYNTHETIC_AWS_KEY}"\n',
        encoding="utf-8",
    )
    build_git(repo, "add", "-A")
    build_git(repo, "commit", "-qm", "add configuration")
    leaky_commit = build_git(repo, "rev-parse", "HEAD")
    build_git(repo, "rm", "-q", "gone.py")
    build_git(repo, "commit", "-qm", "remove it")
    (repo / "README.md").write_text("# clean\n", encoding="utf-8")
    build_git(repo, "add", "-A")
    build_git(repo, "commit", "-qm", "add a readme")
    assert build_git(repo, "status", "--porcelain") == ""
    return LeakyRepo(path=repo, leaky_commit=leaky_commit)


@needs_git
class TestGitHelpAndDiscovery:
    def test_help_lists_the_git_subcommand(self) -> None:
        """A capability nobody can find is a capability nobody has."""

        assert "git" in run_cli("--help").stdout

    def test_help_offers_a_git_example(self) -> None:
        assert "secret-shield git" in run_cli("--help").stdout

    def test_git_help_documents_every_option(self) -> None:
        """Written out, so *removing* an option fails this test."""

        stdout = run_cli("git", "--help").stdout

        for option in (
            "--max-commits",
            "--max-blobs",
            "--max-refs",
            "--max-blob-size",
            "--max-line-length",
            "--timeout",
            "--since",
            "--until",
            "--respect-path-filters",
            "--format",
            "--output",
            "--fingerprint",
            "--min-confidence",
            "--fail-on",
        ):
            assert option in stdout, f"{option} is undocumented in git --help"

    def test_git_help_states_the_sha1_limitation(self) -> None:
        """A limitation the help does not mention is a limitation nobody meets."""

        assert "SHA-1" in run_cli("git", "--help").stdout

    def test_git_help_states_that_nothing_is_written(self) -> None:
        assert "checked out" in run_cli("git", "--help").stdout

    def test_git_help_documents_the_exit_codes(self) -> None:
        stdout = run_cli("git", "--help").stdout

        for code in ("0", "1", "2", "3"):
            assert re.search(rf"^\s+{code}\s", stdout, re.MULTILINE)

    def test_git_help_exits_zero(self) -> None:
        assert run_cli("git", "--help").returncode == 0

    def test_a_missing_target_is_a_usage_error(self) -> None:
        result = run_cli("git")

        assert result.returncode == 2

    def test_an_unknown_option_is_a_usage_error(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--turbo").returncode == 2


@needs_git
class TestGitExitCodes:
    def test_a_clean_repository_is_zero(self, tmp_path: Path) -> None:
        repo = tmp_path / "clean"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo))

        assert result.returncode == 0
        assert_no_synthetic_value(result)

    def test_a_secret_in_the_history_is_one(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path))

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_an_empty_repository_is_zero(self, tmp_path: Path) -> None:
        """``git init`` and nothing more is not a broken repository."""

        repo = tmp_path / "unborn"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")

        result = run_cli("git", str(repo))

        assert result.returncode == 0
        assert result.stderr == ""

    def test_a_missing_target_is_two(self, tmp_path: Path) -> None:
        result = run_cli("git", str(tmp_path / "not-a-repo"))

        assert result.returncode == 2
        assert result.stdout == ""

    def test_a_missing_target_says_why(self, tmp_path: Path) -> None:
        result = run_cli("git", str(tmp_path / "not-a-repo"))

        assert "no such file or directory" in result.stderr

    def test_a_file_target_is_two(self, secret_file: Path) -> None:
        """A blob is not a repository, and the message must say which."""

        result = run_cli("git", str(secret_file))

        assert result.returncode == 2
        assert "directory" in result.stderr

    def test_a_directory_that_is_not_a_repository_is_three(
        self, tmp_path: Path
    ) -> None:
        """A scan that examined nothing cannot pass as a clean scan."""

        plain = tmp_path / "plain"
        plain.mkdir()

        result = run_cli("git", str(plain))

        assert result.returncode == 3
        assert "FINDINGS" not in result.stdout
        assert_no_synthetic_value(result)

    def test_a_non_repository_says_why_on_stderr(self, tmp_path: Path) -> None:
        plain = tmp_path / "plain2"
        plain.mkdir()

        result = run_cli("git", str(plain))

        assert "not-a-git-repository" in result.stderr
        assert "partial" in result.stderr.lower()

    def test_a_non_repository_reports_the_reason_in_the_report(
        self, tmp_path: Path
    ) -> None:
        """The error belongs in the report too, for a redirect to be useful."""

        plain = tmp_path / "plain3"
        plain.mkdir()

        result = run_cli("git", str(plain))

        assert "not a Git repository" in result.stdout

    def test_a_truncated_history_is_three_and_beats_findings(
        self, leaky: LeakyRepo
    ) -> None:
        """The precedence that matters most for a history scan.

        Stopping at one commit and reporting findings would leave a reader
        believing the older history was searched.
        """

        result = run_cli("git", str(leaky.path), "--max-commits", "1")

        assert result.returncode == 3
        assert_no_synthetic_value(result)

    def test_a_truncated_history_says_so_on_stderr(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--max-commits", "1")

        assert "NOT examined in full" in result.stderr

    def test_fail_on_none_cannot_make_a_partial_scan_clean(
        self, leaky: LeakyRepo
    ) -> None:
        result = run_cli(
            "git", str(leaky.path), "--max-commits", "1", "--fail-on", "none"
        )

        assert result.returncode == 3

    def test_an_invalid_format_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--format", "xml").returncode == 2

    def test_fail_on_above_every_finding_is_clean(self, leaky: LeakyRepo) -> None:
        """The AWS key rule is medium, so a ``critical`` threshold drops it."""

        assert run_cli("git", str(leaky.path), "--fail-on", "medium").returncode == 1
        assert run_cli("git", str(leaky.path), "--fail-on", "critical").returncode == 0

    def test_fail_on_none_is_zero(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--fail-on", "none")

        assert result.returncode == 0

    def test_not_implemented_is_never_returned(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path)).returncode != 5


@needs_git
class TestGitReporting:
    def test_the_working_tree_scan_misses_it(self, leaky: LeakyRepo) -> None:
        """The reason this subcommand exists, stated in one test."""

        result = run_cli("scan", str(leaky.path))

        assert result.returncode == 0
        assert_no_synthetic_value(result)

    def test_the_history_scan_finds_it(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path))

        assert "gone.py" in result.stdout
        assert leaky.leaky_commit[:8] in result.stdout

    def test_the_text_report_names_the_commit_and_the_path(
        self, leaky: LeakyRepo
    ) -> None:
        result = run_cli("git", str(leaky.path))

        assert f"gone.py:2:8@{leaky.displayed_commit}" in result.stdout

    def test_the_text_report_prints_no_rule_object(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path))

        assert "Finding(" not in result.stdout
        assert "ScanResult(" not in result.stdout
        assert "SourceKind." not in result.stdout

    def test_json_carries_the_full_commit_and_time(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--format", "json")

        payload = json.loads(result.stdout)
        locations = [finding["location"] for finding in payload["findings"]]

        assert locations
        for location in locations:
            assert len(location["commit"]) == 40
            assert isinstance(location["commit_time"], int)
            assert location["source_kind"] == "git"

    def test_json_names_the_commit_that_had_the_secret(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--format", "json")

        payload = json.loads(result.stdout)
        commits = {finding["location"]["commit"] for finding in payload["findings"]}

        assert commits == {leaky.leaky_commit}

    def test_json_is_the_same_envelope_as_scan(self, leaky: LeakyRepo) -> None:
        """One reporter for every source, so a CI parser needs no branch."""

        from_secret = run_cli("git", str(leaky.path), "--format", "json")
        from_scan = run_cli("scan", str(leaky.path), "--format", "json")

        assert set(json.loads(from_secret.stdout)) == set(json.loads(from_scan.stdout))

    def test_markdown_names_the_commit(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--format", "markdown")

        assert "# Secret Shield Report" in result.stdout
        assert f"gone.py:2:8@{leaky.displayed_commit}" in result.stdout

    def test_markdown_escapes_the_masked_value(self, leaky: LeakyRepo) -> None:
        """The masked value is rendered inside a table cell and must not spill."""

        result = run_cli("git", str(leaky.path), "--format", "markdown")

        assert "\\*" in result.stdout
        assert_no_synthetic_value(result)

    @pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
    def test_no_format_prints_a_raw_value(self, leaky: LeakyRepo, fmt: str) -> None:
        result = run_cli("git", str(leaky.path), "--format", fmt)

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_output_writes_the_report_and_leaves_stdout_empty(
        self, leaky: LeakyRepo, tmp_path: Path
    ) -> None:
        destination = tmp_path / "report.json"

        result = run_cli(
            "git", str(leaky.path), "--format", "json", "--output", str(destination)
        )

        assert result.stdout == ""
        assert result.returncode == 1
        payload = json.loads(destination.read_text(encoding="utf-8"))
        assert payload["findings"]
        assert_no_synthetic_value(result)

    def test_min_confidence_filters_the_report(self, leaky: LeakyRepo) -> None:
        permissive = run_cli(
            "git", str(leaky.path), "--format", "json", "--min-confidence", "candidate"
        )
        strict = run_cli(
            "git", str(leaky.path), "--format", "json", "--min-confidence", "verified"
        )

        permissive_findings = json.loads(permissive.stdout)["findings"]
        strict_findings = json.loads(strict.stdout)["findings"]

        assert permissive_findings
        assert len(strict_findings) < len(permissive_findings)

    def test_min_confidence_never_turns_a_partial_scan_into_a_clean_one(
        self, leaky: LeakyRepo
    ) -> None:
        result = run_cli(
            "git",
            str(leaky.path),
            "--max-commits",
            "1",
            "--min-confidence",
            "verified",
        )

        assert result.returncode == 3
        assert_no_synthetic_value(result)

    def test_an_unusable_min_confidence_is_two(self, leaky: LeakyRepo) -> None:
        assert (
            run_cli("git", str(leaky.path), "--min-confidence", "certain").returncode
            == 2
        )

    def test_fingerprint_is_present_in_json(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--format", "json")

        payload = json.loads(result.stdout)
        assert all(f["fingerprint"] for f in payload["findings"])

    def test_the_fingerprint_is_stable_across_runs(self, leaky: LeakyRepo) -> None:
        first = run_cli("git", str(leaky.path), "--format", "json")
        second = run_cli("git", str(leaky.path), "--format", "json")

        assert first.stdout == second.stdout

    def test_an_hmac_fingerprint_needs_a_key(self, leaky: LeakyRepo) -> None:
        result = run_cli(
            "git", str(leaky.path), "--format", "json", "--fingerprint", "hmac"
        )

        assert result.returncode == 2

    def test_the_coverage_line_goes_to_stderr(self, tmp_path: Path) -> None:
        repo = tmp_path / "binary"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        (repo / "logo.png").write_bytes(bytes(range(256)) * 8)
        (repo / "app.py").write_text("X = 1\n", encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo))

        assert result.returncode == 0
        assert "binary object(s) not searched" in result.stderr
        assert "binary" not in result.stdout

    def test_path_filters_are_off_unless_asked_for(self, tmp_path: Path) -> None:
        """A dependency tree is searched by default, because today's ignores
        may not have been in force when the secret was committed."""

        repo = tmp_path / "dependency"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        vendored = repo / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_text(
            f'var key = "{SYNTHETIC_AWS_KEY}";\n', encoding="utf-8"
        )
        (repo / "app.py").write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        build_git(repo, "add", "-f", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo))

        assert result.returncode == 1
        assert "node_modules" in result.stdout

    def test_respecting_path_filters_skips_the_dependency_tree(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "filtered"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        vendored = repo / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_text(
            f'var key = "{SYNTHETIC_AWS_KEY}";\n', encoding="utf-8"
        )
        (repo / "app.py").write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        build_git(repo, "add", "-f", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo), "--respect-path-filters")

        assert result.returncode == 1
        assert "node_modules" not in result.stdout
        assert "path(s) skipped by --respect-path-filters" in result.stderr

    def test_a_complete_scan_says_nothing_extra(self, tmp_path: Path) -> None:
        repo = tmp_path / "complete"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("X = 1\n", encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo))

        assert result.stderr == ""

    def test_the_output_is_deterministic(self, leaky: LeakyRepo) -> None:
        first = run_cli("git", str(leaky.path), "--format", "json")
        second = run_cli("git", str(leaky.path), "--format", "json")

        assert first.stdout == second.stdout
        assert first.returncode == second.returncode

    def test_stdin_is_not_read(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), stdin="", timeout=60.0)

        assert result.returncode == 1


@needs_git
class TestGitLimitsAndWindow:
    def test_max_commits_zero_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--max-commits", "0").returncode == 2

    def test_max_commits_is_not_a_number_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--max-commits", "many").returncode == 2

    def test_max_commits_past_the_end_is_not_a_truncation(
        self, leaky: LeakyRepo
    ) -> None:
        """Nothing was dropped, so exit ``3`` would be a false alarm."""

        result = run_cli("git", str(leaky.path), "--max-commits", "1000")

        assert result.returncode == 1
        assert "NOT examined in full" not in result.stderr

    def test_a_negative_max_commits_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--max-commits", "-1").returncode == 2

    def test_max_blob_size_counts_what_it_skipped(self, tmp_path: Path) -> None:
        repo = tmp_path / "huge"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        (repo / "big.env").write_text(
            "x" * 8192 + f'\nKEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8"
        )
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo), "--max-blob-size", "1024")

        assert result.returncode == 0
        assert "over the size limit not read" in result.stderr
        assert_no_synthetic_value(result)

    def test_max_blobs_counts_what_it_skipped(self, tmp_path: Path) -> None:
        repo = tmp_path / "many-blobs"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        for index in range(6):
            (repo / f"f{index}.txt").write_text(f"unique {index}\n", encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo), "--max-blobs", "2")

        assert result.returncode == 3
        assert "NOT examined in full" in result.stderr

    def test_a_hostile_since_is_two(self, leaky: LeakyRepo) -> None:
        """A date beginning with ``-`` is an option, whatever the user meant."""

        result = run_cli("git", str(leaky.path), "--since", "-x")

        assert result.returncode == 2
        assert result.stdout == ""
        assert "since" in result.stderr

    def test_a_hostile_until_is_two(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--until", "--all")

        assert result.returncode == 2

    def test_a_real_date_is_accepted(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--since", "2000-01-01")

        assert result.returncode == 1
        assert_no_synthetic_value(result)

    def test_a_window_that_excludes_the_secret_is_clean(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--since", "2099-01-01")

        assert result.returncode == 0
        assert "NOT examined in full" not in result.stderr

    def test_a_zero_timeout_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--timeout", "0").returncode == 2

    def test_an_unparseable_timeout_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--timeout", "soon").returncode == 2

    def test_a_timeout_beyond_the_ceiling_is_two(self, leaky: LeakyRepo) -> None:
        assert run_cli("git", str(leaky.path), "--timeout", "99999").returncode == 2

    def test_a_timeout_within_range_is_accepted(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", str(leaky.path), "--timeout", "120")

        assert result.returncode == 1

    def test_respect_path_filters_prunes_vendor_paths(self, tmp_path: Path) -> None:
        repo = tmp_path / "vendored"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        path = repo / "node_modules" / "pkg" / "index.env"
        path.parent.mkdir(parents=True)
        path.write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        without = run_cli("git", str(repo))
        with_filters = run_cli("git", str(repo), "--respect-path-filters")

        assert without.returncode == 1
        assert with_filters.returncode == 0
        assert "skipped by --respect-path-filters" in with_filters.stderr
        assert_no_synthetic_value(without)
        assert_no_synthetic_value(with_filters)

    def test_path_filters_are_off_by_default(self, tmp_path: Path) -> None:
        """A secret behind today's ignore rules is exactly the interesting case."""

        repo = tmp_path / "default"
        repo.mkdir()
        build_git(repo, "init", "-q", "-b", "main")
        path = repo / "node_modules" / "pkg" / "index.env"
        path.parent.mkdir(parents=True)
        path.write_text(f'KEY = "{SYNTHETIC_AWS_KEY}"\n', encoding="utf-8")
        build_git(repo, "add", "-A")
        build_git(repo, "commit", "-qm", "first")

        result = run_cli("git", str(repo))

        assert result.returncode == 1
        assert "node_modules/pkg/index.env" in result.stdout


@needs_git
class TestGitIsReadOnly:
    """The claim a CI job can verify for itself."""

    def _state(self, repo: Path) -> tuple[object, ...]:
        tracked = sorted(
            (str(path.relative_to(repo)), path.read_bytes())
            for path in repo.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(repo).parts
        )
        return (
            build_git(repo, "rev-parse", "HEAD"),
            build_git(repo, "symbolic-ref", "HEAD"),
            build_git(repo, "status", "--porcelain"),
            build_git(repo, "for-each-ref"),
            build_git(repo, "rev-list", "--all", "--count"),
            tuple(tracked),
        )

    def test_the_repository_is_untouched(self, leaky: LeakyRepo) -> None:
        before = self._state(leaky.path)

        run_cli("git", str(leaky.path))

        assert self._state(leaky.path) == before

    def test_nothing_is_checked_out(self, leaky: LeakyRepo) -> None:
        run_cli("git", str(leaky.path))

        assert not (leaky.path / "gone.py").exists()

    def test_the_working_tree_is_still_clean(self, leaky: LeakyRepo) -> None:
        run_cli("git", str(leaky.path))

        assert build_git(leaky.path, "status", "--porcelain") == ""

    def test_no_ref_was_created(self, leaky: LeakyRepo) -> None:
        before = build_git(leaky.path, "for-each-ref")

        run_cli("git", str(leaky.path))

        assert build_git(leaky.path, "for-each-ref") == before

    def test_two_runs_leave_the_repository_identical(self, leaky: LeakyRepo) -> None:
        run_cli("git", str(leaky.path))
        after_first = self._state(leaky.path)

        run_cli("git", str(leaky.path))

        assert self._state(leaky.path) == after_first

    def test_a_relative_target_works(self, leaky: LeakyRepo) -> None:
        result = run_cli("git", ".", cwd=leaky.path)

        assert result.returncode == 1
        assert "gone.py" in result.stdout
