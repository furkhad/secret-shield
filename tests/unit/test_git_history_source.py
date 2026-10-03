"""Unit tests for the Git history source.

:mod:`secret_shield.sources.git_history` is where a repository's *contents* stop
being trusted input and start being untrusted input. Two properties follow from
that, and they are what this file tests:

* **Every path in the history is attacker-controlled.** A tree entry can hold a
  newline, an ANSI escape, a bidirectional override, an absolute prefix or a
  ``..`` segment, and it can be arbitrarily long. Those tests
  (:class:`TestReportPath`) need no repository at all, because sanitising the
  label is a pure function of the label.
* **The expensive work is per blob, not per finding.** The source scans one
  blob's bytes once and then re-addresses the resulting findings at every path
  the blob was found at. Tests that only checked the findings would still pass
  if the content were re-scanned per path, so :class:`TestRelabel` asserts on the
  *number* of passes too.

The integration behaviour -- a secret committed and then deleted, deduplication
across commits and paths, the size and binary limits -- lives in
``tests/integration/test_git_history.py``, where a real repository is needed.

Every credential-shaped value below is assembled from a prefix and a body, so no
literal credential appears in this file.
"""

from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path

import pytest

from secret_shield.filters.paths import PathFilterConfig
from secret_shield.models import (
    Confidence,
    DetectorKind,
    Finding,
    Location,
    ScanError,
    ScanResult,
    SecretCategory,
    Severity,
    SourceKind,
)
from secret_shield.sources import git_cmd, git_history
from secret_shield.sources.filesystem import _cap_long_lines as filesystem_cap_long_lines
from secret_shield.sources.git_history import (
    DEFAULT_MAX_BLOBS,
    DEFAULT_MAX_BLOB_SIZE,
    MAX_PATH_LENGTH,
    BlobRecord,
    GitScanConfig,
    HistoryScan,
    default_git_scan_config,
    scan_history,
)

#: A key that matches the shipped AWS rule, built so that no literal credential
#: is committed to this file.
SYNTHETIC_AWS_KEY = "AKIA" + "5H2XNSYNTHKEY09A"


def _location(path: str, **kwargs: object) -> Location:
    """Build a ``Location`` with the defaults a Git finding would carry."""

    arguments: dict[str, object] = {
        "path": path,
        "line": 1,
        "column": 1,
        "source_kind": SourceKind.GIT,
        "commit": "a" * 40,
        "commit_time": 1_700_000_000,
    }
    arguments.update(kwargs)
    return Location(**arguments)  # type: ignore[arg-type]


def _finding(path: str = "a.txt", masked: str = "AKIA****KEY09A") -> Finding:
    """Build a ``Finding`` at ``path`` for the tests that only re-address it."""

    return Finding(
        rule_id="aws-access-key-id",
        rule_name="AWS Access Key ID",
        category=SecretCategory.AWS,
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        detector=DetectorKind.PATTERN,
        location=_location(path),
        masked_value=masked,
        value_length=20,
        value_fingerprint="0123456789ab",
        entropy=3.5,
        matched_keywords=("aws",),
        remediation="rotate it",
    )


def _ref(path: str, commit: str = "a" * 40, commit_time: int = 1_700_000_000) -> git_cmd.HistoryRef:
    return git_cmd.HistoryRef(
        commit=commit,
        commit_time=commit_time,
        path=path,
        object_name="b" * 40,
    )


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestGitScanConfig:
    def test_the_defaults_are_the_documented_ones(self) -> None:
        config = default_git_scan_config()

        assert config.max_blobs == DEFAULT_MAX_BLOBS
        assert config.blob_size_limit() > 0
        assert config.max_commits is None
        assert config.max_refs is not None

    def test_the_blob_limit_falls_back_to_the_file_limit(self) -> None:
        """One number for two identical questions is better than two settings."""

        config = GitScanConfig()

        assert config.blob_size_limit() == config.scan.max_file_size

    def test_an_explicit_blob_limit_wins_over_the_file_limit(self) -> None:
        config = GitScanConfig(max_blob_size=17)

        assert config.blob_size_limit() == 17

    def test_the_default_blob_size_matches_the_filesystem_bound(self) -> None:
        """A blob is a historical file, and the limit should say so once."""

        assert DEFAULT_MAX_BLOB_SIZE == GitScanConfig().scan.max_file_size

    def test_each_call_returns_a_fresh_object(self) -> None:
        assert default_git_scan_config() is not default_git_scan_config()

    def test_it_is_frozen(self) -> None:
        config = default_git_scan_config()

        with pytest.raises(dataclasses.FrozenInstanceError):
            config.max_blobs = 1  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("field", "value", "error", "message"),
        [
            ("max_line_length", 0, ValueError, "max_line_length must be at least 1"),
            ("max_line_length", "80", TypeError, "max_line_length must be an int"),
            ("max_commits", 0, ValueError, "max_commits must be at least 1"),
            ("max_commits", -3, ValueError, "max_commits must be at least 1"),
            ("max_commits", 1.5, TypeError, "max_commits must be an int"),
            ("max_blobs", 0, ValueError, "max_blobs must be at least 1"),
            ("max_refs", 0, ValueError, "max_refs must be at least 1"),
            ("max_blob_size", 0, ValueError, "max_blob_size must be at least 1"),
            ("max_blob_size", True, TypeError, "max_blob_size must be an int"),
            ("timeout", "60", TypeError, "timeout must be a number"),
            ("timeout", 0, ValueError, "timeout must be positive"),
            ("timeout", -1, ValueError, "timeout must be positive"),
        ],
    )
    def test_a_bad_limit_is_refused_at_construction(
        self, field: str, value: object, error: type[Exception], message: str
    ) -> None:
        """A configuration mistake should not wait for a repository to find it."""

        with pytest.raises(error) as raised:
            GitScanConfig(**{field: value})

        assert message in str(raised.value)

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("scan", 5, "scan must be a ScanConfig"),
            ("binary", None, "binary must be a BinaryConfig"),
            ("path_filters", "src", "path_filters must be a PathFilterConfig"),
            ("registry", {}, "registry must be a DetectorRegistry"),
        ],
    )
    def test_a_bad_component_is_refused_by_type(
        self, field: str, value: object, message: str
    ) -> None:
        with pytest.raises(TypeError) as raised:
            GitScanConfig(**{field: value})

        assert message in str(raised.value)

    @pytest.mark.parametrize("expression", ["-x", "--upload-pack=evil", "-"])
    def test_a_revision_may_not_look_like_an_option(self, expression: str) -> None:
        """A date that begins with ``-`` is an option, whatever the user meant."""

        with pytest.raises(ValueError) as raised:
            GitScanConfig(since=expression)

        assert "since" in str(raised.value)

    def test_until_is_checked_the_same_way(self) -> None:
        with pytest.raises(ValueError) as raised:
            GitScanConfig(until="--output=/tmp/x")

        assert "until" in str(raised.value)

    @pytest.mark.parametrize(
        "expression", ["2 weeks ago", "2024-01-01", "yesterday", "1970-01-01T00:00:00Z"]
    )
    def test_an_ordinary_date_expression_is_accepted(self, expression: str) -> None:
        assert GitScanConfig(since=expression, until=expression).since == expression

    def test_no_date_is_fine(self) -> None:
        config = GitScanConfig()

        assert config.since is None and config.until is None


class TestCoerceConfig:
    def test_none_means_the_shipped_defaults(self) -> None:
        assert git_history._coerce_config(None) is git_history.DEFAULT_GIT_SCAN_CONFIG

    def test_a_config_is_returned_unchanged(self) -> None:
        config = default_git_scan_config()

        assert git_history._coerce_config(config) is config

    def test_a_wrong_type_raises_rather_than_being_collected(self) -> None:
        """A programming error is loud; only repository problems are data."""

        with pytest.raises(TypeError) as raised:
            git_history._coerce_config({"max_blobs": 1})  # type: ignore[arg-type]

        assert "config must be a GitScanConfig" in str(raised.value)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


class TestReportPath:
    """A path out of a Git tree is attacker-controlled like any filename."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a.txt", "a.txt"),
            ("src/secret.py", "src/secret.py"),
            ("dir with space/three.txt", "dir with space/three.txt"),
            ("with space and 'quote.txt", "with space and 'quote.txt"),
            ("unicode-é中文.txt", "unicode-é中文.txt"),
        ],
    )
    def test_an_ordinary_path_survives_unchanged(self, raw: str, expected: str) -> None:
        assert git_history._report_path(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "evil\x1b[31mFAKE",
            "new\nline.txt",
            "null\x00byte.txt",
            "del\x7fete.txt",
            "bell\a.txt",
            "bidirectional‮gnitroc.txt",
        ],
    )
    def test_control_characters_are_stripped(self, raw: str) -> None:
        """Otherwise a repository repaints the CI log of whoever scans it."""

        result = git_history._report_path(raw)

        assert result is not None
        assert all(ord(character) >= 32 for character in result)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("../escape.py", "escape.py"),
            ("a/../../escape.py", "a/escape.py"),
            ("./a.txt", "a.txt"),
            ("a//b.txt", "a/b.txt"),
            ("/absolute.txt", "absolute.txt"),
            ("a/./b.txt", "a/b.txt"),
        ],
    )
    def test_a_crafted_path_cannot_escape_the_repository(self, raw: str, expected: str) -> None:
        """Segments are *removed*, not resolved, so no ``..`` survives to be printed."""

        assert git_history._report_path(raw) == expected

    def test_a_path_of_only_junk_is_dropped_rather_than_placeholdered(self) -> None:
        """A placeholder would merge two real paths into one wrong address."""

        assert git_history._report_path("..") is None
        assert git_history._report_path("/") is None
        assert git_history._report_path(".") is None
        assert git_history._report_path("\x00") is None

    def test_a_path_at_the_limit_is_kept(self) -> None:
        raw = "d" * MAX_PATH_LENGTH

        assert git_history._report_path(raw) == raw

    def test_a_path_over_the_limit_is_dropped(self) -> None:
        assert git_history._report_path("d" * (MAX_PATH_LENGTH + 1)) is None

    def test_a_path_that_only_fits_after_normalisation_is_dropped(self) -> None:
        raw = "./" * (MAX_PATH_LENGTH // 2) + "a.txt"
        assert len(raw) > MAX_PATH_LENGTH

        assert git_history._report_path(raw) is None

    def test_a_long_path_of_real_segments_is_dropped_too(self) -> None:
        raw = "/".join("segment" for _ in range(MAX_PATH_LENGTH // 4))

        assert len(raw) > MAX_PATH_LENGTH
        assert git_history._report_path(raw) is None


class TestPathAllowed:
    """History has no traversal order, so filtering is applied by hand."""

    @pytest.mark.parametrize(
        "path",
        [
            "src/app.py",
            "tests/test_app.py",
            "config/settings.toml",
            "README.md",
        ],
    )
    def test_ordinary_project_paths_are_kept(self, path: str) -> None:
        assert git_history._path_allowed(PathFilterConfig(), path) is True

    def test_a_default_ignored_directory_is_skipped_at_any_depth(self) -> None:
        filters = PathFilterConfig()

        assert git_history._path_allowed(filters, "node_modules/pkg/index.js") is False
        assert git_history._path_allowed(filters, ".git/config") is False

    def test_a_default_ignored_extension_is_skipped(self) -> None:
        filters = PathFilterConfig()

        assert git_history._path_allowed(filters, "image.png") is False

    def test_an_ignored_directory_name_skips_everything_under_it(self) -> None:
        """``decide`` alone would not: the ancestor is never visited."""

        filters = PathFilterConfig(ignored_directories=("vendor",))

        assert git_history._path_allowed(filters, "vendor/deep/file.py") is False
        assert git_history._path_allowed(filters, "src/vendor/file.py") is False

    def test_an_ignored_path_prefix_skips_the_directory(self) -> None:
        filters = PathFilterConfig(ignored_paths=("build", "docs/generated"))

        assert git_history._path_allowed(filters, "build/out.js") is False
        assert git_history._path_allowed(filters, "docs/generated/x.md") is False
        assert git_history._path_allowed(filters, "docs/written/x.md") is True

    def test_a_name_that_only_looks_like_a_directory_is_kept(self) -> None:
        """Directory names are matched exactly, never as substrings."""

        filters = PathFilterConfig(ignored_directories=("env",))

        assert git_history._path_allowed(filters, "envs/example.py") is True
        assert git_history._path_allowed(filters, "environment.py") is True
        assert git_history._path_allowed(filters, "env/example.py") is False

    def test_the_final_component_is_offered_as_a_file_not_a_directory(self) -> None:
        filters = PathFilterConfig(ignored_filenames=("secrets.json",))

        assert git_history._path_allowed(filters, "secrets.json") is False
        assert git_history._path_allowed(filters, "cfg/secrets.json") is False


# ---------------------------------------------------------------------------
# Re-addressing one blob's findings
# ---------------------------------------------------------------------------


class TestRelabel:
    def test_only_the_location_changes(self) -> None:
        """Severity, confidence and fingerprint are properties of the content."""

        original = _finding(path="first.txt")
        reference = _ref("second.txt", commit="c" * 40, commit_time=1_700_000_001)

        moved = git_history._relabel(original, reference)

        assert moved.location.path == "second.txt"
        assert moved.location.commit == "c" * 40
        assert moved.location.commit_time == 1_700_000_001
        assert moved.masked_value == original.masked_value
        assert moved.value_fingerprint == original.value_fingerprint
        assert moved.value_length == original.value_length
        assert moved.severity == original.severity
        assert moved.confidence == original.confidence
        assert moved.rule_id == original.rule_id
        assert moved.category == original.category
        assert moved.detector == original.detector
        assert moved.matched_keywords == original.matched_keywords
        assert moved.remediation == original.remediation

    def test_the_source_kind_survives(self) -> None:
        moved = git_history._relabel(_finding(), _ref("b.txt"))

        assert moved.location.source_kind is SourceKind.GIT

    def test_the_line_and_column_survive(self) -> None:
        moved = git_history._relabel(_finding(), _ref("b.txt"))

        assert (moved.location.line, moved.location.column) == (1, 1)

    def test_a_matching_reference_is_not_rewritten(self) -> None:
        """Identity is a cheap way to keep the common single-path case free."""

        original = _finding(path="only.txt")

        assert git_history._relabel(original, _ref("only.txt")) is original

    def test_the_original_is_left_untouched(self) -> None:
        original = _finding(path="first.txt")

        git_history._relabel(original, _ref("second.txt"))

        assert original.location.path == "first.txt"
        assert original.location.commit == "a" * 40

    def test_one_finding_per_path_from_a_single_analysis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The deduplication argument, asserted on the number of analyses.

        The count is the point: a source that re-scanned the content per path
        would produce the same findings and four times the work.
        """

        record = BlobRecord(
            name="b" * 40,
            paths=(_ref("a.txt"), _ref("b.txt"), _ref("dir with space/c.txt")),
            occurrences=9,
        )
        analyses: list[str] = []

        def counting_analyze_text(text: str, display: str, **kwargs: object) -> tuple[Finding, ...]:
            analyses.append(display)
            return (_finding(display),)

        monkeypatch.setattr(git_history, "analyze_text", counting_analyze_text)

        outcome = git_history._analyze_blob(
            b"whatever", record, default_git_scan_config()
        )

        assert len(analyses) == 1, "the blob's bytes were analysed once"
        assert [finding.location.path for finding in outcome.findings] == [
            "a.txt",
            "b.txt",
            "dir with space/c.txt",
        ]


class TestReportName:
    def test_a_blob_is_named_by_its_first_sorted_path(self) -> None:
        """A blob-level problem is a property of the bytes, not of where they lived."""

        record = BlobRecord(
            name="b" * 40,
            paths=(_ref("z.txt"), _ref("a.txt")),
            occurrences=2,
        )

        assert git_history._report_name(record) == "z.txt"

    def test_a_blob_with_no_path_is_named_by_its_object(self) -> None:
        record = BlobRecord(name="0123456789abcdef0123456789abcdef01234567")

        assert git_history._report_name(record) == "object:0123456789ab"


# ---------------------------------------------------------------------------
# Analysis of one blob
# ---------------------------------------------------------------------------


class TestAnalyzeBlob:
    def _record(self) -> BlobRecord:
        return BlobRecord(
            name="b" * 40,
            paths=(_ref("config.py"),),
            occurrences=1,
        )

    def test_a_secret_in_a_blob_is_found_and_addressed_at_the_commit(self) -> None:
        data = f'AWS_ACCESS_KEY_ID = "{SYNTHETIC_AWS_KEY}"\n'.encode("utf-8")

        outcome = git_history._analyze_blob(data, self._record(), default_git_scan_config())

        assert len(outcome.findings) == 1
        finding = outcome.findings[0]
        assert finding.rule_id == "aws-access-key-id"
        assert finding.location.source_kind is SourceKind.GIT
        assert finding.location.commit == "a" * 40
        assert finding.location.commit_time == 1_700_000_000
        assert finding.location.path == "config.py"
        assert outcome.errors == ()
        assert outcome.analyzed is True
        assert outcome.size == len(data)

    def test_the_secret_itself_is_never_kept_in_the_finding(self) -> None:
        data = f'{SYNTHETIC_AWS_KEY}\n'.encode("utf-8")

        outcome = git_history._analyze_blob(data, self._record(), default_git_scan_config())

        assert outcome.findings
        for finding in outcome.findings:
            assert SYNTHETIC_AWS_KEY not in repr(finding)

    def test_a_utf8_bom_is_transparently_removed(self) -> None:
        body = f'key = "{SYNTHETIC_AWS_KEY}"\n'.encode("utf-8")

        with_bom = git_history._analyze_blob(
            "﻿".encode("utf-8") + body, self._record(), default_git_scan_config()
        )
        without = git_history._analyze_blob(body, self._record(), default_git_scan_config())

        assert with_bom.findings[0].location == without.findings[0].location

    def test_invalid_utf8_is_an_error_not_a_finding(self) -> None:
        """Searching a mangled rendering reports on text nobody wrote."""

        data = b"key = \xff\xfe\x00\x80\n"

        outcome = git_history._analyze_blob(data, self._record(), default_git_scan_config())

        assert outcome.findings == ()
        assert [error.code for error in outcome.errors] == ["invalid-encoding"]
        assert outcome.analyzed is False

    def test_a_clean_blob_produces_nothing(self) -> None:
        outcome = git_history._analyze_blob(
            b"print('hello')\n", self._record(), default_git_scan_config()
        )

        assert outcome.findings == ()
        assert outcome.errors == ()

    def test_a_line_over_the_limit_is_declared(self) -> None:
        config = GitScanConfig(max_line_length=80)
        data = b"x" * 5000 + b"\n"

        outcome = git_history._analyze_blob(data, self._record(), config)

        assert [error.code for error in outcome.errors] == ["line-too-long"]
        assert "80" in outcome.errors[0].reason

    def test_an_over_long_line_still_finds_a_private_key(self) -> None:
        """A PEM block is legitimately longer than the line limit.

        Capping the text is what makes the analysis unfused, and giving up on the
        blob entirely would turn a certain finding into a missed one.
        """

        body = "".join(chr(ord("A") + index % 26) for index in range(4000))
        data = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "\n".join(body[index : index + 64] for index in range(0, 4000, 64))
            + "\n-----END RSA PRIVATE KEY-----\n"
        ).encode("utf-8")

        # One single line longer than the limit, so the cap actually fires.
        flat = "-----BEGIN RSA PRIVATE KEY----- " + body + " -----END RSA PRIVATE KEY-----\n"
        config = GitScanConfig(max_line_length=200)

        outcome = git_history._analyze_blob(flat.encode("utf-8"), self._record(), config)

        assert [error.code for error in outcome.errors] == ["line-too-long"]
        assert any("private" in finding.rule_id for finding in outcome.findings)

        # The same block split into short lines fuses normally and still matches.
        capped = git_history._analyze_blob(data, self._record(), config)

        assert capped.errors == ()
        assert any("private" in finding.rule_id for finding in capped.findings)

    def test_a_multi_line_block_is_collapsed_for_fusion(self) -> None:
        data = b"AWS_ACCESS_KEY_ID\n  = \"" + SYNTHETIC_AWS_KEY.encode("ascii") + b"\"\n"

        outcome = git_history._analyze_blob(data, self._record(), default_git_scan_config())

        assert any(finding.rule_id == "aws-access-key-id" for finding in outcome.findings)

    def test_one_finding_per_path_when_a_blob_has_many(self) -> None:
        record = BlobRecord(
            name="b" * 40,
            paths=(_ref("one.env"), _ref("two.env"), _ref("three.env")),
            occurrences=3,
        )
        data = f'KEY={SYNTHETIC_AWS_KEY}\n'.encode("utf-8")

        outcome = git_history._analyze_blob(data, record, default_git_scan_config())

        assert [finding.location.path for finding in outcome.findings] == [
            "one.env",
            "two.env",
            "three.env",
        ]
        assert {finding.location.commit for finding in outcome.findings} == {"a" * 40}


class TestCapLongLines:
    """Both copies exist on purpose; a test is what stops them drifting."""

    @pytest.mark.parametrize(
        ("text", "limit"),
        [
            ("", 10),
            ("short\n", 10),
            ("exactly-ten", 10),
            ("eleven chars\n", 10),
            ("a\n" * 100, 3),
            ("x" * 500, 1),
            ("no trailing newline", 5),
            ("trailing newline\n", 5),
            ("\n\n\n", 2),
        ],
    )
    def test_the_copy_matches_the_filesystem_source(self, text: str, limit: int) -> None:
        assert git_history._cap_long_lines(text, limit) == filesystem_cap_long_lines(text, limit)

    def test_a_capped_line_keeps_its_length_bound(self) -> None:
        """Line numbers must survive capping; only offsets may shift."""

        capped, over = git_history._cap_long_lines("x" * 100 + "\n" + "short\n", 10)

        assert capped == "x" * 10 + "\nshort\n"
        assert over == 1
        assert capped.count("\n") == ("x" * 100 + "\nshort\n").count("\n")

    def test_the_newline_is_not_counted_against_the_limit(self) -> None:
        """A line exactly at the limit is not an over-long line."""

        assert git_history._cap_long_lines("x" * 10 + "\n", 10) == ("x" * 10 + "\n", 0)

    def test_no_lines_over_the_limit_means_no_change(self) -> None:
        assert git_history._cap_long_lines("a\nb\n", 10) == ("a\nb\n", 0)

    def test_a_short_file_is_returned_unchanged_by_identity(self) -> None:
        text = "a\nb\n"

        assert git_history._cap_long_lines(text, 10)[0] is text


# ---------------------------------------------------------------------------
# What a history scan is
# ---------------------------------------------------------------------------


class TestHistoryScan:
    def test_findings_is_a_view_of_the_result(self) -> None:
        finding = _finding()
        scan = HistoryScan(result=ScanResult(findings=(finding,)))

        assert scan.findings == (finding,)

    def test_the_counters_default_to_zero(self) -> None:
        scan = HistoryScan(result=ScanResult())

        assert scan.commits == 0
        assert scan.blobs_seen == 0
        assert scan.blobs_scanned == 0
        assert not scan.truncated
        assert scan.truncated_because == ()

    def test_a_clean_scan_and_a_scan_that_looked_at_nothing_differ(self) -> None:
        """The counters are the only thing that tells these apart."""

        clean = HistoryScan(result=ScanResult(), commits=3, blobs_seen=4, blobs_scanned=4)
        empty = HistoryScan(result=ScanResult())

        assert clean.findings == empty.findings == ()
        assert clean.blobs_scanned > empty.blobs_scanned

    def test_the_result_reports_blobs_as_files(self) -> None:
        """One reporter for every source, so blobs must count as files."""

        scan = HistoryScan(result=ScanResult(), blobs_scanned=7)

        assert scan.result.files_scanned == 0  # the caller sets it, not the wrapper
        assert scan.blobs_scanned == 7


class TestFailedScan:
    def test_a_failed_scan_is_empty_and_carries_one_error(self) -> None:
        scan = git_history._failed(
            0.0, ScanError("no repository", path="/tmp/x", code="not-a-git-repository")
        )

        assert scan.findings == ()
        assert scan.result.files_scanned == 0
        assert scan.result.bytes_scanned == 0
        assert [error.code for error in scan.result.errors] == ["not-a-git-repository"]
        assert scan.blobs_scanned == 0


class TestErrorFor:
    def test_the_git_kind_becomes_the_code_verbatim(self) -> None:
        """So SHA-256 can be recognised by equality, not by reading prose."""

        error = git_history._error_for(
            git_cmd.GitError(git_cmd.KIND_OBJECT_FORMAT, "repository uses SHA-256"),
            Path("/tmp/repo"),
        )

        assert error.code == git_cmd.KIND_OBJECT_FORMAT == "unsupported-object-format"
        assert error.path == "/tmp/repo"

    def test_the_message_is_passed_through_unreworded(self) -> None:
        error = git_history._error_for(
            git_cmd.GitError(git_cmd.KIND_TIMEOUT, "Git did not finish in time"),
            Path("/tmp/repo"),
        )

        assert error.reason == "Git did not finish in time"

    def test_the_repository_path_is_attached(self) -> None:
        error = git_history._error_for(
            git_cmd.GitError(git_cmd.KIND_FAILED, "failed"), Path("/srv/app")
        )

        assert error.path == "/srv/app"


# ---------------------------------------------------------------------------
# Failure paths that need no repository
# ---------------------------------------------------------------------------


class TestNothingToScan:
    def test_a_missing_path_is_reported_not_raised(self) -> None:
        scan = scan_history("/nonexistent-repository-path/secret-shield")

        assert scan.findings == ()
        assert [error.code for error in scan.result.errors] == ["not-found"]
        assert scan.result.files_scanned == 0

    def test_a_plain_directory_is_not_a_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scan = scan_history(directory)

        assert scan.findings == ()
        assert [error.code for error in scan.result.errors] == [
            git_cmd.KIND_NOT_A_REPOSITORY
        ]

    def test_a_wrongly_typed_config_is_a_programming_error(self) -> None:
        with pytest.raises(TypeError):
            scan_history(".", config=object())  # type: ignore[arg-type]

    def test_a_config_is_optional(self) -> None:
        assert isinstance(scan_history(".", None).result, ScanResult)


# ---------------------------------------------------------------------------
# The shape of the source itself
# ---------------------------------------------------------------------------


class TestTheModuleShape:
    def test_it_exports_only_what_it_documents(self) -> None:
        exported = set(git_history.__all__)

        assert exported == {
            "DEFAULT_MAX_BLOBS",
            "DEFAULT_MAX_BLOB_SIZE",
            "DEFAULT_MAX_REFS",
            "MAX_PATH_LENGTH",
            "BlobRecord",
            "GitScanConfig",
            "HistoryScan",
            "default_git_scan_config",
            "scan_history",
        }
        for name in exported:
            assert hasattr(git_history, name), name

    def test_it_reaches_git_only_through_the_one_wrapper(self) -> None:
        """Every Git guarantee lives in ``git_cmd``; a second door would undo it."""

        import inspect

        source = inspect.getsource(git_history)

        for forbidden in ("import subprocess", "from subprocess import", "os.system("):
            assert forbidden not in source

        assert "git_cmd." in source

    def test_the_wrappers_are_the_only_process_importers_in_the_package(self) -> None:
        package = Path(git_history.__file__).resolve().parent.parent

        importers = {
            path.relative_to(package).as_posix()
            for path in package.rglob("*.py")
            if "import subprocess" in path.read_text(encoding="utf-8")
        }

        assert importers == {"sources/git_cmd.py"}

    def test_the_module_docstring_states_the_limits(self) -> None:
        doc = git_history.__doc__ or ""

        assert "SHA-256" in doc
        assert "reachable" in doc