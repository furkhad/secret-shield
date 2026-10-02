"""Unit tests for :mod:`secret_shield.models`.

The security-critical assertions live in
:func:`test_finding_cannot_hold_a_raw_secret` and its neighbours: a finding is
required to be incapable of retaining raw secret material, no matter how it is
inspected or serialized.

All secret-shaped values here are synthetic.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from secret_shield.models import (
    MAX_ENTROPY,
    SCHEMA_VERSION,
    TOOL_NAME,
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
from secret_shield.masking import (
    FINGERPRINT_LENGTH,
    REDACTION,
    MaskPolicy,
    fingerprint,
)

SYNTHETIC_SECRET = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
EXAMPLE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EXAMPLE_MULTILINE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "-----END RSA PRIVATE KEY-----"
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def make_location(**overrides: object) -> Location:
    """Build a valid file location, overriding individual fields."""

    fields: dict[str, object] = {
        "source_kind": SourceKind.FILE,
        "path": "config/settings.py",
        "line": 12,
        "column": 24,
    }
    fields.update(overrides)
    return Location(**fields)  # type: ignore[arg-type]


def make_finding(raw_value: str = SYNTHETIC_SECRET, **overrides: object) -> Finding:
    """Build a finding through the redacting factory."""

    fields: dict[str, object] = {
        "rule_id": "generic-api-key",
        "rule_name": "Generic API key",
        "category": SecretCategory.API_KEY,
        "severity": Severity.HIGH,
        "confidence": Confidence.PROBABLE,
        "detector": DetectorKind.PATTERN,
        "location": make_location(),
        "raw_value": raw_value,
        "policy": MaskPolicy(4, 4, name="test"),
        "entropy": 4.83,
        "matched_keywords": ["api_key", "staging"],
        "remediation": "Move the value into a secret manager.",
    }
    fields.update(overrides)
    return Finding.from_match(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# enums
# --------------------------------------------------------------------------


def test_severity_orders_numerically() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_labels_are_lowercase_and_stable() -> None:
    assert Severity.CRITICAL.label == "critical"
    assert Confidence.HIGH_CONFIDENCE.label == "high_confidence"
    assert SourceKind.FILE.label == "file"
    assert DetectorKind.COMPOSITE.label == "composite"


def test_str_enum_values_serialize_as_plain_strings() -> None:
    assert SecretCategory.PRIVATE_KEY.value == "private_key"
    assert SourceKind.GIT.value == "git"
    assert DetectorKind.ENTROPY.value == "entropy"


@pytest.mark.parametrize(
    "enum_class, label",
    [
        (Severity, "critical"),
        (Confidence, "high_confidence"),
        (SecretCategory, "private_key"),
        (SourceKind, "git"),
        (DetectorKind, "composite"),
    ],
)
def test_from_label_round_trips(enum_class: type, label: str) -> None:
    assert enum_class.from_label(label).label == label  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "label, expected",
    [("HIGH", Severity.HIGH), (" high ", Severity.HIGH)],
)
def test_from_label_is_forgiving_about_formatting(label: str, expected: Severity) -> None:
    assert Severity.from_label(label) is expected


def test_from_label_treats_hyphens_as_underscores() -> None:
    assert Confidence.from_label("high-confidence") is Confidence.HIGH_CONFIDENCE
    assert Confidence.from_label("HIGH_CONFIDENCE") is Confidence.HIGH_CONFIDENCE


def test_from_label_reports_the_valid_options() -> None:
    with pytest.raises(ValueError, match="valid labels"):
        Severity.from_label("urgent")


def test_from_label_rejects_non_strings() -> None:
    with pytest.raises(TypeError):
        Severity.from_label(3)  # type: ignore[arg-type]


def test_int_enum_str_is_not_a_label() -> None:
    """Guards the trap documented on the enums: ``str()`` yields the number."""

    assert str(Severity.HIGH) != "high"
    assert Severity.HIGH.label == "high"


# --------------------------------------------------------------------------
# Location
# --------------------------------------------------------------------------


def test_location_requires_a_path() -> None:
    with pytest.raises(ValueError):
        make_location(path="")
    with pytest.raises(ValueError):
        make_location(path="   ")


@pytest.mark.parametrize("field_name", ["line", "column"])
def test_location_positions_are_one_based(field_name: str) -> None:
    with pytest.raises(ValueError):
        make_location(**{field_name: 0})


def test_location_positions_accept_none() -> None:
    location = make_location(line=None, column=None)

    assert location.line is None
    assert location.column is None


def test_location_rejects_bool_positions() -> None:
    with pytest.raises(TypeError):
        make_location(line=True)  # type: ignore[arg-type]


def test_location_requires_a_full_commit_hash() -> None:
    with pytest.raises(ValueError):
        make_location(source_kind=SourceKind.GIT, commit="da2dc5d")
    # A full 40-character lowercase SHA-1 is accepted.
    assert make_location(source_kind=SourceKind.GIT, commit="da2dc5d" + ("0" * 33)) is not None


def test_location_rejects_uppercase_commit_hashes() -> None:
    with pytest.raises(ValueError):
        make_location(source_kind=SourceKind.GIT, commit="A" * 40)


def test_location_rejects_a_negative_commit_time() -> None:
    with pytest.raises(ValueError):
        make_location(source_kind=SourceKind.GIT, commit="a" * 40, commit_time=-1)


def test_location_display_omits_unknown_parts() -> None:
    assert make_location().to_display() == "config/settings.py:12:24"
    assert make_location(column=None).to_display() == "config/settings.py:12"
    assert make_location(line=None, column=None).to_display() == "config/settings.py"


def test_location_display_shortens_the_commit() -> None:
    location = make_location(source_kind=SourceKind.GIT, commit="a" * 40, line=None, column=None)

    assert location.to_display() == f"config/settings.py@{'a' * 12}"


def test_location_to_dict_has_stable_keys() -> None:
    assert list(make_location().to_dict()) == [
        "source_kind",
        "path",
        "line",
        "column",
        "commit",
        "commit_time",
    ]


def test_location_repr_is_informative_and_safe() -> None:
    assert "config/settings.py" in repr(make_location())


# --------------------------------------------------------------------------
# Finding: the security invariant
# --------------------------------------------------------------------------


def test_finding_declares_no_raw_secret_field() -> None:
    names = {field.name for field in dataclasses.fields(Finding)}

    assert "raw_value" not in names
    assert "value" not in names
    assert "secret" not in names
    assert names.isdisjoint({"raw", "plaintext", "match"})


def test_finding_cannot_hold_a_raw_secret() -> None:
    """The headline guarantee of the whole design."""

    finding = make_finding(EXAMPLE_AWS_KEY)
    rendered = repr(finding) + finding.to_json(indent=2) + json.dumps(finding.to_dict())

    assert EXAMPLE_AWS_KEY not in rendered
    assert SYNTHETIC_SECRET not in rendered


def test_finding_repr_never_contains_a_test_secret() -> None:
    finding = make_finding(SYNTHETIC_SECRET)

    assert SYNTHETIC_SECRET not in repr(finding)
    assert SYNTHETIC_SECRET[:4] in repr(finding)  # the deliberate prefix reveal
    assert finding.rule_id in repr(finding)


def test_finding_serialization_never_contains_a_raw_test_secret() -> None:
    finding = make_finding(EXAMPLE_AWS_KEY)

    assert EXAMPLE_AWS_KEY not in finding.to_json()
    assert EXAMPLE_AWS_KEY not in json.dumps(finding.to_dict())
    assert EXAMPLE_AWS_KEY not in finding.masked_value


def test_finding_keeps_only_redacted_material() -> None:
    finding = make_finding(EXAMPLE_AWS_KEY, policy=MaskPolicy(4, 4, name="aws"))

    assert finding.masked_value.startswith("AKIA")
    assert finding.masked_value.endswith("MPLE")
    assert finding.value_length == len(EXAMPLE_AWS_KEY)


def test_finding_defaults_to_revealing_nothing() -> None:
    finding = make_finding(EXAMPLE_AWS_KEY, policy=None)

    assert finding.masked_value == REDACTION


def test_finding_fingerprints_the_raw_value() -> None:
    finding = make_finding(SYNTHETIC_SECRET)

    assert finding.value_fingerprint == fingerprint(SYNTHETIC_SECRET)
    assert len(finding.value_fingerprint) == FINGERPRINT_LENGTH


def test_same_secret_at_two_places_shares_a_fingerprint() -> None:
    first = make_finding(location=make_location(line=1))
    second = make_finding(location=make_location(line=99))

    assert first.secret_key() == second.secret_key()
    assert first.occurrence_key() != second.occurrence_key()


def test_different_secrets_have_different_fingerprints() -> None:
    first = make_finding(SYNTHETIC_SECRET)
    second = make_finding(SYNTHETIC_SECRET + "extra")

    assert first.secret_key() != second.secret_key()


def test_finding_supports_keyed_fingerprints() -> None:
    keyed = make_finding(SYNTHETIC_SECRET, fingerprint_key=b"per-run-key")
    unkeyed = make_finding(SYNTHETIC_SECRET)

    assert keyed.value_fingerprint != unkeyed.value_fingerprint


def test_multiline_values_are_fully_redacted() -> None:
    """A multi-line block must never keep a visible prefix or suffix."""

    finding = make_finding(EXAMPLE_MULTILINE_KEY, policy=MaskPolicy(10, 10, name="leaky"))

    assert finding.masked_value == REDACTION
    assert "\n" not in finding.masked_value
    assert finding.value_length == len(EXAMPLE_MULTILINE_KEY)


def test_surrounding_whitespace_does_not_defeat_masking() -> None:
    finding = make_finding(f"  {SYNTHETIC_SECRET}\n", policy=MaskPolicy(0, 0, name="strict"))

    assert finding.masked_value == REDACTION
    assert "\n" not in finding.masked_value


def test_from_match_rejects_non_string_values() -> None:
    with pytest.raises(TypeError):
        make_finding(b"raw-bytes")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Finding: validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", ["", "Has Spaces", "UPPER", "-leading", "trailing-", "a--b"])
def test_finding_rejects_invalid_rule_ids(rule_id: str) -> None:
    finding = make_finding()
    with pytest.raises(ValueError):
        dataclasses.replace(finding, rule_id=rule_id)


def test_finding_accepts_a_long_but_well_formed_rule_id() -> None:
    rule_id = "vendor-" + "segment-" * 8 + "key"

    assert dataclasses.replace(make_finding(), rule_id=rule_id).rule_id == rule_id


def test_finding_rejects_an_empty_rule_name() -> None:
    finding = make_finding()

    with pytest.raises(ValueError):
        dataclasses.replace(finding, rule_name="  ")


@pytest.mark.parametrize("masked", ["", "line\nbreak", "tab\there"])
def test_finding_rejects_unsafe_masked_values(masked: str) -> None:
    """A redacted value must stay single-line and non-empty."""

    finding = make_finding()

    with pytest.raises(ValueError):
        dataclasses.replace(finding, masked_value=masked)


@pytest.mark.parametrize("length", [-1, -100])
def test_finding_rejects_a_negative_length(length: int) -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(make_finding(), value_length=length)


def test_finding_accepts_a_zero_length_value() -> None:
    assert dataclasses.replace(make_finding(), value_length=0).value_length == 0


@pytest.mark.parametrize("bad", ["", "short", "0123456789AB", "0123456789ABC", "zzzzzzzzzzzz", None])
def test_finding_rejects_an_invalid_fingerprint(bad: object) -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(make_finding(), value_fingerprint=bad)


@pytest.mark.parametrize("entropy", [0.0, 1.5, 4.83, MAX_ENTROPY])
def test_finding_accepts_entropy_in_range(entropy: float) -> None:
    assert dataclasses.replace(make_finding(), entropy=entropy).entropy == entropy


@pytest.mark.parametrize("entropy", [-0.1, MAX_ENTROPY + 0.1, float("nan")])
def test_finding_rejects_impossible_entropy(entropy: float) -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(make_finding(), entropy=entropy)


def test_finding_accepts_no_entropy() -> None:
    assert dataclasses.replace(make_finding(), entropy=None).entropy is None


def test_finding_rejects_a_bare_string_of_keywords() -> None:
    """A string is iterable, so this mistake would otherwise pass silently."""

    with pytest.raises(TypeError):
        dataclasses.replace(make_finding(), matched_keywords="api_key")


def test_finding_freezes_keyword_tuples() -> None:
    finding = dataclasses.replace(make_finding(), matched_keywords=["alpha", "beta"])

    assert finding.matched_keywords == ("alpha", "beta")


def test_finding_is_hashable_and_immutable() -> None:
    finding = make_finding()

    assert hash(finding) == hash(make_finding())
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.severity = Severity.LOW  # type: ignore[misc]


# --------------------------------------------------------------------------
# Finding: serialization
# --------------------------------------------------------------------------


def test_finding_to_dict_keys_are_stable() -> None:
    assert list(make_finding().to_dict()) == [
        "rule_id",
        "rule_name",
        "category",
        "severity",
        "confidence",
        "detector",
        "location",
        "masked_value",
        "value_length",
        "value_fingerprint",
        "entropy",
        "matched_keywords",
        "remediation",
    ]


def test_finding_serialization_is_deterministic() -> None:
    finding = make_finding()

    assert finding.to_json() == finding.to_json()
    assert finding.to_json() == make_finding().to_json()


def test_finding_to_dict_is_json_ready() -> None:
    payload = make_finding().to_dict()

    assert json.loads(json.dumps(payload)) == payload
    assert payload["severity"] == "high"
    assert payload["confidence"] == "probable"
    assert payload["category"] == "api_key"


def test_finding_sort_key_orders_by_position() -> None:
    late = make_finding(location=make_location(line=99))
    early = make_finding(location=make_location(line=2))

    assert sorted([late, early], key=lambda f: f.sort_key) == [early, late]


def test_finding_sort_key_tolerates_missing_positions() -> None:
    without_line = make_finding(location=make_location(line=None, column=None))

    assert without_line.sort_key[1] == 0


# --------------------------------------------------------------------------
# ScanError
# --------------------------------------------------------------------------


def test_scan_error_to_dict_has_stable_keys() -> None:
    assert list(ScanError("boom", path="a/b.py").to_dict()) == ["code", "path", "reason"]


def test_scan_error_requires_a_reason() -> None:
    with pytest.raises(ValueError):
        ScanError("   ")


def test_scan_error_strips_control_characters() -> None:
    error = ScanError("cannot read\x1b[31m", path="dir\x07/file")

    assert "\x1b" not in error.reason
    assert "\x07" not in (error.path or "")


def test_scan_error_repr_has_no_escape_sequences() -> None:
    assert "\x1b" not in repr(ScanError("bad\x1b[0m"))


# --------------------------------------------------------------------------
# ScanResult
# --------------------------------------------------------------------------


def test_empty_scan_result_is_serializable() -> None:
    result = ScanResult(tool_version="0.1.0")
    payload = result.to_dict()

    assert result.findings == ()
    assert result.highest_severity() is None
    assert payload["summary"]["total_findings"] == 0
    assert payload["findings"] == []


def test_scan_result_freezes_lists() -> None:
    result = ScanResult(findings=[make_finding()], errors=[ScanError("boom")])  # type: ignore[arg-type]

    assert isinstance(result.findings, tuple)
    assert isinstance(result.errors, tuple)


def test_scan_result_rejects_wrong_element_types() -> None:
    with pytest.raises(TypeError):
        ScanResult(findings=["not a finding"])  # type: ignore[arg-type]


def test_scan_result_rejects_a_string_of_findings() -> None:
    with pytest.raises(TypeError):
        ScanResult(findings="abc")  # type: ignore[arg-type]


def test_scan_result_counts_are_complete_and_ordered() -> None:
    result = ScanResult(
        findings=[
            make_finding(severity=Severity.LOW),
            make_finding(severity=Severity.CRITICAL, raw_value=SYNTHETIC_SECRET + "b"),
            make_finding(severity=Severity.CRITICAL, raw_value=SYNTHETIC_SECRET + "c"),
        ]
    )

    counts = result.counts_by_severity()

    assert list(counts) == ["critical", "high", "medium", "low"]
    assert counts["critical"] == 2
    assert counts["high"] == 0


def test_scan_result_confidence_counts_are_complete() -> None:
    counts = ScanResult(findings=[make_finding()]).counts_by_confidence()

    assert list(counts) == ["verified", "high_confidence", "probable", "candidate"]
    assert counts["probable"] == 1


def test_scan_result_category_counts_are_sorted() -> None:
    result = ScanResult(
        findings=[
            make_finding(category=SecretCategory.STRIPE, raw_value=SYNTHETIC_SECRET + "1"),
            make_finding(category=SecretCategory.AWS, raw_value=SYNTHETIC_SECRET + "2"),
        ]
    )

    assert list(result.counts_by_category()) == ["aws", "stripe"]


def test_scan_result_highest_severity() -> None:
    result = ScanResult(
        findings=[
            make_finding(severity=Severity.MEDIUM, raw_value=SYNTHETIC_SECRET + "1"),
            make_finding(severity=Severity.CRITICAL, raw_value=SYNTHETIC_SECRET + "2"),
        ]
    )

    assert result.highest_severity() is Severity.CRITICAL


def test_scan_result_counts_distinct_secrets() -> None:
    shared = SYNTHETIC_SECRET
    result = ScanResult(
        findings=[
            make_finding(shared, location=make_location(line=1)),
            make_finding(shared, location=make_location(line=2)),
            make_finding(shared + "different", location=make_location(line=3)),
        ]
    )

    assert len(result.findings) == 3
    assert result.distinct_secret_count() == 2


def test_scan_result_sorted_findings_is_deterministic() -> None:
    findings = [
        make_finding(location=make_location(line=line, column=column))
        for line, column in [(9, 1), (2, 30), (2, 4)]
    ]

    ordered = ScanResult(findings=findings).sorted_findings()

    assert [finding.location.line for finding in ordered] == [2, 2, 9]
    assert [finding.location.column for finding in ordered] == [4, 30, 1]


def test_scan_result_serialization_is_deterministic() -> None:
    result = ScanResult(
        findings=[make_finding(location=make_location(line=2)), make_finding()],
        errors=[ScanError("boom", path="a.py")],
        files_scanned=3,
        bytes_scanned=1024,
        duration_seconds=0.5,
        tool_version="0.1.0",
    )

    assert result.to_json() == result.to_json()
    assert result.to_json() == ScanResult(
        findings=[make_finding(location=make_location(line=2)), make_finding()],
        errors=[ScanError("boom", path="a.py")],
        files_scanned=3,
        bytes_scanned=1024,
        duration_seconds=0.5,
        tool_version="0.1.0",
    ).to_json()


def test_scan_result_envelope_shape() -> None:
    payload = ScanResult(tool_version="0.1.0").to_dict()

    assert list(payload) == ["schema_version", "tool", "summary", "findings", "errors"]
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["tool"] == {"name": TOOL_NAME, "version": "0.1.0"}


def test_scan_result_summary_is_json_ready() -> None:
    result = ScanResult(findings=[make_finding()], files_scanned=2, bytes_scanned=64)
    summary = result.summary()

    assert json.loads(json.dumps(summary)) == summary
    assert summary["total_findings"] == 1
    assert summary["highest_severity"] == "high"
    assert summary["error_count"] == 0


@pytest.mark.parametrize("field_name", ["files_scanned", "bytes_scanned"])
@pytest.mark.parametrize("value", [-1, -1000])
def test_scan_result_rejects_negative_counters(field_name: str, value: int) -> None:
    with pytest.raises(ValueError):
        ScanResult(**{field_name: value})


@pytest.mark.parametrize("value", [-0.001, float("nan")])
def test_scan_result_rejects_impossible_durations(value: float) -> None:
    with pytest.raises(ValueError):
        ScanResult(duration_seconds=value)


def test_scan_result_rejects_bool_counters() -> None:
    with pytest.raises(TypeError):
        ScanResult(files_scanned=True)  # type: ignore[arg-type]


def test_scan_result_repr_is_compact_and_safe() -> None:
    result = ScanResult(findings=[make_finding(SYNTHETIC_SECRET)], files_scanned=1)
    rendered = repr(result)

    assert SYNTHETIC_SECRET not in rendered
    assert "findings=1" in rendered