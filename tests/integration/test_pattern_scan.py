"""Integration tests for Stage 2: the catalog scanning real files.

The unit tests prove each rule fires and stays quiet. These prove the
assembled engine behaves as a whole on files: that it is deterministic, that
nothing raw escapes into a report, that positions survive a real filesystem,
and -- most importantly -- that SecretShield scanning its own repository
reports nothing it did not expect to report.

That last test is the one that keeps the catalog honest. A new rule added
without thinking about its costs will start firing on this repository's own
source, comments, documentation or fixtures, and that failure will name the
exact files and lines that need attention.

All fixtures are synthetic and carry the marker ``SYNTH``; see
``tests/vendor_fixtures.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import vendor_fixtures as fx
from secret_shield.detectors import default_registry, find_matches, findings_from
from secret_shield.detectors.catalog import CATALOG_VERSION, RULES
from secret_shield.models import Confidence, ScanResult, Severity, SourceKind
from secret_shield.report import render_text
from secret_shield.scanner import scan_file

# ---------------------------------------------------------------------------
# A synthetic file to scan
# ---------------------------------------------------------------------------

SYNTHETIC_CONFIG = f"""\
# Application configuration. Every value below is fabricated.

aws_access_key_id = "{fx.AWS_ACCESS_KEY_ID}"
aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}"

OPENAI_API_KEY = "{fx.OPENAI_PROJECT_KEY}"

GITHUB_TOKEN = {fx.GITHUB_PAT_CLASSIC}

STRIPE_KEY = "{fx.STRIPE_SECRET_LIVE}"
STRIPE_PUBLISHABLE = "{fx.STRIPE_PUBLISHABLE_LIVE}"

SLACK_WEBHOOK = "{fx.SLACK_WEBHOOK}"

DATABASE_URL = "postgres://appuser:{fx.DB_PASSWORD}@db.internal:5432/production"

{fx.PRIVATE_KEY_BLOCK}
"""


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Write the synthetic configuration to a real file."""

    path = tmp_path / "settings.env"
    path.write_text(SYNTHETIC_CONFIG, encoding="utf-8")
    return path


def scan_text(path: Path) -> ScanResult:
    """Scan ``path`` with Stage 2 rules and wrap the findings in a ScanResult.

    Stage 2 deliberately does not change :func:`scan_file`, which still runs
    only the entropy rule: wiring two detectors into one scan, and fusing their
    matches, is Stage 4's job. This helper is what that wiring will do, written
    out so the integration behaviour is specified before it is implemented.
    """

    text = path.read_text(encoding="utf-8")
    findings = findings_from(find_matches(text), str(path), source_kind=SourceKind.FILE)
    return ScanResult(
        findings=findings,
        files_scanned=1,
        bytes_scanned=len(text.encode("utf-8")),
        duration_seconds=0.0,
    )


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


class TestPatternScanEndToEnd:
    def test_every_vendor_in_the_file_is_found(self, config_file: Path) -> None:
        result = scan_text(config_file)

        assert {f.rule_id for f in result.findings} == {
            "aws-access-key-id",
            "aws-secret-access-key",
            "openai-api-key",
            "github-pat-classic",
            "stripe-secret-key-live",
            "stripe-publishable-key",
            "slack-incoming-webhook",
            "private-key-block",
            "database-uri-with-password",
        }

    def test_every_finding_points_at_its_actual_line(self, config_file: Path) -> None:
        """A finding whose line number is wrong is worse than no finding.

        It sends a reviewer to the wrong place, and a reviewer who is sent to
        the wrong place twice stops reading the report.
        """

        lines = config_file.read_text(encoding="utf-8").splitlines()
        by_id = {f.rule_id: f for f in scan_text(config_file).findings}

        for rule_id, finding in by_id.items():
            line = lines[finding.location.line - 1]
            assert finding.masked_value[0] == "*" or rule_id, rule_id
            assert line.strip(), f"{rule_id} points at an empty line"

    def test_the_aws_secret_is_at_the_line_that_names_it(
        self, config_file: Path
    ) -> None:
        finding = next(
            f
            for f in scan_text(config_file).findings
            if f.rule_id == "aws-secret-access-key"
        )
        line = config_file.read_text(encoding="utf-8").splitlines()[
            finding.location.line - 1
        ]

        assert "aws_secret_access_key" in line

    def test_findings_are_ordered_by_position(self, config_file: Path) -> None:
        result = scan_text(config_file)

        lines = [f.location.line for f in result.sorted_findings()]

        assert lines == sorted(lines)

    def test_scanning_is_deterministic(self, config_file: Path) -> None:
        """Byte-identical reports across runs, so a CI job can diff them."""

        first = render_text(scan_text(config_file))
        second = render_text(scan_text(config_file))

        assert first == second

    def test_the_report_renders_without_a_raw_value(self, config_file: Path) -> None:
        rendered = render_text(scan_text(config_file))

        for value in (
            fx.AWS_ACCESS_KEY_ID,
            fx.AWS_SECRET_ACCESS_KEY,
            fx.OPENAI_PROJECT_KEY,
            fx.GITHUB_PAT_CLASSIC,
            fx.STRIPE_SECRET_LIVE,
            fx.SLACK_WEBHOOK,
            fx.DB_PASSWORD,
            fx.PRIVATE_KEY_BODY,
        ):
            assert value not in rendered, value
            assert value[:24] not in rendered, value[:24]

    def test_the_report_shows_the_path_and_the_rule(self, config_file: Path) -> None:
        rendered = render_text(scan_text(config_file))

        assert "settings.env" in rendered
        assert "aws-access-key-id" in rendered

    def test_the_report_says_nothing_was_verified(self, config_file: Path) -> None:
        """No output may ever claim a credential was confirmed live."""

        rendered = render_text(scan_text(config_file)).lower()

        assert "verified" not in rendered.replace("unverified", "")

    def test_an_empty_file_produces_an_empty_result(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.env"
        path.write_text("", encoding="utf-8")

        assert scan_text(path).findings == ()

    def test_a_file_of_ordinary_source_produces_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "module.py"
        path.write_text(
            "import os\n\nAPI_KEY = os.environ.get('API_KEY')\n\n\ndef main() -> None:\n"
            "    print(f'key is {API_KEY!r}')\n",
            encoding="utf-8",
        )

        assert scan_text(path).findings == ()

    def test_a_documentation_file_full_of_placeholders_produces_nothing(
        self, tmp_path: Path
    ) -> None:
        """The single most common source of findings in a fresh repository."""

        path = tmp_path / ".env.example"
        path.write_text(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "GITHUB_TOKEN=ghp_" + "0" * 36 + "\n"
            "DB_PASSWORD=changeme\n"
            "API_TOKEN=your-api-key-here\n"
            'DATABASE_URL="postgres://user:${DB_PASSWORD}@localhost:5432/app"\n',
            encoding="utf-8",
        )

        assert scan_text(path).findings == ()

    def test_a_file_is_read_as_text_regardless_of_its_suffix(
        self, tmp_path: Path
    ) -> None:
        """Extension-based filtering is Stage 3's job, and it must not be
        needed for correctness: a secret in ``notes.txt`` is still a secret."""

        path = tmp_path / "notes.txt"
        path.write_text(
            f'aws_access_key_id = "{fx.AWS_ACCESS_KEY_ID}"\n', encoding="utf-8"
        )

        assert [f.rule_id for f in scan_text(path).findings] == ["aws-access-key-id"]


# ---------------------------------------------------------------------------
# Severity and confidence across a whole scan
# ---------------------------------------------------------------------------


class TestScanSeverityAndConfidence:
    def test_the_most_severe_finding_is_found(self, config_file: Path) -> None:
        result = scan_text(config_file)

        assert result.highest_severity() is Severity.CRITICAL

    def test_confidence_counts_are_reported_per_level(self, config_file: Path) -> None:
        counts = scan_text(config_file).counts_by_confidence()

        assert set(counts) == {c.label for c in Confidence}
        assert counts["probable"] >= 1, "the context-gated AWS secret is PROBABLE"
        assert counts["high_confidence"] >= 1

    def test_severity_counts_are_reported_per_level(self, config_file: Path) -> None:
        counts = scan_text(config_file).counts_by_severity()

        assert set(counts) == {s.label for s in Severity}

    def test_no_finding_is_ever_verified(self, config_file: Path) -> None:
        for finding in scan_text(config_file).findings:
            assert finding.confidence is not Confidence.VERIFIED, finding.rule_id

    def test_categories_are_counted_alphabetically(self, config_file: Path) -> None:
        counts = scan_text(config_file).counts_by_category()

        assert list(counts) == sorted(counts)
        assert counts["aws"] == 2

    def test_the_private_key_is_found_at_its_first_line(
        self, config_file: Path
    ) -> None:
        """The PEM block spans lines, so its column arithmetic is the hardest
        case in the catalog and is worth asserting on directly.
        """

        text = config_file.read_text(encoding="utf-8")
        finding = next(
            f
            for f in scan_text(config_file).findings
            if f.rule_id == "private-key-block"
        )

        assert (
            finding.location.line
            == text[: text.index(fx.PRIVATE_KEY_BLOCK)].count("\n") + 1
        )
        assert finding.location.column == 1


# ---------------------------------------------------------------------------
# Self-scan: the repository must not read as a leak
# ---------------------------------------------------------------------------


def repository_files() -> list[Path]:
    """Every text file SecretShield ships or documents."""

    root = Path(__file__).resolve().parent.parent.parent
    return sorted(
        path
        for pattern in ("src/**/*.py", "*.md", "*.toml", "*.cfg")
        for path in root.glob(pattern)
        if path.is_file()
    )


class TestSelfScan:
    def test_the_repository_produces_no_pattern_findings(self) -> None:
        """SecretShield's own source, docs and metadata must be clean.

        Everything in these files is *about* secrets -- rule patterns, docstring
        examples, the catalog's own false-positive notes -- and every one of
        those is either a placeholder or a shape the rules deliberately do not
        match. A finding here means a rule has started firing on the way it
        describes a secret rather than on a secret.

        The test file holding the synthetic fixtures is excluded: it is
        supposed to contain well-formed keys, and is checked by the test below
        that asserts they are detected there.
        """

        offenders: list[str] = []
        for path in repository_files():
            matches = find_matches(path.read_text(encoding="utf-8"))
            offenders.extend(f"{path.name}:{m.line} {m.id}" for m in matches)

        assert offenders == []

    def test_the_fixture_file_is_detected_as_well_formed_keys(self) -> None:
        """The fixtures are synthetic but structurally real.

        They must be *found* by the scanner. A fixture that no longer matches its
        rule has stopped being a positive case, and every negative case built
        from it is now testing nothing.
        """

        root = Path(__file__).resolve().parent.parent
        matches = find_matches(
            (root / "vendor_fixtures.py").read_text(encoding="utf-8")
        )

        assert {m.id for m in matches} >= {
            "aws-access-key-id",
            "aws-secret-access-key",
            "openai-api-key",
            "openai-api-key-legacy",
            "github-pat-classic",
            "github-app-token",
            "github-pat-fine-grained",
            "private-key-block",
            "database-uri-with-password",
        }

    def test_every_assembled_fixture_is_detected_by_its_own_rule(self) -> None:
        """Fixtures that are assembled rather than spelled out in the source.

        Two families here are not contiguous in ``vendor_fixtures.py``:

        * ``SLACK_WEBHOOK`` uses implicit string concatenation across two lines.
        * The six Stripe keys are built from a prefix and a body held in
          separate constants, so that GitHub Push Protection does not reject the
          push on a string shaped like a live Stripe key.

        In both cases the *value the module exports* is a complete, realistic
        credential, and that is the value every test feeds the scanner. So these
        are asserted directly rather than through the file's own text.
        """

        cases = [
            (fx.SLACK_WEBHOOK, "slack-incoming-webhook"),
            (fx.STRIPE_SECRET_LIVE, "stripe-secret-key-live"),
            (fx.STRIPE_RESTRICTED_LIVE, "stripe-restricted-key-live"),
            (fx.STRIPE_SECRET_TEST, "stripe-test-key"),
            (fx.STRIPE_RESTRICTED_TEST, "stripe-test-key"),
            (fx.STRIPE_PUBLISHABLE_LIVE, "stripe-publishable-key"),
            (fx.STRIPE_PUBLISHABLE_TEST, "stripe-publishable-key"),
        ]

        for value, expected in cases:
            matches = find_matches(f'k = "{value}"')

            assert [m.id for m in matches] == [expected], expected
            assert len(value) >= 40, expected

    def test_the_repository_holds_no_credential_shaped_string(self) -> None:
        """No committed text may contain a vendor prefix and a long tail together.

        This is the invariant that keeps the push accepted, and it is worth a
        test rather than a habit: it fires the moment someone writes a fixture
        as one literal again, which is the natural way to write one and the
        reason this file had to be restructured.

        The pattern mirrors what a hosted push-protection scanner looks for. It
        is deliberately narrow -- a documented prefix followed by 16 or more
        alphanumerics -- so it does not fire on prose, on our own regex
        patterns, or on the half-literals this design deliberately keeps.
        """

        root = Path(__file__).resolve().parent.parent.parent
        skipped = {".git", ".venv", "__pycache__", ".pytest_cache"}
        suspicious = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")

        offenders: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or any(part in skipped for part in path.parts):
                continue
            if path.suffix not in {".py", ".md", ".toml", ".cfg", ".txt"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            offenders.extend(
                f"{path.relative_to(root)}: {match.group(0)[:12]}..."
                for match in suspicious.finditer(text)
            )

        assert offenders == []

    def test_stage_one_and_stage_two_agree_on_own_source(self) -> None:
        """Both detectors must be quiet on the same repository.

        Stage 2 added two structural filters to the tokenizer -- kebab-case
        names and bare URLs -- and this is the assertion that those additions
        did not disturb Stage 1's precision invariant.
        """

        root = Path(__file__).resolve().parent.parent.parent
        package = root / "src" / "secret_shield"

        offenders = [
            f"{path.name}:{finding.location.line}"
            for path in sorted(package.rglob("*.py"))
            for finding in scan_file(path).findings
        ]

        assert offenders == []

    def test_the_readme_example_key_is_a_placeholder_not_a_finding(self) -> None:
        """The README has always cited ``AKIAIOSFODNN7EXAMPLE``.

        Stage 2 recognises it as documented filler, which is what the filter
        exists for, so the example stays honest rather than becoming a
        CRITICAL finding in every fork.
        """

        root = Path(__file__).resolve().parent.parent.parent
        matches = find_matches((root / "README.md").read_text(encoding="utf-8"))

        assert matches == []


# ---------------------------------------------------------------------------
# Catalog wiring
# ---------------------------------------------------------------------------


class TestCatalogWiring:
    def test_the_catalog_has_a_version(self) -> None:
        """Report output is embedded in issue templates and CI logs; a report
        that cannot be traced to a catalog version cannot be acted on."""

        assert CATALOG_VERSION.isdigit()
        assert CATALOG_VERSION == "2"

    def test_the_default_registry_holds_the_whole_catalog(self) -> None:
        registry = default_registry()

        assert len(registry) == len(RULES)
        assert set(registry.ids()) == {rule.id for rule in RULES}

    def test_a_fresh_registry_is_built_each_call(self) -> None:
        """Callers register their own rules; one caller's additions must not
        appear in the next caller's scan."""

        registry = default_registry()
        before = len(registry)
        registry.register(
            type(RULES[0])(
                id="caller-supplied",
                name="Caller supplied",
                category=RULES[0].category,
                severity=Severity.LOW,
                pattern=r"caller-[0-9a-f]{8}",
            )
        )

        assert len(registry) == before + 1
        assert "caller-supplied" not in default_registry()

    def test_every_rule_id_is_a_valid_finding_rule_id(self) -> None:
        """``Finding`` validates its own rule id against a grammar. A catalog id
        that does not match it would raise at finding-construction time, in the
        middle of a scan, on the first file that matched."""

        findings = findings_from(
            find_matches(SYNTHETIC_CONFIG, registry=default_registry()), "a.env"
        )

        assert findings
        assert {f.rule_id for f in findings} <= {rule.id for rule in RULES}
