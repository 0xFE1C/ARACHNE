"""The M4 support layer: applicability, probe URLs, classification and secret plumbing.

Two properties deserve their own tests because a mistake in them is invisible in a scan:

* **Applicability** — a check that claims a URL must not run on a bucket, and the bucket
  check must accept the three shapes an operator can declare.
* **Redaction plumbing** — an artifact carrying detector *names* survives evidence
  redaction, while a key that merely *sounds* sensitive (``secret_kinds``) would be blanked.
  This is why M4 uses ``detectors``, and the test pins that decision.
"""

from __future__ import annotations

from arachne.core.results import Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.m3.inventory import Page
from arachne.modules.m4.support import (
    BucketCheck,
    UrlCheck,
    is_denied,
    listing_entries,
    path_url,
    text_contains_any,
)


# --------------------------------------------------------------------------- applicability
class _UrlProbe(UrlCheck, Module):
    metadata = CheckMetadata(
        id="m4.url-probe",
        module="M4",
        name="url-probe",
        version="1.0",
        title="URL probe",
        description="A synthetic URL-scoped check.",
        research_ref="ch04#1",
        target_kinds=(TargetKind.URL,),
    )

    async def run(self, ctx):  # type: ignore[no-untyped-def]  # pragma: no cover
        yield ctx.info("stand-in")


class _BucketProbe(BucketCheck, Module):
    metadata = CheckMetadata(
        id="m4.bucket-probe",
        module="M4",
        name="bucket-probe",
        version="1.0",
        title="Bucket probe",
        description="A synthetic storage-scoped check.",
        research_ref="ch04#13",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
    )

    async def run(self, ctx):  # type: ignore[no-untyped-def]  # pragma: no cover
        yield ctx.info("stand-in")


def test_a_url_check_applies_only_to_http_urls() -> None:
    check = _UrlProbe()
    assert check.supports(Asset.from_meta("url", "https://example.com/"))
    assert check.supports(Asset.from_meta("url", "http://example.com/"))
    assert not check.supports(Asset.from_meta("url", "ftp://example.com/"))
    assert not check.supports(Asset.from_meta("domain", "example.com"))
    assert not check.supports(Asset.from_meta("cloud", "s3:example"))


def test_a_bucket_check_accepts_url_cloud_and_bucket_assets() -> None:
    check = _BucketProbe()
    assert check.supports(Asset.from_meta("url", "https://example.com/"))
    assert check.supports(Asset.from_meta("cloud", "s3:example-backup"))
    assert check.supports(Asset.from_meta("bucket", "https://example-backup.s3.amazonaws.com/"))
    assert not check.supports(Asset.from_meta("host", "example.com"))


# --------------------------------------------------------------------------- urls and text
def test_path_url_joins_without_doubling_or_dropping_the_slash() -> None:
    assert path_url("http://h:80", "/.env") == "http://h:80/.env"
    assert path_url("http://h:80/", "/.env") == "http://h:80/.env"
    assert path_url("http://h:80", "") == "http://h:80/"
    assert path_url("http://h:80/", "backup/db.sql") == "http://h:80/backup/db.sql"
    assert path_url("http://h:80", "https://other/x") == "https://other/x"


def test_text_contains_any_is_case_insensitive_and_returns_the_marker() -> None:
    assert text_contains_any("APP_KEY=abc", ("APP_KEY=",)) == "APP_KEY="
    assert text_contains_any("<title>index of /files</title>", ("<title>Index of",)) == (
        "<title>Index of"
    )
    assert text_contains_any("nothing here", ("APP_KEY=", "")) is None


def test_listing_entries_extracts_links_and_drops_outbound_ones() -> None:
    body = (
        "<a href='?C=N;O=D'>Name</a>"
        "<a href='/backup/'>backup/</a>"
        "<a href='dump.sql'>dump.sql</a>"
        "<a href='https://evil.example/x'>out</a>"
        "<a href='../up'>up</a>"
    )
    assert listing_entries(body) == ("/backup/", "dump.sql")
    assert listing_entries(body, limit=1) == ("/backup/",)


def test_is_denied_treats_auth_challenges_as_not_exposed() -> None:
    def page(status: int) -> Page:
        return Page(
            url="http://h/",
            status=status,
            headers={},
            body="x",
            content_type="text/plain",
            elapsed_ms=0,
        )

    assert is_denied(page(401)) and is_denied(page(403)) and is_denied(page(405))
    assert not is_denied(page(200)) and not is_denied(None)


# --------------------------------------------------------------------------- evidence
def test_detector_names_survive_evidence_redaction() -> None:
    """The artifact key choice is load-bearing: ``secret_kinds`` would be blanked."""
    safe = Evidence.of(
        "artifact",
        {"detectors": ["aws-access-key-id", "private-key"], "assignment_keys": ["DB_PASSWORD"]},
    )
    assert safe.payload["detectors"] == ["aws-access-key-id", "private-key"]
    assert safe.payload["assignment_keys"] == ["DB_PASSWORD"]
    # Documents the redactor's behaviour rather than approving it: a key named after a
    # secret is wiped wholesale, which is why M4 never names one that way.
    blanked = Evidence.of("artifact", {"secret_kinds": ["aws-access-key-id"]})
    assert blanked.payload["secret_kinds"] != ["aws-access-key-id"]
