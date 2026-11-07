"""WP-29 · Source-control, CI and infrastructure artifacts (REQ-DET-022).

Twenty-four read-only L1 checks over the artifacts an over-exposed web root leaves reachable.
The requirement names eight scope areas and this module covers each with three checks:

* **DVCS artifacts and configuration** — the ``.git`` reflog, a DVCS configuration or
  credential store whose *content* carries credentials, and the legacy families
  (Bazaar, CVS, Fossil) the corpus does not otherwise reach;
* **CI pipeline definitions and the secrets they carry** — a GitHub Actions workflow, the
  other pipeline definitions (GitLab, Jenkins, Travis, CircleCI, Azure Pipelines, Bitbucket,
  Drone, AppVeyor, Woodpecker, Buildkite), and a pipeline definition whose own body carries
  credential material;
* **Terraform state and plan files** — the state file, the plan artifact, and the dependency
  lock state (``.terraform.lock.hcl``, the module manifest);
* **Cloud credential files** — the AWS credential file, the cloud CLIs' credential stores
  (gcloud application-default credentials, the Azure token cache) and cloud service-account
  keys;
* **Container and orchestration manifests** — a Compose file, a Dockerfile, and the
  Kubernetes/Helm/Rancher manifests a deployment publishes;
* **Editor swap and backup residue** — vim swap and Emacs autosave files, the ``~`` backup
  copies, and the operating-system metadata files (``.DS_Store``, ``Thumbs.db``,
  ``desktop.ini``, ``.directory``);
* **Credential and authorization files** — package-manager credential configuration
  (``.npmrc``, ``.pypirc``, ``.gem/credentials``, Maven/NuGet/pip), the container-registry
  credential configuration, and the authorization files (``.htaccess``,
  ``authorized_keys``);
* **Environment file variants** — the staging/dev/prod/ci environment variants the shipped
  ``m4.env-file-probe`` does not name, the secrets-file family
  (``.env.vault``, ``secrets.env``, ``secrets.yml``) and the framework configuration files
  that carry a secret inline (Django, .NET, Symfony, Rails).

**Read-only, and nothing else.** Every request is a ``GET``: no verb but ``GET`` appears
anywhere in this module, asserted structurally by ``tests/integration/test_wp29_scan.py``.
Nothing is uploaded, deleted, reconstructed or cloned. Detecting that ``.git`` is served is
the finding; cloning the repository is not this package's business, and the evidence carries
``history_mining: false`` to say so.

**The decoy is a refusal.** The requirement's decoy is a server that answers every artifact
path with a generic 404 or an error page, and that is what the fixture's two decoy modes
serve. No check fires on a status code: a signal is one of

1. a **marker from the artifact's own content** — ``terraform_version``, ``runs-on:``,
   ``services:``, ``[Desktop Entry]`` — never a word a refusal page carries;
2. the suffix being one the corpus declares **binary by nature** (``.tfplan``, ``.swp``,
   ``.ds_store``, ``.dirstate``) and the answer being a non-HTML 2xx, so a vim swap or a
   ``.DS_Store`` is reported without decoding a byte of it;
3. the **redactor's detector firing** on the served body, which only two checks require
   (``m4.git-credentials-exposed`` and ``m4.ci-pipeline-secret-exposed``): for those the
   claim *is* the credential, so a file that carries none must not fire.

**Secrets are redacted at capture, and the checks never see a value.** The HTTP client
redacts at capture time and reports which detectors fired (F-08-04); every check reads
``Page.secret_kinds`` and passes *names*, counts and key names into its artifact, never the
body it came from. ``tests/integration/test_wp29_scan.py`` drives the secret-bearing
fixtures end to end and asserts the planted value appears in no evidence payload.

**Nothing larger than the client's body limit is fetched to "confirm" an artifact.** Every
request goes through the shared scoped client, which reads at most ``body_limit`` bytes and
reports whether more existed; no check calls the raw-bytes entry point (``request_bytes``) or
decodes a binary body. A finding records ``captured_bytes``, ``truncated`` and the limit it
was read under, so the claim is checkable from the evidence.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page
from arachne.modules.m4.corpus import ArtifactProbe
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    finding_cap,
    http_or_skip,
    is_catchall_page,
    looks_like_not_found,
    m4_candidate,
    not_found_for,
    owns_origin,
    probe_paths,
    secrets_in,
    skip,
    text_contains_any,
)

__all__ = [
    "AppConfigSecretExposed",
    "ArtifactChecks",
    "AuthorizationFileExposed",
    "AwsCredentialFileExposed",
    "CiPipelineDefinitionExposed",
    "CiPipelineSecretExposed",
    "CloudCliCredentialExposed",
    "CloudServiceAccountKeyExposed",
    "ContainerComposeExposed",
    "DockerfileExposed",
    "EditorBackupResidueExposed",
    "EnvSecretFileExposed",
    "EnvVariantExposed",
    "GitCredentialsExposed",
    "GitReflogExposure",
    "GithubWorkflowExposed",
    "LegacyVcsMetadata",
    "OrchestrationManifestExposed",
    "OsMetadataResidueExposed",
    "PackageManagerCredentialExposed",
    "RegistryAuthExposed",
    "TerraformLockExposed",
    "TerraformPlanExposed",
    "TerraformStateExposed",
    "VimSwapExposed",
]

#: The family tag every artifact carries, so one heuristic rule can cover the whole set.
FAMILY = "infra-artifact"

#: The signal name every finding carries (the rules key on it, the way ``backup-download``
#: and ``vcs-exposure`` are keyed for the existing M4 families).
SIGNAL = "artifact-exposure"

#: The client's placeholder for a binary body (``core/http.py``, F-08-04): the bytes are never
#: decoded, so the count it names is the only record of how much was captured.
_BINARY_PLACEHOLDER_RE = re.compile(r"^\[binary payload: (\d+) bytes\]\Z")


def _meta(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
    compliance: tuple[str, ...] = (),
) -> CheckMetadata:
    """Build one check's metadata: L1, safe, read-only, default-on, URL-scoped.

    The family's contract is files.py's: a plain anonymous ``GET`` probe of a bounded path
    inventory, decided against the application's own not-found rendering. Every member is
    ``hybrid`` (it probes the origin and classifies the answer) and no member sets
    ``requires_active_checks``, because nothing here is beyond a plain ``GET``.

    The arguments are keyword-only on purpose. The research-coverage scanner
    (``modules/coverage.py``) attributes a ``research_ref`` to the nearest preceding
    ``id=``/``name=`` literal, so a factory whose check name is a *positional* argument hides
    it from the matrix — the defect WP-25 ... WP-28 recorded, where their factories' hits
    collapsed to the scanner's ``str``. Every call site here writes ``name=``, so the matrix
    names the check.
    """
    return CheckMetadata(
        id=f"m4.{name}",
        module="M4",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="hybrid",
        safe=True,
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        runs_on_discovered=True,
        target_kinds=(TargetKind.URL,),
    )


class _ArtifactCheck:
    """The shared shape: a bounded ``GET`` sweep of one corpus group, decided on content.

    A concrete check is declared ``class X(_ArtifactCheck, UrlCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. This is a plain mixin rather than a
    :class:`~arachne.modules.base.Module` subclass: the base refuses to be created without
    metadata and a family base has none of its own, which is the same reason M3's
    ``_ApiProbe`` is written this way.
    """

    metadata: ClassVar[CheckMetadata]
    #: The corpus group this check sweeps (``artifacts.groups.<group>``).
    group: ClassVar[str] = ""
    #: True for the two checks whose claim *is* the credential material: they fire only when
    #: the redactor's detector fired on the served body, never on a marker.
    detector_required: ClassVar[bool] = False
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "Infrastructure artifact served ({path})"

    def probes(self, ctx: CheckContext) -> tuple[ArtifactProbe, ...]:
        return corpus_for(ctx).artifact_probes(self.group)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        probes = self.probes(ctx)
        if not probes:
            yield skip(ctx, f"the M4 corpus names no artifact paths for group {self.group!r}")
            return
        not_found = await not_found_for(ctx, origin)
        binary_extensions = corpus.artifact_binary_extensions()
        min_bytes = corpus.artifact_min_bytes()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(
            ctx, origin, [item.path for item in probes], not_found=not_found
        ):
            page = probe.page
            if page is None or not 200 <= page.status < 300:
                continue
            if looks_like_not_found(page, not_found):
                continue
            if is_catchall_page(page, not_found=not_found, root=None):
                continue
            definition = next((item for item in probes if item.path == probe.path), None)
            markers = () if definition is None else definition.markers
            family = self.group if definition is None else definition.family
            marker = text_contains_any(page.body, markers)
            detectors = secrets_in(page)
            extension = _suffix_of(probe.path)
            binary_answer = (
                extension in binary_extensions
                and not page.content_type.lower().startswith(
                    ("text/html", "text/plain", "application/json")
                )
            )
            if self.detector_required:
                confirmed = bool(detectors)
            else:
                confirmed = bool(marker) or bool(detectors) or binary_answer
            if not confirmed:
                continue
            captured = _captured_bytes(page)
            if captured < min_bytes and not (binary_answer or marker):
                continue
            findings += 1
            artifact: dict[str, Any] = {
                "signal": SIGNAL,
                "family": FAMILY,
                "group": self.group,
                "artifact_family": family,
                "path": probe.path,
                "extension": extension,
                "status": page.status,
                "content_type": page.content_type,
                "content_family": "binary" if page.binary else "text",
                "marker": marker,
                "detectors": list(detectors),
                "binary": page.binary,
                "origin": origin,
                # The read bound the answer was captured under, so "nothing larger than the
                # client's body limit was fetched" is checkable from the evidence rather than
                # asserted: the bytes the client actually captured, and the cap it read under.
                "captured_bytes": captured,
                "body_limit": client.body_limit,
                "truncated": page.truncated,
                # Detecting that the artifact is served is the finding; nothing is
                # reconstructed, cloned or downloaded beyond the capture limit.
                "history_mining": False,
                "anonymous": True,
                "credential_test_sent": False,
            }
            yield m4_candidate(
                ctx,
                self.finding_title.format(path=probe.path.lstrip("/")),
                artifact=artifact,
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95 if (detectors or marker) else 0.8,
                detail=(
                    f"{probe.url} returned HTTP {page.status} "
                    f"({page.content_type or 'unknown type'}, {page.body_length} bytes"
                    f" of at most {client.body_limit})"
                    + (f"; marker: {marker!r}" if marker else "")
                    + (f"; detectors: {', '.join(detectors)}" if detectors else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                f"no {self.metadata.name.replace('-', ' ')} found",
                detail=f"probed {len(probes)} artifact path(s) on {origin}",
            )


def _suffix_of(path: str) -> str:
    """The path's lowercase suffix (``.tfplan``, ``.ds_store``), or ``""`` when it has none.

    Like ``files._extension_of``, but this family's inventories carry only single suffixes, so
    a split on the last dot is the whole rule; a suffix that would swallow a path separator
    (``/.DS_Store`` → ``.ds_store`` is fine, ``/a.b/c`` is not a suffix) yields ``""``.
    """
    lowered = path.split("?")[0].lower()
    head, dot, suffix = lowered.rpartition(".")
    return "" if not head or not dot or "/" in suffix else f".{suffix}"


def _captured_bytes(page: Page) -> int:
    """How many bytes the client actually captured for this answer.

    A text body's length is its length. A binary body is replaced, at capture, by a byte-count
    placeholder (F-08-04) — ``[binary payload: N bytes]`` — so its real captured size is the
    number the placeholder names, not the length of the placeholder. That number is what makes
    "the read stopped at the cap" checkable from the evidence.
    """
    if page.binary:
        match = _BINARY_PLACEHOLDER_RE.match(page.body)
        if match is not None:
            return int(match.group(1))
    return page.body_length


# --------------------------------------------------------------------------- DVCS artifacts
class GitReflogExposure(_ArtifactCheck, UrlCheck, Module):
    """``m4.git-reflog-exposure`` — the served ``.git`` reflog (ch04#2)."""

    group = "dvcs_reflog"
    finding_title = "Version-control reflog served ({path})"
    metadata = _meta(
        name="git-reflog-exposure",
        title="Version-control reflog served",
        description="Requests /.git/logs/HEAD and the per-branch reflog and reports one that is "
        "served. A reflog proves the repository's history is readable from the web "
        "root and names the branch movements, the commit identifiers and the committer "
        "identities of every local change. The finding reports the artifact path and "
        "the reflog action markers; it does "
        "not download objects and does not reconstruct history. Read-only GET probes.",
        research_ref="ch04#2",
        cwe="CWE-538",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.32", "ISO-A.8.12", "ISO-A.8.4"),
        severity="medium",
        estimated_requests=3,
    )


class GitCredentialsExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.git-credentials-exposed`` — a DVCS config or credential store with credentials."""

    group = "dvcs_credentials"
    detector_required = True
    finding_title = "Version-control credentials served ({path})"
    metadata = _meta(
        name="git-credentials-exposed",
        title="Credentials served in version-control configuration",
        description="Requests /.git/config and the credential-helper store and reports one whose "
        "own content carries credential material, which the client's redactor proves "
        "by reporting the detector that fired on the body. The finding names the path, "
        "the file family and the detector names; the credential value was redacted at "
        "capture time and never reaches the check. A configuration file that names a "
        "remote without credentials is "
        "not reported here. Read-only GET probes; nothing is cloned.",
        research_ref="ch04#2",
        cwe="CWE-538",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.5.32"),
        severity="high",
        estimated_requests=3,
    )


class LegacyVcsMetadata(_ArtifactCheck, UrlCheck, Module):
    """``m4.legacy-vcs-metadata`` — Bazaar/CVS/Fossil metadata on the web root."""

    group = "dvcs_legacy"
    finding_title = "Legacy version-control metadata served ({path})"
    metadata = _meta(
        name="legacy-vcs-metadata",
        title="Legacy version-control metadata served",
        description="Requests the metadata of the version-control systems a migration left behind "
        "— Bazaar's branch configuration, CVS's Entries and Root, Fossil's checkout "
        "database — and reports the ones served. Each is "
        "confirmed by its own content (a branch nick, a CVS path revision line, a "
        "SQLite payload, a pserver root), "
        "so a 404 or an error page is never the finding. Read-only GET probes.",
        research_ref="ch04#2",
        cwe="CWE-538",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.32", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- CI pipelines
class GithubWorkflowExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.github-workflow-exposed`` — a served GitHub Actions workflow (ch04#24)."""

    group = "ci_github_workflow"
    finding_title = "Continuous-integration workflow served ({path})"
    metadata = _meta(
        name="github-workflow-exposed",
        title="Continuous-integration workflow definition served",
        description="Requests the workflow definitions a repository keeps under .github/workflows "
        "and the Dependabot configuration, and reports the ones served. The finding is "
        "confirmed by the workflow document's own keys (a runner selector beside a job "
        "and a step list), so the deployment's refusal is not mistaken for a pipeline. "
        "The artifact names the path and the job keys; any credential the workflow "
        "carries is redacted at capture. "
        "Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.4"),
        severity="medium",
        estimated_requests=7,
    )


class CiPipelineDefinitionExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.ci-pipeline-definition-exposed`` — the other CI systems' definitions (ch04#24)."""

    group = "ci_pipeline_definition"
    finding_title = "Continuous-integration pipeline served ({path})"
    metadata = _meta(
        name="ci-pipeline-definition-exposed",
        title="Continuous-integration pipeline definition served",
        description="Requests the pipeline definitions of the other common CI systems — GitLab, "
        "Jenkins, Travis, CircleCI, Azure Pipelines, Bitbucket, Drone, AppVeyor, "
        "Woodpecker and Buildkite — and reports the ones served. Each is confirmed by "
        "that system's own document shape (a stage list, a declarative pipeline block, "
        "a step list with an image), which is what tells a published pipeline apart "
        "from the server's error page. "
        "Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.4"),
        severity="medium",
        estimated_requests=10,
    )


class CiPipelineSecretExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.ci-pipeline-secret-exposed`` — credential material inside a served pipeline."""

    group = "ci_pipeline_secret"
    detector_required = True
    finding_title = "Credential material in a served pipeline definition ({path})"
    metadata = _meta(
        name="ci-pipeline-secret-exposed",
        title="Credential material carried in a served pipeline definition",
        description="Requests the pipeline definitions a CI system reads and reports one whose own "
        "body carries credential material, which the client's redactor proves by "
        "reporting the detector that fired (a provider access key, a private key, a "
        "credentialed connection string). The finding names the path and the detector "
        "names; the value was redacted at capture time. A pipeline definition that "
        "carries no credential is not "
        "reported — it is the other check's finding. Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-798",
        framework=("WSTG-CONF-04", "CWE-798"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="high",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- Terraform
class TerraformStateExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.terraform-state-exposed`` — a served Terraform state file (ch04#24)."""

    group = "terraform_state"
    finding_title = "Terraform state file served ({path})"
    metadata = _meta(
        name="terraform-state-exposed",
        title="Terraform state file served",
        description="Requests the Terraform state file at the locations a deployment leaves it and "
        "reports one that is served. The state document is confirmed by its own "
        "structure (a Terraform format version beside a lineage identifier and a "
        "resource list), and it names every managed resource, its attributes and any "
        "credential a resource declaration stored. The finding reports the path and "
        "the document's key names; a "
        "value the redactor detected is reported by detector name only. Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.5.34"),
        severity="high",
        estimated_requests=6,
    )


class TerraformPlanExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.terraform-plan-exposed`` — a served Terraform plan artifact (ch04#24)."""

    group = "terraform_plan"
    finding_title = "Terraform plan artifact served ({path})"
    metadata = _meta(
        name="terraform-plan-exposed",
        title="Terraform plan artifact served",
        description="Requests the plan artifacts a pipeline writes beside the state and reports "
        "one that is served. A plan is recognised by the document's own format version "
        "and planned values, or — for the binary form, whose bytes are never decoded — "
        "by the declared plan suffix answered with a non-HTML type. A plan describes "
        "the next change to the infrastructure, which is what makes publishing it a "
        "disclosure rather than a "
        "curiosity. Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.5.34"),
        severity="high",
        estimated_requests=6,
    )


class TerraformLockExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.terraform-lock-exposed`` — Terraform dependency lock and module state."""

    group = "terraform_lock"
    finding_title = "Terraform dependency state served ({path})"
    metadata = _meta(
        name="terraform-lock-exposed",
        title="Terraform dependency lock state served",
        description="Requests the provider lock file and the module manifest a working directory "
        "keeps under .terraform and reports the ones served. Together they name every "
        "provider and module version the infrastructure is built from, which is the "
        "supply-chain inventory an attacker would otherwise have to guess. Confirmed "
        "by each file's own structure (provider blocks with constraints, a module list "
        "with sources and directories). "
        "Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.28"),
        severity="medium",
        estimated_requests=3,
    )


# --------------------------------------------------------------------------- cloud credentials
class AwsCredentialFileExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.aws-credential-file-exposed`` — the served AWS credential file (ch04#1)."""

    group = "cloud_aws_credentials"
    finding_title = "Cloud credential file served ({path})"
    metadata = _meta(
        name="aws-credential-file-exposed",
        title="Cloud provider credential file served",
        description="Requests the AWS credential file and configuration at the location the CLI "
        "and the SDKs read them and reports the ones served. The file is confirmed by "
        "its own keys (an access key identifier, a secret access key, a profile "
        "section) and the finding names the path, the profile names and the detectors "
        "that fired; the key values were "
        "redacted at capture time and never reach the check. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="high",
        estimated_requests=3,
    )


class CloudCliCredentialExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.cloud-cli-credential-exposed`` — the cloud CLIs' credential stores (ch04#1)."""

    group = "cloud_cli_credentials"
    finding_title = "Cloud CLI credential store served ({path})"
    metadata = _meta(
        name="cloud-cli-credential-exposed",
        title="Cloud CLI credential store served",
        description="Requests the credential stores the cloud command-line tools keep under the "
        "home directory — the Google Cloud application-default credentials and "
        "credentials file, and the Azure profile and token cache — and reports the "
        "ones served. Each is confirmed by its own document keys, and the finding "
        "names the path and the detector that fired where one did (a JSON web token in "
        "the token cache, a private key in a "
        "credential document): the values are redacted at capture time. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="high",
        estimated_requests=5,
    )


class CloudServiceAccountKeyExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.cloud-service-account-key-exposed`` — a served service-account key (ch04#15)."""

    group = "cloud_service_account_key"
    finding_title = "Cloud service-account key served ({path})"
    metadata = _meta(
        name="cloud-service-account-key-exposed",
        title="Cloud service-account key served",
        description="Requests the service-account key documents a deployment commonly leaves in "
        "the web root and reports the ones served. A key document is confirmed by its "
        "own fields (a service-account type, a key identifier, a client address), and "
        "the private half it carries is redacted at capture time — the finding reports "
        "the detector names, the "
        "path and the document's field names, never the key. Read-only GET probes.",
        research_ref="ch04#15",
        cwe="CWE-321",
        framework=("WSTG-CONF-04", "CWE-321"),
        compliance=("CIS-5.2", "ISO-A.5.17", "ISO-A.8.12"),
        severity="critical",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- containers
class ContainerComposeExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.container-compose-exposed`` — a served Compose manifest (ch04#24)."""

    group = "container_compose"
    finding_title = "Container composition manifest served ({path})"
    metadata = _meta(
        name="container-compose-exposed",
        title="Container composition manifest served",
        description="Requests the Compose manifests a service is deployed with and reports the "
        "ones served. The manifest is confirmed by its own keys (a services mapping "
        "beside an image reference and a container name), which is what distinguishes "
        "it from an ordinary YAML document. It names the services, their images and "
        "the environment each is given — including any connection string, whose value "
        "the redactor blanks at "
        "capture. Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.9"),
        severity="medium",
        estimated_requests=5,
    )


class DockerfileExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.dockerfile-exposed`` — a served container build definition (ch04#24)."""

    group = "container_dockerfile"
    finding_title = "Container build definition served ({path})"
    metadata = _meta(
        name="dockerfile-exposed",
        title="Container build definition served",
        description="Requests the Dockerfile at the paths a build leaves it and reports the ones "
        "served. The file is confirmed by its own instructions (a base image beside a "
        "build step and a working directory), so the server's refusal is not mistaken "
        "for it. A build definition names the base image and its version, the packages "
        "installed, the internal hosts a step reaches and any build argument a "
        "pipeline passed in. "
        "Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.28"),
        severity="low",
        estimated_requests=5,
    )


class OrchestrationManifestExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.orchestration-manifest-exposed`` — Kubernetes/Helm/Rancher manifests (ch04#24)."""

    group = "orchestration_manifest"
    finding_title = "Orchestration manifest served ({path})"
    metadata = _meta(
        name="orchestration-manifest-exposed",
        title="Orchestration manifest served",
        description="Requests the orchestration manifests a deployment publishes — Kubernetes "
        "Deployments and Secrets, Helm values files and a Rancher composition file — "
        "and reports the ones served. Each is confirmed by its own document shape (an "
        "API version beside a kind and a spec, or a values file's image and replica "
        "keys). The manifest names the workload's image, its replicas and its secret "
        "references; an inline "
        "connection string is redacted at capture. Read-only GET probes.",
        research_ref="ch04#24",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.9"),
        severity="medium",
        estimated_requests=8,
    )


# --------------------------------------------------------------------------- editor residue
class VimSwapExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.vim-swap-exposed`` — vim swap and Emacs autosave files (ch04#3)."""

    group = "editor_swap"
    finding_title = "Editor swap or autosave file served ({path})"
    metadata = _meta(
        name="vim-swap-exposed",
        title="Editor swap or autosave file served",
        description="Requests the hidden swap and autosave files an interrupted editing session "
        "leaves beside a file — vim's dot-prefixed .swp/.swo/.un~ siblings and Emacs's "
        "#file# and .#file forms — and reports the ones served. A swap file is the "
        "buffer's stored blocks, so it carries the file's contents as they were being "
        "edited, including any credential that was in it; it is recognised from the "
        "suffix and the answer's type, "
        "and its bytes are never decoded. Read-only GET probes.",
        research_ref="ch04#3",
        cwe="CWE-530",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "CWE-530"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.4"),
        severity="medium",
        estimated_requests=7,
    )


class EditorBackupResidueExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.editor-backup-residue-exposed`` — the ``~`` backup copies (ch04#3)."""

    group = "editor_backup_residue"
    finding_title = "Editor backup copy served ({path})"
    metadata = _meta(
        name="editor-backup-residue-exposed",
        title="Editor backup copy served",
        description="Requests the tilde-suffixed copies an editor writes on save and reports the "
        "ones served. The copy is confirmed by the content family of the file it backs "
        "up — a dotenv body, PHP source, a Python module — which is what makes it a "
        "copy of a real file rather than the not-found page's echo of the path. A "
        "backup copy of a configuration file carries the values the live file was "
        "changed to remove. "
        "Read-only GET probes.",
        research_ref="ch04#3",
        cwe="CWE-530",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "CWE-530"),
        compliance=("CIS-16.8", "ISO-A.8.12", "ISO-A.8.4"),
        severity="medium",
        estimated_requests=4,
    )


class OsMetadataResidueExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.os-metadata-residue-exposed`` — macOS/Windows/Freedesktop metadata files."""

    group = "editor_os_metadata"
    finding_title = "Operating-system metadata file served ({path})"
    metadata = _meta(
        name="os-metadata-residue-exposed",
        title="Operating-system metadata file served",
        description="Requests the metadata files a desktop operating system leaves in a directory "
        "that was uploaded or archived — .DS_Store, Thumbs.db, desktop.ini and "
        ".directory — and reports the ones served. Each is recognised from its own "
        "marker or from its declared binary suffix, never from the server's answer "
        "alone. These files name the directory's entries, which is a listing an "
        "operator did not intend to publish. "
        "Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("ISO-A.8.12", "ISO-A.5.32"),
        severity="low",
        estimated_requests=4,
    )


# --------------------------------------------------------------------------- credential files
class PackageManagerCredentialExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.package-manager-credential-exposed`` — npm/pypi/gem/maven credential config."""

    group = "credential_package_manager"
    finding_title = "Package-manager credential configuration served ({path})"
    metadata = _meta(
        name="package-manager-credential-exposed",
        title="Package-manager credential configuration served",
        description="Requests the credential configuration the package managers read (.npmrc, "
        ".yarnrc.yml, .pypirc, the RubyGems credential store, Maven's settings, "
        "NuGet's configuration and pip's configuration) and reports the ones served. "
        "Each is confirmed by its own keys — a registry host beside an auth-token key, "
        "a servers section with a password element, an index URL — which is what a "
        "refusal page cannot "
        "imitate. Any credential value is redacted at capture time. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=7,
    )


class RegistryAuthExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.registry-auth-exposed`` — the container-registry credential configuration."""

    group = "credential_registry_auth"
    finding_title = "Container-registry credential configuration served ({path})"
    metadata = _meta(
        name="registry-auth-exposed",
        title="Container-registry credential configuration served",
        description="Requests the Docker client's credential configuration at the locations it is "
        "read and reports the ones served. The document is confirmed by its own keys "
        "(a registries mapping whose entries carry an encoded credential or an "
        "identity token), and the finding names the file family and the detector that "
        "fired where one did; the encoded credential is redacted at capture time. A "
        "served registry credential lets a reader "
        "pull every private image the host can. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="high",
        estimated_requests=3,
    )


class AuthorizationFileExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.authorization-file-exposed`` — ``.htaccess``/``authorized_keys`` served."""

    group = "credential_authorization"
    finding_title = "Authorization file served ({path})"
    metadata = _meta(
        name="authorization-file-exposed",
        title="Authorization file served",
        description="Requests the authorization files a deployment writes — an Apache "
        "access-control file and the SSH authorized-keys files — and reports the ones "
        "served. Each is confirmed by its own directives (an authentication type "
        "beside a require rule, a public-key line, a host block), which is what tells "
        "the file apart from the server's own refusal. An authorized-keys file names "
        "the accounts and key types that may log in; the keys are public, and no "
        "private half is requested. Read-only GET "
        "probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.15", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=4,
    )


# --------------------------------------------------------------------------- env variants
class EnvVariantExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.env-variant-exposed`` — the environment-file variants beyond ``.env``."""

    group = "env_variant"
    finding_title = "Environment file variant served ({path})"
    metadata = _meta(
        name="env-variant-exposed",
        title="Environment file variant served",
        description="Requests the environment-file variants the shipped dotenv probe does not name "
        "— the staging, prod, dev, test, qa and ci forms, a layered production "
        "override and a local-suffixed name — and reports the ones served. A file is "
        "confirmed by the assignment keys an environment file carries (an application "
        "key beside a database password and a secret key), which is what a not-found "
        "page cannot imitate. The "
        "values were redacted at capture time. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-200",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-200"),
        compliance=("ISO-A.5.17", "ISO-A.5.34", "ISO-A.8.12"),
        severity="high",
        estimated_requests=8,
    )


class EnvSecretFileExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.env-secret-file-exposed`` — the secrets-file family."""

    group = "env_secret_file"
    finding_title = "Environment secrets file served ({path})"
    metadata = _meta(
        name="env-secret-file-exposed",
        title="Environment or secrets file served",
        description="Requests the files whose whole purpose is to hold secrets — the dotenv-vault "
        "documents and their key file, a secrets environment file, a Ruby secrets "
        "document and a credentials environment file — and reports the ones served. "
        "Each is confirmed by its own keys (a vault key, an access key identifier "
        "beside a database password, a secret key base), never by the status code. The "
        "values are redacted at capture "
        "time and the finding reports the key names and the detectors. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-538",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.5.34"),
        severity="high",
        estimated_requests=6,
    )


class AppConfigSecretExposed(_ArtifactCheck, UrlCheck, Module):
    """``m4.app-config-secret-exposed`` — framework configuration carrying a secret."""

    group = "app_config_secret"
    finding_title = "Application configuration file served ({path})"
    metadata = _meta(
        name="app-config-secret-exposed",
        title="Application configuration file served",
        description="Requests the framework configuration files a deployment leaves in the web "
        "root and reports the ones served — a Django settings module and its local "
        "override, the .NET app settings and web configuration, and a Symfony "
        "parameters file. Each is confirmed by its own keys (a secret key beside the "
        "database settings, a connection-strings section, a parameters mapping with a "
        "database password). The finding names the path "
        "and the key names; the values were redacted at capture time. Read-only GET probes.",
        research_ref="ch04#1",
        cwe="CWE-200",
        framework=("WSTG-CONF-04", "WSTG-INFO-05", "CWE-200"),
        compliance=("ISO-A.5.17", "ISO-A.5.34", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=6,
    )


#: Every WP-29 check, in the order the families appear above.
ArtifactChecks: tuple[type[Module], ...] = (
    GitReflogExposure,
    GitCredentialsExposed,
    LegacyVcsMetadata,
    GithubWorkflowExposed,
    CiPipelineDefinitionExposed,
    CiPipelineSecretExposed,
    TerraformStateExposed,
    TerraformPlanExposed,
    TerraformLockExposed,
    AwsCredentialFileExposed,
    CloudCliCredentialExposed,
    CloudServiceAccountKeyExposed,
    ContainerComposeExposed,
    DockerfileExposed,
    OrchestrationManifestExposed,
    VimSwapExposed,
    EditorBackupResidueExposed,
    OsMetadataResidueExposed,
    PackageManagerCredentialExposed,
    RegistryAuthExposed,
    AuthorizationFileExposed,
    EnvVariantExposed,
    EnvSecretFileExposed,
    AppConfigSecretExposed,
)

#: The eight scope areas the requirement names, each mapped to the groups it covers. Used by
#: the acceptance test to assert the family actually spans the requirement's scope.
GROUPS_BY_AREA: dict[str, tuple[str, ...]] = {
    "dvcs": ("dvcs_reflog", "dvcs_credentials", "dvcs_legacy"),
    "ci": ("ci_github_workflow", "ci_pipeline_definition", "ci_pipeline_secret"),
    "terraform": ("terraform_state", "terraform_plan", "terraform_lock"),
    "cloud-credentials": (
        "cloud_aws_credentials",
        "cloud_cli_credentials",
        "cloud_service_account_key",
    ),
    "containers": ("container_compose", "container_dockerfile", "orchestration_manifest"),
    "editor-residue": ("editor_swap", "editor_backup_residue", "editor_os_metadata"),
    "credential-files": (
        "credential_package_manager",
        "credential_registry_auth",
        "credential_authorization",
    ),
    "env-variants": ("env_variant", "env_secret_file", "app_config_secret"),
}
