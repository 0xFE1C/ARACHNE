"""M5 · Cloud, Container & Supply Chain .

M5 answers "what did we leave reachable, and what are we building from?" It is the module that
most often needs something *other* than the target's web surface: a cloud reference (read-only),
a repository clone, an image/registry reference, or an exposure-visible service (a bucket, a
dashboard, a metadata endpoint). The checks split into three groups:

========================================  ==========  ==========================================
check                                      ref         what it establishes
========================================  ==========  ==========================================
``m5.bucket-enumerator``                   ch05#2      public S3/GCS/Azure bucket listing/ACL
``m5.firebase-rules``                      ch05#7      Firebase project with open rules
``m5.supabase-rls``                        ch05#8      PostgREST table readable without RLS
``m5.tfstate-exposure``                    ch05#11-12  committed/served state + IaC review
``m5.k8s-exposure``                        ch05#13-14  anonymous kubelet API / dashboard
``m5.registry-scan``                       ch05#15     anonymous registry catalog
``m5.docker-socket``                       ch05#16     reachable Docker daemon API/socket
``m5.leaked-cloud-keys``                   ch05#3      cloud credentials in artifacts
``m5.gcp-sa-keys``                         ch05#6      GCP service-account key material
``m5.image-history-secrets``               ch05#17     secrets in Dockerfiles/manifests
``m5.cicd-audit``                          ch05#23     CI/CD pipeline supply-chain risk
``m5.dep-confusion``                       ch05#24     dependency-confusion candidates
``m5.sbom-review``                         ch05#25     known-vulnerable components
``m5.iam-review``                          ch05#1      IAM over-privilege / escalation paths
``m5.imds-ssrf``                           ch05#4      metadata service via an SSRF sink
``m5.azure-mi-audit``                      ch05#5      Azure managed-identity metadata
``m5.serverless-functions``                ch05#9      unauthenticated function endpoint
``m5.managed-datastores``                  ch05#20     reachable managed DB console/proxy
``m5.search-platform-exposure``            ch05#21     anonymous Elasticsearch/Kibana
``m5.cloud-posture``                       ch05#1      continuous cloud-config posture + drift
========================================  ==========  ==========================================

**Numbering.** As for M1-M4, ``research_ref`` values are the canonical method numbers of
``docs/research/05-cloud-and-supply-chain.md`` and the check **ids** are the corpus's; the
spec table's refs drift from the corpus after ``imds-ssrf``, and ADR-S10-3 records the
reconciliation.

**Safety** : read-only cloud calls with a documented permission list;
bucket/registry probes non-destructive; repo/pipeline analysis on **local clones only**. The two
metadata checks are off by default on top of the active-checks gate (``ARACHNE_M5_IMDS_PROBE``);
credential validation is off by default (``ARACHNE_M5_VALIDATE_CLOUD_KEYS``) and uses only a
configured key; the external image scanner is off by default (``ARACHNE_M5_REGISTRY_SCAN`` /
``ARACHNE_M5_SBOM_TOOL``). Nothing in M5 is destructive: no object write, no image push, no
account change, no alias claim.
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m5.cloud import (
    AzureMiAudit,
    BucketEnumerator,
    GcpSaKeys,
    IamReview,
    ImdsSsrf,
    LeakedCloudKeys,
)
from arachne.modules.m5.cloud_posture import CloudPosture
from arachne.modules.m5.hardening import (
    ManagedDatastores,
    SearchPlatformExposure,
    ServerlessFunctions,
)
from arachne.modules.m5.platform import (
    DockerSocket,
    FirebaseRules,
    K8sExposure,
    RegistryScan,
    SupabaseRls,
    TfstateExposure,
)
from arachne.modules.m5.supply import (
    CicdAudit,
    DepConfusion,
    ImageHistorySecrets,
    SbomReview,
)
from arachne.modules.registry import ModuleGroup

__all__ = ["M5", "M5_CHECKS"]

#: Every M5 check, in run order: the read-only artifact reviews first (they cost nothing and
#: make the default posture useful), then the endpoint probes, then the two opt-in metadata
#: checks last.
M5_CHECKS: tuple[type[Module], ...] = (
    LeakedCloudKeys,
    GcpSaKeys,
    IamReview,
    CloudPosture,
    CicdAudit,
    DepConfusion,
    SbomReview,
    ImageHistorySecrets,
    TfstateExposure,
    BucketEnumerator,
    FirebaseRules,
    SupabaseRls,
    K8sExposure,
    RegistryScan,
    DockerSocket,
    ServerlessFunctions,
    ManagedDatastores,
    SearchPlatformExposure,
    ImdsSsrf,
    AzureMiAudit,
)

#: The M5 module group . Bump the version when the set or a check's
#: behaviour changes: scan reports record it (F-02-10).
M5 = ModuleGroup(
    id="M5",
    title="Cloud, Container & Supply Chain",
    description=(
        "Cloud misconfiguration, container/orchestration exposure, IaC and CI/CD hygiene, and "
        "dependency/supply-chain risk: public buckets, open Firebase/Supabase rules, exposed "
        "Terraform state and IaC misconfiguration, anonymous kubelet/dashboard/Docker/registry "
        "endpoints, secrets in images and pipelines, dependency-confusion candidates, "
        "known-vulnerable components, IAM over-privilege, the cloud metadata services "
        "reachable through an SSRF sink, and the continuous cloud-config posture/drift watch. "
        "Read-only throughout; repo/pipeline analysis runs on local clones only."
    ),
    version="1.1.0",
    research_chapter="ch05",
    checks=M5_CHECKS,
)
