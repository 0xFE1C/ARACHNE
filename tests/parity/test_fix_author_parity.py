"""Dual-engine parity for template-covered classes (S27, REQ-FIX-006).

REQ-FIX-006 lets AI-assisted authoring *extend* the template-based default, with parity
required wherever a template covers the class. These tests pin both halves of that rule: two
engines that agree produce the template's artifact with the agreement recorded, and two
engines that disagree produce **the template's artifact** — with the divergence recorded and
flagged, never substituted.

The second engine here is a stub, which is the point: the parity gate is a property of the
engine, not of a provider, so it is testable with no model configured (and a default
deployment configures none — see ``build_patch_author``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.fix.authoring import (
    AI_PARITY_DIVERGENCE,
    AiPatchAuthor,
    AuthorRequest,
    TemplateAuthor,
    change_set,
    parity_report,
    resolve_draft,
)
from arachne.fix.plans import FindingProfile, load_fix_plan_catalog

pytestmark = pytest.mark.parity

K8S_MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.internal/api:1.2.3
          securityContext:
            privileged: true
"""

#: The template's own artifact for the manifest above, as a diff. A second engine that
#: proposes the same change set is in parity; one that changes anything else is not.
EQUIVALENT_DIFF = """\
--- a/deploy/api.yaml
+++ b/deploy/api.yaml
@@ -6,4 +6,4 @@
       containers:
         - name: api
           image: registry.internal/api:1.2.3
           securityContext:
-            privileged: true
+            privileged: false
"""

DIVERGENT_DIFF = """\
--- a/deploy/api.yaml
+++ b/deploy/api.yaml
@@ -6,4 +6,5 @@
       containers:
         - name: api
           image: registry.internal/api:1.2.3
           securityContext:
-            privileged: true
+            privileged: false
+            readOnlyRootFilesystem: false
"""


def _request(tmp_path: Path) -> AuthorRequest:
    (tmp_path / "deploy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "deploy" / "api.yaml").write_text(K8S_MANIFEST, encoding="utf-8")
    catalog = load_fix_plan_catalog()
    selection = catalog.select(
        FindingProfile(check_key="M5/tfstate-exposure@1.1", rule="k8s-privileged")
    )
    assert selection.plan is not None
    return AuthorRequest(
        profile=FindingProfile(check_key="M5/tfstate-exposure@1.1", rule="k8s-privileged"),
        plan=selection.plan,
        root=tmp_path,
        targets=("deploy/api.yaml",),
        remediation_summary="Stop the container running privileged.",
    )


def test_a_covered_class_is_authored_by_the_template_with_no_second_engine(tmp_path: Path) -> None:
    outcome = resolve_draft(_request(tmp_path))
    assert outcome.draft is not None
    assert outcome.engine == "template"
    assert outcome.parity == "n/a"
    assert "privileged: false" in outcome.draft.diff
    assert outcome.flags == ()


def test_a_second_engine_that_agrees_is_recorded_and_the_template_artifact_is_used(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    ai = AiPatchAuthor(complete=lambda _request: EQUIVALENT_DIFF, name="stub-model")
    outcome = resolve_draft(request, template=TemplateAuthor(), ai=ai)
    assert outcome.draft is not None
    assert outcome.engine == "template", "the deterministic artifact is the artifact"
    assert outcome.parity == "ok"
    assert "agreed with the template" in outcome.parity_detail
    assert outcome.flags == ()


def test_a_second_engine_that_diverges_is_recorded_and_never_substituted(tmp_path: Path) -> None:
    request = _request(tmp_path)
    ai = AiPatchAuthor(complete=lambda _request: DIVERGENT_DIFF, name="stub-model")
    outcome = resolve_draft(request, template=TemplateAuthor(), ai=ai)
    assert outcome.draft is not None
    assert outcome.engine == "template"
    assert outcome.parity == "failed"
    assert AI_PARITY_DIVERGENCE in outcome.flags
    assert "readOnlyRootFilesystem" not in (outcome.draft.diff or "")
    assert "different lines" in outcome.parity_detail


def test_an_uncovered_class_is_only_authored_by_a_model_when_the_deployment_opts_in(
    tmp_path: Path,
) -> None:
    request = AuthorRequest(
        profile=FindingProfile(check_key="M1/exposed-dotfile@1.0", rule="env-file"),
        plan=None,
        root=tmp_path,
        targets=(),
    )
    ai = AiPatchAuthor(complete=lambda _request: EQUIVALENT_DIFF, name="stub-model")
    withheld = resolve_draft(request, ai=ai)
    assert withheld.draft is None
    assert withheld.engine == "none"
    assert withheld.parity == "not-covered"

    allowed = resolve_draft(request, ai=ai, allow_beyond_templates=True)
    assert allowed.draft is not None
    assert allowed.engine == "stub-model"
    assert allowed.parity == "not-covered"


def test_an_engine_that_declines_leaves_the_template_artifact_alone(tmp_path: Path) -> None:
    request = _request(tmp_path)
    ai = AiPatchAuthor(complete=lambda _request: None, name="stub-model")
    outcome = resolve_draft(request, template=TemplateAuthor(), ai=ai)
    assert outcome.draft is not None
    assert outcome.parity == "n/a"
    assert "no draft to compare" in outcome.parity_detail


# ------------------------------------------------------------------ change sets
def test_the_change_set_ignores_trailing_whitespace_and_hunk_shape() -> None:
    # The trailing spaces are the subject of this test, so they are built inside the
    # literals rather than left at the end of a source line.
    reordered = (
        "--- a/deploy/api.yaml\n"
        "+++ b/deploy/api.yaml\n"
        "@@ -1,8 +1,8 @@\n"
        "       containers:\n"
        "         - name: api\n"
        "           securityContext:\n"
        "-            privileged: true   \n"
        "+            privileged: false  \n"
    )
    left = change_set(EQUIVALENT_DIFF)
    right = change_set(reordered)
    assert left == right
    assert left["deploy/api.yaml"][0] == ("            privileged: false",)


def test_a_missing_file_is_a_difference() -> None:
    report = parity_report("", EQUIVALENT_DIFF)
    assert not report.equivalent
    assert report.differences and "only the second engine" in report.differences[0]


def test_a_reformatting_is_a_real_difference() -> None:
    reformatted = EQUIVALENT_DIFF.replace("            privileged: false", "\tprivileged: false")
    report = parity_report(EQUIVALENT_DIFF, reformatted)
    assert not report.equivalent
