"""Continuous exposure management (S23, area POSTURE).

From "scan" to "watch": this package holds the pure machinery the continuous mode is
built from, so the M5 check that collects it, the scheduler that budgets it, the CLI that
drives the fix-verification loop and the admission webhook that reuses the IaC policy
engine all share one vocabulary:

- :mod:`arachne.posture.state` — cloud-config snapshots (the normalized form the AWS /
  Azure / GCP read-only list responses are parsed into), the drift diff against the last
  baseline, and the posture policies evaluated over a snapshot.
- :mod:`arachne.posture.iac` — the pre-deploy policy engine for Kubernetes manifests
  (shared by the IaC gate and the admission webhook).
- :mod:`arachne.posture.verify` — the fix-verification loop (targeted re-scan → auto-close
  → auto-reopen, evidence linked to the original finding).
- :mod:`arachne.posture.trend` — the estate posture/trend report (executive-facing).
- :mod:`arachne.posture.admission` — the Kubernetes AdmissionReview evaluation
  (monitor by default, enforce opt-in with a staged namespace list).
- :mod:`arachne.posture.cmdb` — CMDB criticality import and the lookup index attack paths
  rank by.

Persistence lives beside the other stores (:mod:`arachne.data.posture_store`); this
package stays free of the data layer so its decisions are testable as pure functions.
"""
