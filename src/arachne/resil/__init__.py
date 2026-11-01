"""Resilience: offline content, autoscaling, disaster recovery (S25, area RESIL).

Four leaf concerns, deliberately kept out of ``core`` and ``data`` so each can be tested as
a pure function of its inputs:

* :mod:`arachne.resil.packs` — signed offline **content packs**: build one from a connected
  build, import one into an air-gapped estate, fail closed on anything whose signature or
  digest does not check out.
* :mod:`arachne.resil.autoscale` — the queue-depth → replica-count decision the scan farm
  autoscales on (REQ-RESIL-003). The Kubernetes objects that act on it ship in the Helm
  chart; this is the arithmetic, so it can be tested with a fake depth source.
* :mod:`arachne.resil.backup` — the disaster-recovery bundle: a complete, verified, signed
  snapshot of the evidence store (findings, evidence and their objects), the operator's keys
  and the deployment's non-secret configuration, with a restore path (REQ-RESIL-005).
* :mod:`arachne.resil.migrations` — the expand/contract checker that keeps a rolling upgrade
  possible: a migration set that narrows or drops something cannot be deployed without
  downtime, so the check fails before the rollout does (REQ-RESIL-002).

The package imports the data layer only for what genuinely needs it (the backup's store
access and the autoscaler's queue-depth source) and stays free of the API and the modules.
"""
