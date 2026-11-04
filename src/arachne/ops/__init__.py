"""Operations surface: the service-level objectives and the artefacts generated from them.

REQ-OPS-007 asks for SLOs, error budgets and alerts "as code". This package is the code:
:mod:`arachne.ops.slo` reads the in-repo definitions under ``deploy/observability/slos/``,
checks every metric they name against the families ``GET /metrics`` actually exposes, and
generates the burn-rate alert rules from the same definitions, so the alert and the
objective cannot disagree.

The module is imported as ``arachne.ops.slo`` rather than re-exported here: it is also a
command (``python -m arachne.ops.slo --check``), and a parent package that imports it would
have it in ``sys.modules`` twice under the ``-m`` entry point.
"""
