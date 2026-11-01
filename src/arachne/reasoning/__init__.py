"""Agentic reasoning: hypotheses, attack-path composition and the self-improvement loop (S21).

This package is the *reasoning* layer of area AGENT, deliberately separate from the distributed
``arachne.agent`` package (which is the fleet's worker role, S16). Nothing here executes a
request: :mod:`arachne.reasoning.model` is the vocabulary, :mod:`arachne.reasoning.heuristic`
and :mod:`arachne.reasoning.ai` propose, :mod:`arachne.reasoning.engine` selects between them
and degrades, :mod:`arachne.reasoning.executor` is the only thing that turns a proposal into
work (and only through the planner/orchestrator), :mod:`arachne.reasoning.step` wires it into
the pipeline, :mod:`arachne.reasoning.control` is the operator kill switch, and
:mod:`arachne.reasoning.replay` audits a run offline.

The modules are imported individually (``from arachne.reasoning.model import …``) rather than
re-exported here, so importing one never drags in the others — and so ``core.target`` can import
the hypothesis-mode vocabulary without importing the executor (which imports ``core.target``).
"""
