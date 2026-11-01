"""The agentic wiring the S21 tests share (area AGENT).

One factory, so every test builds the hypothesis step exactly the way the composition root does
— the orchestrator as the gate, the catalogued check index, the real rule corpus, the memory
stores the scan writes to — and only the things a test *wants* to vary (the mode, the budget,
the kill switch, the AI engine) are parameters.
"""

from __future__ import annotations

from typing import Any

from arachne.core.catalog import load_catalog
from arachne.core.lifecycle import StepHandler
from arachne.modules.context import ModuleConfig
from arachne.modules.registry import ModuleRegistry
from arachne.reasoning.control import MemoryHypothesisControl
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.step import build_hypothesis_step, load_rules

__all__ = ["HypothesisFactory", "hypothesis_factory", "lab_index"]


class HypothesisFactory:
    """Builds the ``hypothesis`` step for a test orchestrator, and keeps what it built."""

    def __init__(
        self,
        *,
        findings: Any,
        analyses: Any,
        settings: Any = None,
        registry: ModuleRegistry | None = None,
        control: MemoryHypothesisControl | None = None,
        index: CheckIndex | None = None,
        rules: Any = None,
        config: ModuleConfig | None = None,
        ai_engine: Any = None,
        ai_factory: Any = None,
    ) -> None:
        self.findings = findings
        self.analyses = analyses
        self.settings = settings
        self.registry = registry or ModuleRegistry.discover()
        self.control = control if control is not None else MemoryHypothesisControl()
        self.index = index or lab_index()
        self.rules = rules if rules is not None else load_rules(settings)
        self.config = config or ModuleConfig()
        self.ai_engine = ai_engine
        self.ai_factory = ai_factory
        #: The gate the step was built with (set when the factory is called).
        self.gate: Any = None
        self.handler: StepHandler | None = None

    def __call__(self, gate: Any) -> StepHandler:
        self.gate = gate
        self.handler = build_hypothesis_step(
            gate=gate,
            index=self.index,
            registry=self.registry,
            findings=self.findings,
            analyses=self.analyses,
            settings=self.settings,
            rules=self.rules,
            config=self.config,
            control=self.control,
            ai_engine=self.ai_engine,
            ai_factory=self.ai_factory,
        )
        return self.handler


def hypothesis_factory(**kwargs: Any) -> HypothesisFactory:
    """A factory for ``Orchestrator(hypothesis_factory=…)``."""
    return HypothesisFactory(**kwargs)


def lab_index() -> CheckIndex:
    """The shipped catalogue as a check index."""
    return CheckIndex.from_catalog(load_catalog())
