"""The packaged data loaders parse their file once (REQ-QUAL-007).

Five loaders read a document that ships inside the package and is therefore a constant of the
installation: the remediation catalogue, the narrative templates, the rule corpus, the CVSS
vector table and the check catalogue. Each analysis phase builds its own analyzer, so one scan
parsed the catalogue twice and the rules and templates four times each. Profiling an M3 lab
scan put **2.8 s of its 3.2 s** in ``yaml.safe_load`` for exactly those five files.

Memoising the *shipped default* is safe for two reasons, and this module asserts both:

* the models the loaders return are frozen, so no caller can mutate a shared object;
* only the shipped default is cached — a caller that passes an explicit path gets a fresh
  parse every time, so a file rewritten between two calls is still re-read.

What is *not* asserted here is the wall clock: a timing assertion is flaky by nature. The
budget itself is asserted by ``tests/unit/test_quality_gates.py`` (the run's wall clock against
``ARACHNE_SUITE_BUDGET``) and by the CI job that sets it.
"""

from __future__ import annotations

import shutil
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

from arachne.analyzer.narrative import DEFAULT_NARRATIVE_RESOURCE, load_narrative_templates
from arachne.analyzer.remediation import (
    DEFAULT_REMEDIATION_RESOURCE,
    load_remediation_catalog,
)
from arachne.analyzer.rules import DEFAULT_RULES_RESOURCE, load_rule_set
from arachne.analyzer.scoring import DEFAULT_VECTOR_RESOURCE, load_vector_table
from arachne.core.catalog import load_catalog

#: ``(name, loader)`` for each packaged document, in the order the analysis phases load them.
_LOADERS: Final = (
    ("remediation catalogue", load_remediation_catalog),
    ("narrative templates", load_narrative_templates),
    ("rule corpus", load_rule_set),
    ("CVSS vector table", load_vector_table),
    ("check catalogue", load_catalog),
)


def _shipped(resource: tuple[str, ...]) -> Path:
    """The on-disk path of a packaged data document."""
    located: Any = files("arachne.templates")
    for part in resource:
        located = located.joinpath(part)
    return Path(str(located))


def test_the_shipped_defaults_are_parsed_once() -> None:
    """A second call hands back the identical object, not a second parse of the same file."""
    for name, loader in _LOADERS:
        first, second = loader(), loader()
        assert first is second, f"the {name} was parsed again instead of being reused"


def test_the_cached_models_are_frozen_so_sharing_them_is_safe() -> None:
    """The reason a shared object is safe: nothing can assign to it."""
    for name, loader in _LOADERS:
        model = loader()
        assert type(model).model_config.get("frozen") is True, (
            f"{name} is mutable, so caching it could hand one caller another's edit"
        )


def test_an_explicit_path_is_never_cached(tmp_path: Path) -> None:
    """A caller that names a file gets that file's current contents, every time."""
    source = _shipped(DEFAULT_RULES_RESOURCE)
    copy = tmp_path / source.name
    shutil.copyfile(source, copy)

    first = load_rule_set(str(copy))
    second = load_rule_set(str(copy))

    assert first is not second, "an explicit path must be re-read, not served from a cache"
    assert first == second, "and re-reading the same file must yield the same rules"


def test_the_four_resource_constants_still_resolve() -> None:
    """Negative control: the cache is not hiding a missing file behind a first success."""
    for resource in (
        DEFAULT_REMEDIATION_RESOURCE,
        DEFAULT_NARRATIVE_RESOURCE,
        DEFAULT_RULES_RESOURCE,
        DEFAULT_VECTOR_RESOURCE,
    ):
        assert _shipped(resource).is_file(), f"{resource} does not resolve inside the package"
