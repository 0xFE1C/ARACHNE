"""M6 · Automation, AI-Era & Post-Exploit Signals .

M6 answers two things the other modules do not: "is something *already* wrong inside what we
host?" (a planted webshell, a committed secret, a leaked CI token) and "what does the AI-era
attack surface and exploit-readiness picture look like?" (GenAI endpoints, EPSS/KEV correlation,
post-exploit telemetry). Its evidence is mostly files and logs rather than HTTP responses, and
its default posture is offline: it reads what the scan already has and never takes a
post-exploitation action .

========================================  ===========  ============================================
check                                      ref          what it establishes
========================================  ===========  ============================================
``m6.webshell-yara``                       ch06#24      webshell sig+behaviour (PHP2SHELL)
``m6.attack-surface-genai``                ch06#14-15   model endpoints, prompts, agent configs
``m6.secret-scan-at-scale``                ch06#8       committed credentials incl. git history
``m6.ci-secret-leak``                      ch06#23      credentials leaked into CI logs/artifacts
``m6.cve-epss-correlation``                ch06#7       patch-gap view ranked by EPSS/KEV
``m6.lpe-discovery``                       ch06#16      version-based local-privesc CVE matching
``m6.sigma-hunt-rules``                    ch06#18-23   post-exploit Sigma rules + log ingest
``m6.deception-listeners``                 ch06#25      honeytoken trigger monitoring (opt-in)
``m6.ad-attack-path``                      ch06#19      read-only AD escalation paths (opt-in)
========================================  ===========  ============================================

**Numbering.** As for M1-M5, ``research_ref`` values are the canonical method numbers of
``docs/research/06-correlation-and-detection.md`` (the universe G-01 counts) and the
check **ids** are the corpus's; the
spec table gives ``m6.ci-secret-leak`` and ``m6.sigma-hunt-rules`` the same ch06#23, which
ADR-S11.4 records. ``m6.sigma-hunt-rules`` cites the ``ch06#18-23`` range because the rules it
ships encode those discovery methods (Kerberoasting, ticket abuse, lateral movement, persistence,
Sigma hunting).

**Safety** . File-read-only throughout: the webshell scan reads
files and served content (GET-only) and never uploads or evaluates anything; the secret/CI scans
only read; the AD check parses an export and never authenticates; nothing performs a
post-exploitation action. The telemetry checks require an explicit log-access grant
(``ARACHNE_M6_LOG_ACCESS``) and the deception and AD checks are opt-in
(``enabled_by_default=False``, deception also needs ``ARACHNE_M6_DECEPTION``).
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m6.exposure import CveEpssCorrelation, LpeDiscovery
from arachne.modules.m6.genai import AttackSurfaceGenai
from arachne.modules.m6.hardening import CredentialHunt, ExploitMatch, TemplateScan
from arachne.modules.m6.hunting import AdAttackPath, DeceptionListeners, SigmaHuntRules
from arachne.modules.m6.secrets import CiSecretLeak, SecretScanAtScale
from arachne.modules.m6.webshell import WebshellYara
from arachne.modules.registry import ModuleGroup

__all__ = ["M6", "M6_CHECKS"]

#: Every M6 check, in run order: the read-only artifact scans first (they cost nothing and make
#: the default posture useful), then the served-surface scan, then the estate correlations, then
#: the log-hunting check, then the two opt-in checks last.
M6_CHECKS: tuple[type[Module], ...] = (
    SecretScanAtScale,
    CiSecretLeak,
    CveEpssCorrelation,
    LpeDiscovery,
    WebshellYara,
    AttackSurfaceGenai,
    SigmaHuntRules,
    DeceptionListeners,
    AdAttackPath,
    TemplateScan,
    ExploitMatch,
    CredentialHunt,
)

#: The M6 module group . Bump the version when the set or a check's
#: behaviour changes: scan reports record it (F-02-10).
M6 = ModuleGroup(
    id="M6",
    title="Automation, AI-Era & Post-Exploit Signals",
    description=(
        "Signs that a target is on the receiving end of automated/AI-era attacks or has been "
        "post-exploited, plus hygiene over the automation ecosystem: webshell signature and "
        "behaviour scanning (PHP2SHELL class), GenAI attack-surface review (exposed model "
        "endpoints, prompt hygiene, agent configs), CVE/EPSS correlation and patch-gap "
        "analysis, repository/git-history and CI-log secret scanning, post-exploit Sigma hunt "
        "rules with an opt-in log-ingest path, local-privilege-escalation CVE matching, "
        "read-only AD attack-path analysis and honeytoken trigger monitoring. File-read-only "
        "throughout; nothing performs a post-exploitation action."
    ),
    version="1.0.0",
    research_chapter="ch06",
    checks=M6_CHECKS,
)
