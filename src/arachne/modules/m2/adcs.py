"""``m2.adcs-enum`` — read-only Active Directory Certificate Services enumeration (REQ-DET-014).

AD CS is the most commonly abused privilege-escalation path in Active Directory, and the abuse
always starts the same way: reading the *configuration* and finding a template or a CA whose
settings a low-privileged principal can turn into an authentication certificate. ARACHNE stops
at the reading. This module enumerates the two AD CS object classes over LDAP and reports the
**conditions** associated with the published ESC classes as configuration findings.

**The boundary, stated once and enforced everywhere below.**

* Enumeration reads two LDAP object classes — ``pKICertificateTemplate`` and
  ``pKIEnrollmentService`` — and nothing else.
* **No request is ever made to the CA service.** No ``certsrv``/``ICertAdmin``/``ICertRequest``
  call, no Web-enrolment URL, no RPC to the CA. The CA's own configuration is read from the
  directory object it publishes, which is where the ESC6 flag lives.
* **No certificate is requested and no template is modified.** The module builds no modify,
  add, delete or extended LDAP operation, and issues no enrolment request of any kind.
* Every finding states the misconfiguration it read — for example "the template sets
  ``ENROLLEE_SUPPLIES_SUBJECT``" — and names the corresponding ESC class **as context**, never
  as a claim that the condition is exploitable here. Whether a given template is abusable
  depends on enrolment rights, the CA's policy and the attacker's position; that assessment is
  a human's, and inventing it from directory attributes would be guessing.
* Four ESC families are **not** decidable from the attributes this check reads (the ACL-based
  ESC4/ESC5/ESC7, the relay-based ESC8 and the mapping-based ESC9/ESC10 halves). They are named
  as not-assessed rather than silently omitted.

Credentials are mandatory. The enumeration binds as the credential the scan selected and, when
no credential is available or the bind is refused, it **skips**: AD CS cannot be enumerated
anonymously in a default domain (the objects are not readable by ``ANONYMOUS LOGON``), and
guessing is not an option.

**Transport limitation, stated rather than hidden.** The enumeration speaks plain LDAP
(389/3268-style cleartext binds). **LDAPS (636) is not implemented**: a domain that exposes the
directory only over TLS answers nothing to a cleartext bind, and the check reports that as "the
directory did not answer the LDAP bind" rather than inventing a handshake. The bind DN is the
credential's ``bind_dn`` extra field when the operator stored one and the credential's username
otherwise — never a guessed ``CN=<user>,CN=Users,<naming context>``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = [
    "ADCS_ESC_CONDITIONS",
    "ESC_CLASSES_NOT_ASSESSED",
    "NON_EXPLOITATION_NOTE",
    "AdcsEnumeration",
    "AdcsEnumerationResult",
    "AdcsObject",
    "EscCondition",
    "LdapAuthenticator",
    "esc_conditions_for",
]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)

#: The two object classes the enumeration reads, and nothing else (REQ-DET-014).
TEMPLATE_CLASS = "pKICertificateTemplate"
ENROLLMENT_SERVICE_CLASS = "pKIEnrollmentService"

#: The attributes read from each class. A fixed list is part of the boundary: the check cannot
#: wander into an object's security descriptor, private key or certificate blob.
TEMPLATE_ATTRIBUTES: tuple[str, ...] = (
    "objectClass",
    "cn",
    "displayName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-Template-Schema-Version",
    "pKIExtendedKeyUsage",
    "msPKI-Certificate-Application-Policy",
)
CA_ATTRIBUTES: tuple[str, ...] = (
    "objectClass",
    "cn",
    "dNSHostName",
    "flags",
    "certificateTemplates",
)

#: The AD CS container relative to the configuration naming context (read from the rootDSE).
PUBLIC_KEY_SERVICES = "CN=Public Key Services,CN=Services"

#: Extended key usages that carry the abuse potential.
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_ANY_PURPOSE = "1.3.6.1.4.1.311.10.3.12"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

#: ``msPKI-Certificate-Name-Flag`` bits.
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
#: ``msPKI-Enrollment-Flag`` bits.
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
#: ``flags`` on a ``pKIEnrollmentService`` (the CA object).
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

#: The ESC classes the LDAP attributes this check reads cannot decide, with the reason.
ESC_CLASSES_NOT_ASSESSED: tuple[tuple[str, str], ...] = (
    ("ESC4", "template write permissions live in the object's security descriptor"),
    ("ESC5", "CA/configuration object write permissions live in the security descriptor"),
    ("ESC7", "CA officer and manage-certificates rights live in the security descriptor"),
    ("ESC8", "HTTP enrolment endpoints are a service exposure, not a directory attribute"),
    ("ESC10", "certificate mapping is a registry policy, not a directory attribute"),
    ("ESC11", "ICPR encryption policy is a CA configuration setting, not a directory one"),
    ("ESC13", "issuance-policy linkage is a template-CA pairing, not a single attribute"),
)

#: The statement every AD CS finding and the per-scan note carry (REQ-DET-014).
NON_EXPLOITATION_NOTE = (
    "ARACHNE does not attempt exploitation. It read the published directory configuration "
    "only: no request was made to the CA service, no certificate was requested and no "
    "template was modified."
)


def _flags(attributes: Mapping[str, tuple[str, ...]], name: str) -> int:
    """The integer value of a flag attribute (LDAP delivers it as a decimal string)."""
    for value in attributes.get(name, ()):
        try:
            return int(str(value).strip())
        except ValueError:
            continue
    return 0


def _flag_set(attributes: Mapping[str, tuple[str, ...]], name: str, mask: int) -> bool:
    return bool(_flags(attributes, name) & mask)


def _ekus(attributes: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Every extended key usage a template declares, from either of the two attributes."""
    for name in ("pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy"):
        values = attributes.get(name, ())
        if values:
            return tuple(str(value).strip() for value in values if str(value).strip())
    return ()


def _client_auth_capable(ekus: Sequence[str]) -> bool:
    """True when the usage list can authenticate as a user: empty, client auth or Any Purpose."""
    if not ekus:
        return True
    return EKU_CLIENT_AUTH in ekus or EKU_ANY_PURPOSE in ekus


def _esc1(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    if not _flag_set(attributes, "msPKI-Certificate-Name-Flag", CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
        return None
    if not _client_auth_capable(_ekus(attributes)):
        return None
    return (
        "the template sets ENROLLEE_SUPPLIES_SUBJECT and its extended key usage permits client "
        "authentication, so a requester is allowed to choose the subject of a certificate the "
        "domain would accept for logon"
    )


def _esc2(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    ekus = _ekus(attributes)
    if ekus and EKU_ANY_PURPOSE not in ekus:
        return None
    return (
        "the template declares no extended key usage, or declares Any Purpose, so a certificate "
        "issued from it is not restricted to the purpose it was meant for"
    )


def _esc3(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    if EKU_CERTIFICATE_REQUEST_AGENT not in _ekus(attributes):
        return None
    return (
        "the template carries the Certificate Request Agent extended key usage, the enrolment-"
        "agent capability that lets its holder request certificates on another principal's behalf"
    )


def _esc9(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    if not _flag_set(attributes, "msPKI-Enrollment-Flag", CT_FLAG_NO_SECURITY_EXTENSION):
        return None
    return (
        "the template sets CT_FLAG_NO_SECURITY_EXTENSION, so the issued certificate carries no "
        "szOID_NTDS_CA_SECURITY_EXT object identifier and certificate mapping cannot tell two "
        "accounts with the same subject apart"
    )


def _esc15(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    schema = _flags(attributes, "msPKI-Template-Schema-Version")
    if schema != 1:
        return None
    if not _flag_set(attributes, "msPKI-Certificate-Name-Flag", CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
        return None
    return (
        "the template is schema version 1 and permits an enrollee-supplied subject, so the "
        "application-policy extension is not honoured the way a v2+ template's is"
    )


def _esc6(attributes: Mapping[str, tuple[str, ...]]) -> str | None:
    if not _flag_set(attributes, "flags", EDITF_ATTRIBUTESUBJECTALTNAME2):
        return None
    return (
        "the CA sets EDITF_ATTRIBUTESUBJECTALTNAME2, so it honours a SAN the requester supplies "
        "in the request rather than the one the template mandates"
    )


@dataclass(frozen=True, slots=True)
class EscCondition:
    """One ESC condition: the object class it applies to and the reader that decides it."""

    code: str
    object_class: str
    title: str
    #: The context sentence the finding carries — what the ESC class is, not a claim about this
    #: estate. The requirement is explicit that the class is context, not exploitability.
    context: str
    evaluate: Callable[[Mapping[str, tuple[str, ...]]], str | None]


#: Every condition this build can decide from the attributes listed above.
ADCS_ESC_CONDITIONS: tuple[EscCondition, ...] = (
    EscCondition(
        code="ESC1",
        object_class=TEMPLATE_CLASS,
        title="template permits an enrollee-supplied subject",
        context=(
            "ESC1 in the published AD CS taxonomy: a template whose subject is attacker-chosen "
            "and whose usage authenticates. Whether it is abusable here depends on the enrolment "
            "rights on the template and the CA's policy, which this check did not assess."
        ),
        evaluate=_esc1,
    ),
    EscCondition(
        code="ESC2",
        object_class=TEMPLATE_CLASS,
        title="template has no usage restriction",
        context=(
            "ESC2 in the published AD CS taxonomy: a template whose usage is Any Purpose (or "
            "absent). Exploitability depends on who may enrol, which this check did not assess."
        ),
        evaluate=_esc2,
    ),
    EscCondition(
        code="ESC3",
        object_class=TEMPLATE_CLASS,
        title="template grants the enrolment-agent capability",
        context=(
            "ESC3 in the published AD CS taxonomy: a template carrying the Certificate Request "
            "Agent usage. Whether it is abusable here depends on enrolment rights, not assessed."
        ),
        evaluate=_esc3,
    ),
    EscCondition(
        code="ESC9",
        object_class=TEMPLATE_CLASS,
        title="template issues certificates without the security extension",
        context=(
            "ESC9 in the published AD CS taxonomy: a template with no security extension, which "
            "matters only alongside a weak certificate mapping (not assessed — a registry "
            "setting, not a directory attribute)."
        ),
        evaluate=_esc9,
    ),
    EscCondition(
        code="ESC15",
        object_class=TEMPLATE_CLASS,
        title="schema-version-1 template permits an enrollee-supplied subject",
        context=(
            "ESC15 in the published AD CS taxonomy: a v1 template with an enrollee-supplied "
            "subject. Whether it is abusable here depends on the CA's policy, not assessed."
        ),
        evaluate=_esc15,
    ),
    EscCondition(
        code="ESC6",
        object_class=ENROLLMENT_SERVICE_CLASS,
        title="CA honours a requester-supplied subject alternative name",
        context=(
            "ESC6 in the published AD CS taxonomy: a CA with EDITF_ATTRIBUTESUBJECTALTNAME2. "
            "Whether it is abusable here depends on which templates are enabled, not assessed."
        ),
        evaluate=_esc6,
    ),
)


def esc_conditions_for(
    object_class: str, attributes: Mapping[str, tuple[str, ...]]
) -> tuple[tuple[EscCondition, str], ...]:
    """``((condition, explanation), ...)`` for one enumerated object."""
    found: list[tuple[EscCondition, str]] = []
    for condition in ADCS_ESC_CONDITIONS:
        if condition.object_class != object_class:
            continue
        explanation = condition.evaluate(attributes)
        if explanation:
            found.append((condition, explanation))
    return tuple(found)


@dataclass(frozen=True, slots=True)
class AdcsObject:
    """One enumerated AD CS object: its class, its DN, its name and the attributes read."""

    object_class: str
    dn: str
    name: str
    attributes: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class AdcsEnumerationResult:
    """What one credentialed bind-and-search produced — the parsed, non-secret enumeration."""

    config_dn: str = ""
    #: The domain naming context the rootDSE published (context for the report, not a secret).
    default_dn: str = ""
    objects: tuple[AdcsObject, ...] = ()
    truncated: bool = False
    problems: tuple[str, ...] = ()


# --------------------------------------------------------------------------- the transport
class LdapAuthenticator:
    """The LDAP bind and the two AD CS searches, driven by the broker with the material.

    Implements :class:`arachne.creds.broker.Authenticator`: the broker calls :meth:`attempt`
    once with the username and password and gets back a verdict. Two pipelined exchanges, each
    a single ``client.tcp`` call:

    1. ``BindRequest`` then the rootDSE read, in one write. The configuration naming context
       must be known before the AD CS search can be built, so the rootDSE read has to complete
       first.
    2. ``BindRequest`` then one subtree search filtered
       ``(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService))`` under
       ``CN=Public Key Services,CN=Services,<configNC>``.

    Pipelining a bind with the operations that follow it is what RFC 4511 §4.2.1 allows and
    requires: "while a BindRequest is in progress, the server MUST NOT process any other LDAP
    operations on the connection", so the search is evaluated *after* the bind as the
    authenticated identity. One write per connection is also the only shape the scan's scoped
    network client offers, and routing these bytes through it is what keeps the scope gate,
    the rate limiter and the audit trail in force.
    """

    protocol = "ldap"

    def __init__(self, client: Any, service: ServiceRecord) -> None:
        self.client = client
        self.service = service
        self.endpoint = service.key or f"{service.host}:{service.port}"
        #: The parsed enumeration the last attempt produced (never a credential).
        self.enumeration: AdcsEnumerationResult | None = None
        #: Every exchange the attempt made, for the finding's evidence.
        self.exchanges: tuple[Any, ...] = ()

    async def attempt(
        self, username: str, password: str, extra: Mapping[str, str] | None = None
    ) -> Any:
        from arachne.creds.broker import ProtocolAuthResult

        # The bind DN is what LDAP authenticates: the credential's ``bind_dn`` extra field when
        # the operator stored one, else the credential's username verbatim. A bare account name
        # is **not** expanded into a guessed DN — building ``CN=<user>,CN=Users,<guessed NC>``
        # is the guessing the requirement forbids, and a refused bind is the honest answer.
        bind_dn = str((extra or {}).get("bind_dn") or username)
        host, port = self.service.host, self.service.port
        rootdse_payload = wire.build_ldap_bind_request(
            1, bind_dn, password
        ) + wire.build_ldap_search(
            2,
            "",
            scope=wire.LDAP_SCOPE_BASE,
            attributes=(
                "configurationNamingContext",
                "defaultNamingContext",
                "supportedLDAPVersion",
            ),
        )
        rootdse_exchange = await self.client.tcp(host, port, payload=rootdse_payload, reads=4)
        self.exchanges = (rootdse_exchange,)
        messages = wire.iter_ldap_messages(rootdse_exchange.banner)
        bind_response = next((message for message in messages if message.is_bind_response), None)
        if bind_response is None:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name="NO_BIND_RESPONSE",
                detail="the directory did not answer the LDAP bind",
                exchanges=self.exchanges,
            )
        if not bind_response.accepted:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name=wire.ldap_result_text(bind_response.result_code),
                detail=(
                    "the directory refused the bind "
                    f"({wire.ldap_result_text(bind_response.result_code)})"
                ),
                exchanges=self.exchanges,
            )
        rootdse = next((message for message in messages if message.is_search_entry), None)
        config_dn = (
            rootdse.attribute("configurationNamingContext")[0]
            if rootdse and rootdse.attribute("configurationNamingContext")
            else ""
        )
        problems: list[str] = []
        if not config_dn:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=True,
                status_name="NO_CONFIGURATION_CONTEXT",
                detail=(
                    "the bind succeeded but the rootDSE published no configurationNamingContext, "
                    "so the AD CS containers have no base to search from"
                ),
                exchanges=self.exchanges,
            )

        base = f"{PUBLIC_KEY_SERVICES},{config_dn}"
        adcs_filter = wire.ldap_filter_or(
            [
                wire.ldap_filter_present(TEMPLATE_CLASS),
                wire.ldap_filter_present(ENROLLMENT_SERVICE_CLASS),
            ]
        )
        search_payload = wire.build_ldap_bind_request(
            1, bind_dn, password
        ) + wire.build_ldap_search(
            2,
            base,
            scope=wire.LDAP_SCOPE_SUBTREE,
            attributes=(*TEMPLATE_ATTRIBUTES, *CA_ATTRIBUTES),
            filter_body=adcs_filter,
        )
        search_exchange = await self.client.tcp(host, port, payload=search_payload, reads=8)
        self.exchanges = (rootdse_exchange, search_exchange)
        replies = wire.iter_ldap_messages(search_exchange.banner)
        done = next((message for message in replies if message.is_search_done), None)
        entries = tuple(message for message in replies if message.is_search_entry)
        if done is not None and done.result_code != 0:
            problems.append(
                f"the AD CS search returned {wire.ldap_result_text(done.result_code)}: the bound "
                "identity may not read the container"
            )
        truncated = done is not None and done.result_code == 4  # sizeLimitExceeded
        objects = tuple(
            AdcsObject(
                object_class=_object_class(entry),
                dn=entry.object_name,
                name=(entry.attribute("cn") or ("",))[0],
                attributes=dict(entry.attributes),
            )
            for entry in entries
        )
        self.enumeration = AdcsEnumerationResult(
            config_dn=config_dn,
            default_dn=(
                rootdse.attribute("defaultNamingContext")[0]
                if rootdse and rootdse.attribute("defaultNamingContext")
                else ""
            ),
            objects=objects,
            truncated=truncated,
            problems=tuple(problems),
        )
        return ProtocolAuthResult(
            protocol=self.protocol,
            endpoint=self.endpoint,
            attempted=True,
            accepted=True,
            status_name="SUCCESS",
            detail=f"the directory accepted the bind; {len(objects)} AD CS object(s) enumerated",
            exchanges=self.exchanges,
        )


def _object_class(entry: wire.LdapMessage) -> str:
    """The AD CS class of an entry, from its ``objectClass`` values (a case-insensitive match)."""
    classes = {value.strip().lower() for value in entry.attribute("objectClass")}
    if TEMPLATE_CLASS.lower() in classes:
        return TEMPLATE_CLASS
    if ENROLLMENT_SERVICE_CLASS.lower() in classes:
        return ENROLLMENT_SERVICE_CLASS
    return ""


class AdcsEnumeration(NetworkCheck, Module):
    """``m2.adcs-enum`` — read-only AD CS template and CA enumeration over LDAP."""

    metadata = CheckMetadata(
        id="m2.adcs-enum",
        module="M2",
        name="adcs-enum",
        version="1.0",
        title="Active Directory Certificate Services misconfiguration (read-only)",
        description=(
            "Binds to the directory with the scan's selected LDAP credential and enumerates two "
            "AD CS object classes — pKICertificateTemplate and pKIEnrollmentService — under the "
            "configuration naming context, then reports the configuration conditions associated "
            "with the published ESC classes (a template that permits an enrollee-supplied "
            "subject, an unrestricted usage, an enrolment-agent usage, a missing security "
            "extension, a v1 schema, or a CA that honours a requester-supplied subject "
            "alternative name). The ESC class is named as context, never as a claim of "
            "exploitability. ARACHNE does not attempt exploitation: no request reaches the CA "
            "service, no certificate is requested and no template is modified. Read-only, "
            "credentialed, and skipped when no credential is available."
        ),
        research_ref="ch02#18",
        framework=("WSTG-CONF-01", "WSTG-ATHZ-03", "CWE-269"),
        cwe="CWE-269",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        requires_credentials=("ldap",),
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        broker = ctx.credentials
        if broker is None:
            yield ctx.skipped(
                "no credential capability in this step: AD CS enumeration needs an LDAP "
                "credential selected for the scan (AD CS objects are not readable anonymously)"
            )
            return
        client, skipped = net_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert client is not None
        inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None

        services = _ldap_services(ctx)
        if not services:
            yield ctx.skipped(
                f"no LDAP service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish it first)"
            )
            return

        for service in services:
            authenticator = LdapAuthenticator(client, service)
            result = await broker.authenticate(authenticator, host=service.host, port=service.port)
            if not result.attempted:
                yield ctx.skipped(f"no LDAP credential for {service.key}: {result.detail}".strip())
                continue
            service.probes += len(authenticator.exchanges)
            enumeration = authenticator.enumeration
            if enumeration is None:
                yield ctx.info(
                    f"AD CS enumeration on {service.key} did not complete",
                    detail=(
                        f"the directory answered {result.status_name}: {result.detail}. "
                        f"{NON_EXPLOITATION_NOTE}"
                    ),
                    evidence=[_exchange_evidence(service, authenticator.exchanges)],
                    confidence=0.8,
                )
                continue
            service.notes["adcs"] = {
                "config_dn": enumeration.config_dn,
                "objects": len(enumeration.objects),
                "truncated": enumeration.truncated,
            }
            async for item in self._report(ctx, service, authenticator, enumeration):
                yield item

    async def _report(
        self,
        ctx: CheckContext,
        service: ServiceRecord,
        authenticator: LdapAuthenticator,
        enumeration: AdcsEnumerationResult,
    ) -> AsyncIterator[CheckResult]:
        """The findings, then the coverage note: what was read and what was not assessed."""
        evidence = [_exchange_evidence(service, authenticator.exchanges)]
        found = 0
        for item in enumeration.objects:
            if not item.object_class:
                continue
            for condition, explanation in esc_conditions_for(item.object_class, item.attributes):
                found += 1
                yield ctx.candidate(
                    f"AD CS {condition.code} condition: {condition.title} ({item.name or item.dn})",
                    detail=(
                        f"{item.object_class} {item.dn}: {explanation}. The condition is the "
                        f"published ESC class {condition.code} — named as context, not as a "
                        f"claim that it is exploitable in this estate. {condition.context} "
                        f"{NON_EXPLOITATION_NOTE}"
                    ),
                    confidence=0.7,
                    evidence=[
                        _condition_evidence(service, item, condition, explanation),
                        *evidence,
                    ],
                )
        yield ctx.info(
            f"AD CS enumeration on {service.key}: {len(enumeration.objects)} object(s) read, "
            f"{found} configuration condition(s)",
            detail=(
                f"base {PUBLIC_KEY_SERVICES} under {enumeration.config_dn}"
                + (f" (domain {enumeration.default_dn})" if enumeration.default_dn else "")
                + f"; classes read: {TEMPLATE_CLASS}, {ENROLLMENT_SERVICE_CLASS}. "
                "Not assessed (not decidable from the attributes read): "
                + "; ".join(f"{code} — {why}" for code, why in ESC_CLASSES_NOT_ASSESSED)
                + f". {NON_EXPLOITATION_NOTE}"
                + (
                    " The search hit its size limit, so the enumeration is partial."
                    if enumeration.truncated
                    else ""
                )
                + (" " + " ".join(enumeration.problems) if enumeration.problems else "")
            ),
            evidence=evidence,
            confidence=0.9,
        )


def _ldap_services(ctx: CheckContext) -> tuple[ServiceRecord, ...]:
    """The LDAP services this asset has (fingerprinted by the earlier M2 checks)."""
    catalog = port_catalog_for(ctx)
    wanted = {389, 636}
    wanted.update(catalog.ports_for_probe("ldap"))
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() in {"ldap", "ldaps", "ldapssl"}:
            matches.append(service)
            continue
        if service.port in wanted:
            matches.append(service)
    return tuple(matches)


def _exchange_evidence(service: ServiceRecord, exchanges: Sequence[Any]) -> Evidence:
    """The redacted exchanges the attempt produced, as one evidence item."""
    return Evidence.of(
        "banner",
        {
            "service": service.key,
            "port": service.port,
            "protocol": "ldap",
            "operation": "search",
            "responses": len(exchanges),
            "bytes": [len(getattr(item, "banner", b"") or b"") for item in exchanges],
        },
        source=f"ldap://{service.key}",
    )


def _condition_evidence(
    service: ServiceRecord,
    item: AdcsObject,
    condition: EscCondition,
    explanation: str,
) -> Evidence:
    """The finding's machine-readable artifact: the condition, its ESC class and the context.

    ``context`` and ``esc_class`` are explicit fields so a reader (and a test) can check that
    the class is named *as context*; ``exploitation_attempted`` is always false, which is the
    requirement's "ARACHNE does not attempt exploitation" stated where a consumer reads it.
    """
    return Evidence.of(
        "artifact",
        {
            "signal": "adcs-esc-condition",
            "esc_class": condition.code,
            "context": condition.context,
            "condition": explanation,
            "object_class": item.object_class,
            "dn": item.dn,
            "name": item.name,
            "exploitation_attempted": False,
            # REQ-DET-014: the report carries this note explicitly, on the finding itself.
            "note": NON_EXPLOITATION_NOTE,
            "attributes": {key: list(values) for key, values in item.attributes.items()},
        },
        source=f"ldap://{service.key}/{item.dn}",
    )
