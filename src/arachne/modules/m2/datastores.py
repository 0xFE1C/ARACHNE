"""Datastore exposure probing: DBMS handshakes and NoSQL/cache stores (ch02#22-23).

Research method 22 fingerprints database wire protocols (MySQL, PostgreSQL, MSSQL) to learn
product and version; method 23 detects *unauthenticated* datastores (Redis, MongoDB,
Elasticsearch, CouchDB, memcached), which are the exposure class that turns a network
finding into an immediate data-theft incident.

Where the line is drawn, because it matters for the safety framing of docs/spec/05-:

* **Read-only, protocol-level.** Every probe here is the smallest exchange the protocol
  defines for "who are you?" — the MySQL/MSSQL/PostgreSQL handshake, Redis ``PING``,
  memcached ``stats``, the MongoDB ``isMaster``/``hello`` handshake, an unauthenticated HTTP
  ``GET /`` on Elasticsearch/CouchDB. None of them writes, mutates or runs a command.
* **No credential verification.** Empty-password and default-credential attempts are
  research ch02#22's *next* step and a separate, opt-in check (F-01-09); they are out of
  scope for M2. A datastore that answers ``NOAUTH`` is reported as authenticated, not
  attacked.
* **Exposure is the finding.** "A database answered on a network-reachable port" and "the
  store let us read its metadata without any credential" are the two findings this check
  raises; their severity is the analyzer's call (ADR-02).

The HTTP-native stores (Elasticsearch, CouchDB, and anything on a JSON API) are probed
through the shared :class:`~arachne.core.http.ScopedHttpClient` — the same scoped,
rate-limited, redacted, audited path every other HTTP check uses (ADR-05) — while the
binary protocols go through the network client.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceIdentity, ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = ["DATASTORE_PROTOCOLS", "DbServiceProbe"]

#: Protocol identities this check investigates (and the HTTP-native ones it probes over HTTP).
DATASTORE_PROTOCOLS: frozenset[str] = frozenset(
    {"mysql", "postgres", "mssql", "oracle", "redis", "memcached", "mongodb"}
)

#: Ports of the HTTP-native datastores (Elasticsearch, CouchDB, Kibana, InfluxDB, ...).
HTTP_DATASTORE_PORTS: dict[int, str] = {
    9200: "elasticsearch",
    9201: "elasticsearch",
    5984: "couchdb",
    5601: "kibana",
    8086: "influxdb",
    15672: "rabbitmq",
    27017: "mongodb-http",
}


class DbServiceProbe(NetworkCheck, Module):
    """``m2.db-service-probe`` — DBMS fingerprinting + NoSQL exposure (ch02#22-23)."""

    metadata = CheckMetadata(
        id="m2.db-service-probe",
        module="M2",
        name="db-service-probe",
        version="1.0",
        title="Database service probing",
        description=(
            "Fingerprints database wire protocols (MySQL, PostgreSQL, MSSQL) for product and "
            "version, and establishes whether Redis, memcached, MongoDB, Elasticsearch or "
            "CouchDB answer without authentication by reading their metadata endpoints "
            "read-only. No credential is submitted and no data is modified."
        ),
        research_ref="ch02#22-23",
        cwe="CWE-284",
        target_kinds=(*target_kinds_for_network_probes(), TargetKind.URL),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        datastore_ports = {
            entry.port
            for entry in catalog.tcp
            if entry.probe
            in {"mysql", "postgres", "mssql", "oracle", "redis", "memcached", "mongodb"}
        }
        candidates = [
            service
            for service in services_of(inventory, ctx.asset)
            if service.protocol == "tcp"
            and (
                service.effective_service.lower() in DATASTORE_PROTOCOLS
                or service.port in datastore_ports
                or service.port in HTTP_DATASTORE_PORTS
            )
        ]
        if not candidates:
            yield ctx.skipped(
                f"no datastore service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in candidates:
            protocol = service.effective_service.lower()
            if protocol in HTTP_DATASTORE_PORTS.values() or service.port in HTTP_DATASTORE_PORTS:
                async for result in self._http_store(ctx, service):
                    yield result
                continue
            if protocol == "redis" or service.port == 6379:
                async for result in self._redis(ctx, client, service):
                    yield result
                continue
            if protocol == "memcached" or service.port == 11211:
                async for result in self._memcached(ctx, client, service):
                    yield result
                continue
            if protocol == "mongodb" or service.port in {27017, 27018}:
                async for result in self._mongodb(ctx, client, service):
                    yield result
                continue
            if protocol == "mysql" or service.port == 3306:
                async for result in self._mysql(ctx, client, service):
                    yield result
                continue
            if protocol == "postgres" or service.port == 5432:
                async for result in self._postgres(ctx, client, service):
                    yield result
                continue
            if protocol == "mssql" or service.port == 1433:
                async for result in self._mssql(ctx, client, service):
                    yield result
                continue
            # An open port whose catalogue entry is a database but which did not identify:
            # report the exposure without inventing a product.
            evidence = [_service_evidence(ctx, service, {"probe": "not attempted"})]
            yield ctx.candidate(
                f"database port {service.port} is reachable on {service.host}",
                detail=(
                    f"The port catalogue names port {service.port} as a database service and the "
                    "port is open, but no probe in the identification suite recognised it. An "
                    "unauthenticated handshake was therefore not attempted; the exposure itself "
                    "(a database port reachable from the scanning position) is the finding."
                ),
                confidence=0.5,
                evidence=evidence,
            )

    # ------------------------------------------------------------------ noSQL / cache
    async def _redis(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        ping = await client.tcp(
            service.host, service.port, payload=wire.redis_command("PING"), reads=1
        )
        service.probes += 1
        reply = wire.parse_redis_reply(ping.banner)
        if reply is None:
            yield ctx.clean(
                f"no Redis reply from {service.key}",
                evidence=[
                    _service_evidence(ctx, service, {"response": ping.banner_text(limit=128)})
                ],
                confidence=0.4,
            )
            return
        facts: dict[str, Any] = {"ping": reply.value, "needs_auth": reply.needs_auth}
        if reply.needs_auth:
            facts["authentication"] = "required"
            _apply_identity(service, product="redis", version=None, banner=reply.value)
            yield ctx.info(
                f"Redis on {service.key} requires authentication",
                detail=f"PING answered {reply.value!r}, so the instance is not open.",
                evidence=[_service_evidence(ctx, service, facts)],
                confidence=0.9,
            )
            return
        info = await client.tcp(
            service.host, service.port, payload=wire.redis_command("INFO", "server"), reads=1
        )
        service.probes += 1
        version = _redis_version(info.banner_text(limit=4096))
        facts.update({"info_server": info.banner_text(limit=512), "version": version})
        facts["authentication"] = "not required"
        _apply_identity(
            service, product="redis", version=version, banner="+PONG without authentication"
        )
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"Redis {version or 'unknown version'} on {service.key}",
            detail="PING answered without a credential; INFO server was readable.",
            evidence=evidence,
            confidence=0.95,
        )
        yield ctx.candidate(
            f"unauthenticated Redis instance on {service.host}:{service.port}",
            detail=(
                f"Redis answered PING with {reply.value!r} and served INFO without any "
                "authentication"
                + (f" (version {version})" if version else "")
                + ". An unauthenticated Redis is directly exploitable for data theft and, on "
                "typical deployments, for command execution through its persistence and module "
                "surfaces (research ch02#23)."
            ),
            confidence=0.95,
            evidence=evidence,
        )

    async def _memcached(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        stats_exchange = await client.tcp(
            service.host, service.port, payload=wire.memcached_stats(), reads=1
        )
        service.probes += 1
        stats = wire.memcached_values(stats_exchange.banner_text(limit=8192))
        if not stats:
            yield ctx.clean(
                f"no memcached stats from {service.key}",
                evidence=[
                    _service_evidence(
                        ctx, service, {"response": stats_exchange.banner_text(limit=256)}
                    )
                ],
                confidence=0.4,
            )
            return
        version = stats.get("version")
        _apply_identity(
            service, product="memcached", version=version, banner="stats without authentication"
        )
        facts = {
            "version": version,
            "curr_connections": stats.get("curr_connections"),
            "uptime": stats.get("uptime"),
            "authentication": "not required",
        }
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"memcached {version or 'unknown version'} on {service.key}",
            detail="stats was served without a credential.",
            evidence=evidence,
            confidence=0.9,
        )
        yield ctx.candidate(
            f"unauthenticated memcached instance on {service.host}:{service.port}",
            detail=(
                "memcached has no authentication by design, so anything reachable on this port "
                "is readable and writable by anyone who can reach it. Version "
                f"{version or 'unknown'}; "
                f"{stats.get('curr_connections', '?')} active connection(s)."
            ),
            confidence=0.9,
            evidence=evidence,
        )

    async def _mongodb(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        exchange = await client.tcp(
            service.host, service.port, payload=wire.mongo_ismaster_probe(), reads=1
        )
        service.probes += 1
        handshake = wire.parse_mongo_ismaster(exchange.banner)
        if handshake is None:
            yield ctx.clean(
                f"no MongoDB handshake from {service.key}",
                evidence=[
                    _service_evidence(ctx, service, {"response": exchange.banner_text(limit=256)})
                ],
                confidence=0.4,
            )
            return
        facts: dict[str, Any] = {
            "version": handshake.version,
            "max_wire_version": handshake.max_wire_version,
            "auth_error": handshake.auth_error,
            "authentication": "required" if handshake.auth_error else "not required",
        }
        _apply_identity(
            service,
            product="mongodb",
            version=handshake.version,
            banner="isMaster handshake",
        )
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"MongoDB {handshake.version or 'unknown version'} on {service.key}",
            detail=f"isMaster answered; authentication {facts['authentication']}.",
            evidence=evidence,
            confidence=0.9,
        )
        if handshake.auth_error is None:
            yield ctx.candidate(
                f"MongoDB on {service.host}:{service.port} answered without authentication",
                detail=(
                    "The isMaster handshake succeeded with no credential, which is the state "
                    "that exposes an entire database to anyone who can reach the port "
                    "(research ch02#23)."
                ),
                confidence=0.85,
                evidence=evidence,
            )

    # ------------------------------------------------------------------ HTTP-native
    async def _http_store(
        self, ctx: CheckContext, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        http = ctx.http
        if http is None:
            yield ctx.skipped(
                f"no HTTP client in this run: cannot probe the JSON API of {service.key}"
            )
            return
        scheme = "https" if service.port in {9201, 5601} else "http"
        base = f"{scheme}://{service.host}:{service.port}"
        try:
            root = await http.get(base + "/")
        except Exception as exc:  # a refused probe is data, not a crash
            yield ctx.clean(
                f"{service.key} did not answer an HTTP request ({exc.__class__.__name__})",
                evidence=[_service_evidence(ctx, service, {"error": str(exc)[:200]})],
                confidence=0.3,
            )
            return
        document = root.json_body()
        version: str | None = None
        product = service.service or "http-datastore"
        extra: dict[str, Any] = {"status": root.status_code}
        if isinstance(document, dict):
            version_info = document.get("version")
            if isinstance(version_info, dict):
                version = str(version_info.get("number") or "") or None
            elif isinstance(version_info, str):
                version = version_info
            if "couchdb" in document:
                product = "couchdb"
                version = version or str(document.get("version") or "") or None
            if "name" in document and not product:
                product = str(document["name"])
            extra["banner"] = {
                key: document[key]
                for key in ("name", "cluster_name", "couchdb", "tagline", "version")
                if key in document
            }
        _apply_identity(
            service,
            product=product,
            version=version,
            banner=f"{product} {version or ''}".strip(),
        )
        facts = {"status": root.status_code, "product": product, "version": version, **extra}
        evidence = [
            ctx.evidence(
                "http_response",
                {
                    "url": root.url,
                    "status_code": root.status_code,
                    "headers": root.response_headers,
                    "body": root.body[:2048],
                },
                source=service.key,
            ),
            _service_evidence(ctx, service, facts),
        ]
        indexes: tuple[str, ...] = ()
        if product == "elasticsearch":
            indexes = await self._elastic_indexes(http, base, ctx, service)
            facts["indexes"] = list(indexes)
        elif product == "couchdb":
            indexes = await self._couch_databases(http, base, ctx, service)
            facts["databases"] = list(indexes)
        yield ctx.info(
            f"{product} {version or ''} on {service.key}".strip(),
            detail=(
                f"HTTP {root.status_code} from the service root"
                + (f"; {len(indexes)} index/database name(s) readable" if indexes else "")
            ),
            evidence=evidence,
            confidence=0.9 if version else 0.6,
        )
        if root.ok:
            yield ctx.candidate(
                f"unauthenticated {product} API on {service.host}:{service.port}",
                detail=(
                    f"GET {base}/ returned HTTP {root.status_code} without any credential"
                    + (
                        f", and the index/database list was readable: {', '.join(indexes[:8])}"
                        if indexes
                        else ""
                    )
                    + ". An open search/document API is a direct data-exposure finding "
                    "(research ch02#23)."
                ),
                confidence=0.85,
                evidence=evidence,
            )

    async def _elastic_indexes(
        self, http: Any, base: str, ctx: CheckContext, service: ServiceRecord
    ) -> tuple[str, ...]:
        try:
            response = await http.get(base + "/_cat/indices?format=json&h=index")
        except Exception:
            return ()
        service.probes += 1
        document = response.json_body()
        if not isinstance(document, list):
            return ()
        names: list[str] = []
        for item in document[:50]:
            if isinstance(item, dict) and item.get("index"):
                names.append(str(item["index"]))
        del ctx
        return tuple(names)

    async def _couch_databases(
        self, http: Any, base: str, ctx: CheckContext, service: ServiceRecord
    ) -> tuple[str, ...]:
        try:
            response = await http.get(base + "/_all_dbs")
        except Exception:
            return ()
        service.probes += 1
        document = response.json_body()
        if not isinstance(document, list):
            return ()
        del ctx
        return tuple(str(item) for item in document[:50])

    # ------------------------------------------------------------------ DBMS handshakes
    async def _mysql(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        exchange = await client.tcp(service.host, service.port)
        service.probes += 1
        greeting = wire.parse_mysql_greeting(exchange.banner)
        if greeting is None:
            yield ctx.clean(
                f"no MySQL greeting from {service.key}",
                evidence=[
                    _service_evidence(ctx, service, {"response": exchange.banner[:64].hex()})
                ],
                confidence=0.4,
            )
            return
        _apply_identity(
            service,
            product="mysql",
            version=greeting.version,
            banner=f"MySQL {greeting.version}",
        )
        facts = {
            "version": greeting.version,
            "protocol_version": greeting.protocol_version,
            "auth_plugin": greeting.auth_plugin,
        }
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"MySQL {greeting.version} on {service.key}",
            detail=(
                f"handshake protocol {greeting.protocol_version}"
                + (f"; default auth plugin {greeting.auth_plugin}" if greeting.auth_plugin else "")
                + "; no credential was submitted (that is an opt-in check, F-01-09)"
            ),
            evidence=evidence,
            confidence=0.9,
        )
        yield ctx.candidate(
            f"database service exposed on {service.host}:{service.port}",
            detail=(
                f"A MySQL server ({greeting.version}) accepts connections from the scanning "
                "position. Exposed database ports belong on an application subnet; the exposure "
                "is the finding (research ch02#22; deduplicated against M4's db-exposure check "
                "by CWE)."
            ),
            confidence=0.7,
            evidence=evidence,
        )

    async def _postgres(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        ssl_exchange = await client.tcp(
            service.host, service.port, payload=wire.postgres_ssl_request(), reads=1
        )
        service.probes += 1
        ssl_supported = ssl_exchange.banner[:1] == b"S"
        startup = await client.tcp(
            service.host, service.port, payload=wire.postgres_startup(), reads=1
        )
        service.probes += 1
        reply = wire.parse_postgres_message(startup.banner)
        facts: dict[str, Any] = {
            "tls_supported": ssl_supported,
            "reply_type": reply.type if reply else None,
            "sqlstate": reply.code if reply else None,
            "message": reply.message if reply else None,
        }
        _apply_identity(
            service,
            product="postgresql",
            version=service.version,
            banner="PostgreSQL startup/SSL negotiation",
        )
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"PostgreSQL on {service.key}",
            detail=(
                f"SSLRequest answered {'S (TLS available)' if ssl_supported else 'N or nothing'}; "
                f"startup message answered {reply.message if reply else 'nothing'}"
            ),
            evidence=evidence,
            confidence=0.85,
        )
        yield ctx.candidate(
            f"database service exposed on {service.host}:{service.port}",
            detail=(
                "A PostgreSQL server answers the startup handshake from the scanning position"
                + ("" if ssl_supported else " and refused TLS (SSLRequest answered N)")
                + ". The server's version string is not part of its startup error, so no version "
                "is claimed here (research ch02#22)."
            ),
            confidence=0.7,
            evidence=evidence,
        )

    async def _mssql(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        exchange = await client.tcp(service.host, service.port, payload=_tds_prelogin(), reads=1)
        service.probes += 1
        info = wire.parse_mssql_prelogin(exchange.banner)
        if info is None:
            yield ctx.clean(
                f"no TDS PRELOGIN response from {service.key}",
                evidence=[
                    _service_evidence(ctx, service, {"response": exchange.banner[:64].hex()})
                ],
                confidence=0.4,
            )
            return
        _apply_identity(
            service,
            product="microsoft sql server",
            version=info.get("version"),
            banner=f"TDS {info.get('version', '')}".strip(),
        )
        facts = dict(info)
        evidence = [_service_evidence(ctx, service, facts)]
        yield ctx.info(
            f"Microsoft SQL Server {info.get('version', 'unknown')} on {service.key}",
            detail=f"PRELOGIN: {facts}",
            evidence=evidence,
            confidence=0.9,
        )
        yield ctx.candidate(
            f"database service exposed on {service.host}:{service.port}",
            detail=(
                f"A Microsoft SQL Server ({info.get('version', 'version unknown')}) answers TDS "
                "PRELOGIN from the scanning position; encryption is "
                f"{info.get('encryption', 'unspecified')}."
            ),
            confidence=0.7,
            evidence=evidence,
        )
        if info.get("encryption") in {"off", "not supported", "0"}:
            yield ctx.candidate(
                f"SQL Server on {service.key} accepts connections without encryption",
                detail=(
                    "The PRELOGIN ENCRYPTION token reports encryption off/unsupported, so "
                    "credentials and query traffic are not protected in transit (CWE-319)."
                ),
                confidence=0.7,
                evidence=evidence,
            )


# --------------------------------------------------------------------------- helpers
def _tds_prelogin() -> bytes:
    """The TDS PRELOGIN request (same construction as the fingerprinter's)."""
    from arachne.modules.m2.fingerprint import _tds_prelogin as build

    return build()


def _service_evidence(ctx: CheckContext, service: ServiceRecord, facts: dict[str, Any]) -> Evidence:
    return ctx.evidence(
        "note",
        {"service": service.evidence_payload(), "facts": facts},
        source=service.key,
    )


def _apply_identity(
    service: ServiceRecord, *, product: str, version: str | None, banner: str
) -> None:
    current = service.identity
    if current is not None and current.versioned and version is None:
        return
    service.identity = ServiceIdentity(
        protocol=current.protocol if current and current.protocol != "unknown" else product,
        product=product or (current.product if current else None),
        version=version or (current.version if current else None),
        banner=banner or (current.banner if current else ""),
        confidence=0.9,
        extra=dict(current.extra) if current else {},
    )


def _redis_version(text: str) -> str | None:
    for line in text.splitlines():
        if line.lower().startswith("redis_version:"):
            return line.split(":", 1)[1].strip()
    return None


def protocols_probed() -> Sequence[str]:
    """The protocol identities this check claims (used by tests and reporting)."""
    return tuple(sorted(DATASTORE_PROTOCOLS))
