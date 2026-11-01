# Chapter 2 — Active Scanning and Enumeration

The M2 surface: what is listening, what it is, and which version it runs. Methods 1–13 are
discovery and fingerprinting (L1, read-only); 14–28 are per-protocol enumeration, each of
which reads a banner, a share list or a directory rather than changing anything; 29 correlates
what was learned against vulnerability data. Method 11 is deliberately un-implemented: a
stateless wide sweep is an availability risk out of proportion to its benefit for an
authorised, scoped scan.

## Methods

### 1. Host discovery and liveness probing

Deciding which of a scoped address set is up, so later stages send traffic only to live hosts.

### 2. ICMP and TCP ping sweep

Liveness probing with echo requests and with TCP handshakes to commonly-open ports, because
many estates filter ICMP.

### 3. ARP and link-layer discovery

On a directly attached segment, resolving which addresses are present at the link layer.

### 4. TCP connect port scanning

Enumerating open TCP ports with full handshakes, which needs no raw socket and is what a
scoped scan should prefer.

### 5. SYN-style port enumeration

The half-open variant, for when the scan is authorised to use raw sockets and volume matters.

### 6. UDP service probing

Probing the UDP ports that carry discoverable services (SNMP, SSDP, mDNS, NTP), where absence
of a reply is not evidence of absence.

### 7. Port-state change detection

Diffing port state between scans, because a newly open port is a stronger signal than a
long-open one.

### 8. Operating-system fingerprinting

Inferring the platform from TCP/IP stack behaviour, to scope which host-level checks apply.

### 9. Service banner grabbing

Reading the greeting a service offers, which is often the cheapest and most accurate version
signal available.

### 10. Application protocol fingerprinting

Recognising the protocol on a port regardless of the port number, so a service on an
unexpected port is still identified as itself.

### 11. Masscan-scale stateless sweeping

Internet-scale stateless scanning. Not implemented: the throughput that makes it useful is
the same throughput that makes it an availability risk, and it cannot honour a per-host
rate budget.

### 12. HTTP server fingerprinting

Identifying the web server, its modules and its framework from headers, error pages and
default content.

### 13. HTTP title and favicon fingerprinting

Fingerprinting a web service from its page title and favicon hash, which survives header
scrubbing.

### 14. TLS configuration deep scan

Enumerating protocol versions, cipher suites, curves, certificate chain and known TLS flaws.
Read-only handshakes only; no renegotiation abuse.

### 15. SNMP community enumeration

Reading system and interface tables with the default or supplied community string.

### 16. SMB share and auth enumeration

Listing shares and negotiating dialect and signing support, without attempting credential
use beyond the supplied read-only account.

### 17. NFS export enumeration

Listing exported filesystems and their access policy.

### 18. LDAP directory enumeration

Reading the directory's naming contexts, schema and anonymous-readable attributes.

### 19. Kerberos user enumeration

Asking the KDC which principals exist, without requesting or cracking any ticket.

### 20. SMTP banner and relay probing

Reading the banner, the advertised extensions and STARTTLS support, and testing relay policy
with a null sender and an address the operator owns. No message is delivered.

### 21. Anonymous FTP access check

Testing whether the service accepts an anonymous login and what it exposes if it does.

### 22. Database service probing

Identifying the database engine and version from its handshake, without authenticating.

### 23. Database default-configuration probing

Checking for the shipped-default listener behaviour (unauthenticated ping, exposed admin
interface) that a database should not have.

### 24. SSH algorithm and auth enumeration

Reading the offered host keys, key-exchange and MAC algorithms and the accepted
authentication methods.

### 25. RDP and VNC service detection

Identifying remote-desktop services and their negotiated security layer, without attempting
a session.

### 26. SSDP and UPnP discovery

Enumerating devices that advertise over SSDP, including the consumer routers and printers
that estates forget.

### 27. ICS/OT protocol probing

Read-only identification of industrial protocols (Modbus, S7, OPC-UA, BACnet) on a scoped OT
segment. Identification only: no write function code is ever sent.

### 28. DNS zone transfer and wildcard probing

Attempting an AXFR against the target's own name servers and characterising wildcard
behaviour, both of which are frequently misconfigured.

### 29. Service-version CVE correlation

Joining observed product/version pairs against vulnerability data to name the CVEs that
plausibly apply, with the version evidence that produced the join.

### 30. Network topology mapping

Building the host-and-subnet graph from discovery results, to make the estate legible for
scope review. Not implemented as a graph: the discovery results are reported per host.
