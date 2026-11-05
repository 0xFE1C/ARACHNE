# Chapter 5 — Cloud and Supply-Chain Exposure

> **Owner:** Detection group · **Last verified:** 2026-11-05 · **Review interval:** 365 days

The M5 surface. Cloud configuration is read through the provider's own API with a read-only
credential, or observed from outside where the credential is not available. Container and
supply-chain methods read manifests, registries and pipelines. Nothing in this chapter
creates, modifies or deletes a cloud resource; where a method would need a write to prove
itself, it is not implemented and says so.

## Methods

### 1. Cloud IAM policy review

Reading attached policies, roles and trust relationships for the patterns that matter:
wildcard actions, wildcard resources, cross-account trust without an external id, and
long-lived access keys where a role would do.

### 2. Cloud storage bucket enumeration

Enumerating the buckets an account owns and, separately, testing a scoped name for anonymous
access from outside the account.

### 3. Leaked cloud credential detection

Scanning for provider-shaped keys (`AKIA…`, `AIza…`, service-account JSON) in code, build
logs, images and documents, and reporting the key's identity without using it.

### 4. Instance metadata service exposure

Reading the metadata service's own configuration (IMDSv1 still enabled, no hop limit) from
inside the instance's own scope. No credential is fetched.

### 5. Azure managed identity audit

Reviewing which resources carry a managed identity, what it can reach, and whether it is
system- or user-assigned.

### 6. GCP service-account key exposure

Detecting long-lived service-account keys in use or in files, against the recommendation to
prefer workload identity federation.

### 7. Firebase rules exposure

Reading a Firebase project's rules for the permissive cases (`allow read, write: if true`) and
its publicly readable Realtime Database or Firestore.

### 8. Supabase row-level security review

Checking whether tables are exposed without row-level security enabled, which turns a
PostgREST endpoint into a full-table read.

### 9. Serverless function exposure

Reviewing function URLs, triggers, environment variables and layers for public invocation and
for secrets held in configuration rather than in a secret store.

### 10. CloudTrail and audit-log coverage review

Confirming that an account-wide audit trail exists, is multi-region, is protected against
deletion, and is actually delivering. Not implemented: it needs a control-plane read the
current provider adapters do not perform.

### 11. Terraform state exposure

Checking for a state file in an object store or a served path, which discloses every resource
and frequently every secret in the estate.

### 12. Terraform state secret extraction

Reading the secrets a state file retains, including the ones removed from the configuration
but still present in the stored resource attributes.

### 13. Kubernetes API exposure

Checking whether the API server is reachable anonymously, whether the dashboard is exposed,
and whether the kubelet read-only port answers.

### 14. Kubernetes manifest misconfiguration

Reviewing manifests for privileged containers, host-path mounts, host network, missing
security contexts, absent resource limits and the default service account's token mount.

### 15. Container registry image scanning

Scanning image layers for vulnerable packages and for credentials baked into a layer. The
image is read as data and never executed.

### 16. Docker socket exposure

Checking whether the Docker or containerd socket is mounted into a workload or served
unauthenticated over TCP, either of which is a host takeover.

### 17. Image layer and history secret extraction

Reading `docker history` and the layer tarballs for secrets that a later `RUN rm` does not
remove from the image.

### 18. Cloud networking and security-group review

Reviewing ingress rules for `0.0.0.0/0` on administrative and database ports, and for
security groups attached to nothing. Not implemented: it needs a control-plane read the
current provider adapters do not perform.

### 19. Managed key management review

Reviewing key rotation, key policy and whether a customer-managed key is used where a
compliance regime requires one. Not implemented: provider key-management APIs are not in the
current adapter set.

### 20. Managed database exposure

Checking whether a managed database instance is publicly addressable and whether its
snapshot or backup is.

### 21. Search platform exposure

Checking whether an Elasticsearch, OpenSearch or Solr endpoint answers unauthenticated, which
is a full-data read.

### 22. Third-party SaaS integration inventory

Enumerating the OAuth applications and marketplace integrations an account has authorised.
Not implemented: it needs a control-plane read the current provider adapters do not perform.

### 23. CI/CD pipeline audit

Reviewing pipeline definitions and their runtime configuration for untrusted-input execution,
long-lived cloud credentials, unprotected secrets and overly broad runner permissions.

### 24. Dependency confusion exposure

Checking whether an internal package name is claimable on the public registry, which is the
prerequisite for a dependency-confusion substitution. Read-only: nothing is registered.

### 25. SBOM generation and review

Producing a CycloneDX inventory of what the deployment actually contains, then reviewing it
for components that are unmaintained, end-of-life or outside policy.
