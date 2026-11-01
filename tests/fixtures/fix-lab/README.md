# payments-api (lab repository)

A deliberately small repository used by ARACHNE's S27 tests (area FIX). It is the shape of a
real deployment repository — a Kubernetes manifest, some Terraform and its own test suite —
with **no misconfiguration of its own**: the tests plant one (or two) through
`tests/helpers/fixlab.py`, so each test states its own precondition instead of sharing a
fixture whose flaws nobody can see.

`specs/` is the repository's **own** test suite. ARACHNE runs it as the gate on a fix
proposal: a patch that breaks it is flagged and never submitted. The suite asserts what must
keep working (the image stays pinned, the limits stay set, storage stays encrypted) and never
asserts on the security posture a fix would change — which is what makes it an honest gate.

The tree is copied into a temporary directory and `git init`-ed by the helper: the fixture
carries no `.git`, because a nested repository inside ARACHNE's own tree would be a gitlink,
not a checkout.
