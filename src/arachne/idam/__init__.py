"""Identity and access management beyond a single login (WP-20, area IDAM).

The S17 identity model authenticates a caller: an OIDC login mints a session, a service
account carries a key, and every route depends on one of the three roles. This package is the
*provisioning* half — how an enterprise directory keeps ARACHNE's view of who exists and which
groups they are in in step, without ever becoming a second authorisation source.

For now that is SCIM 2.0 (:mod:`arachne.idam.scim`, REQ-IDAM-007). LDAP provisioning and
bind authentication live with the API's authentication path, because they are a login
mechanism rather than a directory mirror.
"""

from __future__ import annotations

__all__: list[str] = []
