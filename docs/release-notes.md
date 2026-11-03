![Logo](images/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

### Version 1.1.0

**Date:** 2026-11-03

- The discovery document of the Sweden Connect reference server holds `service_documentation`, which links to a page for Relying Party developers that describes the service. See [#38](https://github.com/swedenconnect/spring-authentication-server/issues/38).
- `authn-server.oidc.max-jwt-age` now defaults to 10 minutes and cannot be turned off, so the OP rejects a signed request object, signature request or client assertion issued longer ago than that. A deployment whose clients reuse a signed request object through `request_uri` must set a longer value. See [#37](https://github.com/swedenconnect/spring-authentication-server/issues/37).
- The scopes `https://id.oidc.se/scope/sign` and `https://id.oidc.se/scope/signApproval` must now be explicitly declared and are never derived. `auth_time` and `acr` are always published in `claims_supported`, and a warning is logged at startup for a scope whose claims cannot be delivered. The reference service no longer offers the sign scope. See [#39](https://github.com/swedenconnect/spring-authentication-server/issues/39).
- A subject identifier secret is now required, and the server does not start if an enabled protocol has none. An existing deployment that assigns a secret for the first time gives its users new identifiers. An Identity Provider moving from saml-identity-provider keeps its users' persistent `NameID`s by setting `authn-server.saml.subject-identifier.secret` to an empty value. See [#50](https://github.com/swedenconnect/spring-authentication-server/issues/50).
- The OpenID Provider checks that the `sector_identifier_uri` of a pairwise OpenID Federation client lists all its redirect URIs, and that a pairwise client without one has a single redirect host. A client that fails is marked as invalid and gets `invalid_client`. The check of the document can be turned off. See [#50](https://github.com/swedenconnect/spring-authentication-server/issues/50).
- `authn-server.oidc.federation.clients.cache.not-found-time-to-live` now defaults to 5 minutes. See [#50](https://github.com/swedenconnect/spring-authentication-server/issues/50).
- The OpenID Provider fills its cache of OpenID Federation clients with a background job that walks the federation every 30 minutes, so that a client's first request does not wait for the resolver. A client that the resolver no longer knows is by default kept until its cache entry expires. See [#48](https://github.com/swedenconnect/spring-authentication-server/issues/48).
- The background job that refreshed frequently used federation clients, and its `authn-server.oidc.federation.clients.cache.refresh` settings, have been removed. See [#48](https://github.com/swedenconnect/spring-authentication-server/issues/48).
- The federation client supports the subordinate listing and trust marked entities listing calls of OpenID Federation. See [#49](https://github.com/swedenconnect/spring-authentication-server/issues/49).
- The OpenID Provider checks the metadata of an OpenID Federation client each time the client is resolved, and marks a client that it cannot serve as invalid at once, instead of failing when a request hits the fault. Metadata that cannot be parsed no longer gives the user a "try again later" page. The keys at `jwks_uri` are fetched when the client is resolved and held with it, and `signed_jwks_uri` is supported. See [#53](https://github.com/swedenconnect/spring-authentication-server/issues/53).
- An OpenID Connect client from the configuration or from a client repository is now checked with the same rules as an OpenID Federation client, and a client with a fault is blocked and gets `invalid_client` instead of failing when a request hits the fault. A client that uses a client secret needs its method to be enabled. Its keys at `jwks_uri` are held and read again every hour. See [#55](https://github.com/swedenconnect/spring-authentication-server/issues/55).
- When an OpenID Connect authentication request uses a request object, the OpenID Provider requires `response_type`, and a `scope` holding `openid`, to also be sent as ordinary request parameters, as OpenID Connect Core requires. Clients that send them only inside the request object are rejected. See [#35](https://github.com/swedenconnect/spring-authentication-server/issues/35).

-----

### Version 1.0.3

**Date:** 2026-10-13

- The OpenID Provider's federation client closes every HTTP response. Before, a 404 or error answer from a resolver or trust mark issuer left the connection in use, and once all connections were taken, the next federation call, for example fetching the OpenID Provider's own trust marks, waited three minutes before failing. See [#30](https://github.com/swedenconnect/spring-authentication-server/issues/30).
- The reference service shows "Reference OP" in the page heading and title during OpenID Connect logins, and "Reference IdP" only during SAML logins. See [#29](https://github.com/swedenconnect/spring-authentication-server/issues/29).

-----

### Version 1.0.2

**Date:** 2026-10-08

- An OpenID Provider follows version 1.2 of the Signature Extension for OpenID Connect. A signature request sent as a JWT of its own must now hold `iss` and `aud`, so clients that leave them out are rejected. See [#21](https://github.com/swedenconnect/spring-authentication-server/issues/21).
- A new setting, `authn-server.oidc.max-jwt-age`, limits how old a request object, signature request or client assertion signed by a client may be. A JWT signed by a client is also rejected if its `iat` is in the future. See [#21](https://github.com/swedenconnect/spring-authentication-server/issues/21).

-----

### Version 1.0.1

**Date:** 2026-10-06

- An OpenID Provider may now offer a scope without supporting all of its claims. `claims_supported` lists only the claims that the OpenID Provider can deliver.
- The Sweden Connect reference server delivers a simulated user's coordination number as a coordination number, not as a personal identity number.
- An OpenID Provider treats an authentication request without `prompt` as `prompt=login`, as the OpenID Connect Profile for Sweden Connect requires. This can be turned off for deployments outside Sweden Connect. See [#12](https://github.com/swedenconnect/spring-authentication-server/issues/12).
- A request object whose `response_type` differs from the one in the request is rejected. See [#13](https://github.com/swedenconnect/spring-authentication-server/issues/13).
- A client assertion without `iat` is accepted. See [#14](https://github.com/swedenconnect/spring-authentication-server/issues/14).
- A `+` in `state` is returned unchanged to the Relying Party. See [#15](https://github.com/swedenconnect/spring-authentication-server/issues/15).
- An authentication request with a signature request, but without the sign or sign approval scope, is rejected. See [#16](https://github.com/swedenconnect/spring-authentication-server/issues/16).

-----

### Version 1.0.0

**Date:** 2026-10-06

- Initial version.

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
