![Logo](images/sweden-connect.png)

# The OpenID Provider

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes the OpenID Provider: where it publishes its discovery document and its keys, how the keys are
configured and rolled over, how the key that a message to a client is signed with is chosen, how the offered scopes,
the supported claims and the authentication contexts are worked out from the authentication providers, how
authentication requests are processed, how the code flow completes with the authorization code, the token endpoint,
the ID token and the UserInfo endpoint, how to extend the discovery document, and how the OpenID Provider joins an
OpenID Federation. The properties are described in [Configuration](configuration.html#the-openid-provider).

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

- [Where things are published](#where-things-are-published)
- [Keys](#keys)
    - [Signing keys](#signing-keys)
    - [Decryption keys](#decryption-keys)
    - [Key requirements and key IDs](#key-requirements-and-key-ids)
    - [Rolling over a key](#rolling-over-a-key)
- [Choosing the signing key for a client](#choosing-the-signing-key-for-a-client)
- [Scopes, claims and authentication contexts](#scopes-claims-and-authentication-contexts)
- [Authentication requests](#authentication-requests)
    - [How a request is processed](#how-a-request-is-processed)
    - [Clients](#clients)
    - [Request objects](#request-objects)
    - [PKCE, state and response modes](#pkce-state-and-response-modes)
    - [Which clients are accepted](#which-clients-are-accepted)
    - [What the request is turned into](#what-the-request-is-turned-into)
    - [Swedish extensions](#swedish-extensions)
    - [Failures](#failures)
- [The code flow](#the-code-flow)
    - [Authentication and the authorization code](#authentication-and-the-authorization-code)
    - [The token endpoint](#the-token-endpoint)
    - [Client authentication](#client-authentication)
    - [The access token](#the-access-token)
    - [The ID token](#the-id-token)
    - [The UserInfo endpoint](#the-userinfo-endpoint)
    - [Where codes and tokens are kept](#where-codes-and-tokens-are-kept)
- [The discovery document](#the-discovery-document)
    - [Extending the document](#extending-the-document)
- [OpenID Federation](#openid-federation)
    - [Joining a federation](#joining-a-federation)
    - [Federation keys](#federation-keys)
    - [The entity configuration](#the-entity-configuration)
    - [Descriptive metadata](#descriptive-metadata)
    - [The trust marks of the OpenID Provider](#the-trust-marks-of-the-openid-provider)
    - [Changing the entity configuration](#changing-the-entity-configuration)

<a name="where-things-are-published"></a>
## Where things are published

The OpenID Provider is identified by its issuer, which defaults to the base URL. Its endpoints are placed under the
OIDC path, `/oidc` by default, see [URL layout](configuration.html#url-layout). With the base URL
`https://op.example.com`:

| What | URL |
| :--- | :--- |
| Issuer | `https://op.example.com` |
| Discovery document | `https://op.example.com/.well-known/openid-configuration` |
| JWKS | `https://op.example.com/oidc/jwks` |
| Authorization endpoint | `https://op.example.com/oidc/authorize` |
| Token endpoint | `https://op.example.com/oidc/token` |
| UserInfo endpoint | `https://op.example.com/oidc/userinfo` |
| OpenID Federation entity configuration, when [federation](#openid-federation) is enabled | `https://op.example.com/.well-known/openid-federation` |

The discovery document is always published at the issuer followed by `/.well-known/openid-configuration`, as OpenID
Connect Discovery, Section 4, requires, and the entity configuration at the issuer followed by
`/.well-known/openid-federation`, as OpenID Federation 1.0, Section 9, requires. They are therefore not under the OIDC
path. An issuer with a path moves both documents along with it: with the issuer `https://op.example.com/op1`, the
discovery document is published at `https://op.example.com/op1/.well-known/openid-configuration`. The issuer must be
the base URL or begin with it, since the server can only serve paths under the base URL.

<a name="keys"></a>
## Keys

The OpenID Provider has two lists of keys: signing keys and decryption keys. Each key is a credential configured
through the [credentials-support](https://docs.swedenconnect.se/credentials-support/) library, together with a state.
The keys are checked at startup, and the application does not start if a rule below is broken.

<a name="signing-keys"></a>
### Signing keys

The OpenID Provider signs ID tokens, and UserInfo responses unless that is turned off. A signing key is:

- **active**: published in the JWKS and used for signing, or
- **future**: published in the JWKS but never used.

Several signing keys may be active at the same time, for example one RSA key and one EC key, so that clients that only
accept EC signatures are served too. Exactly one active key is the **default key**, which is used for a client that
does not say which algorithm it wants. With only one active key, that key is the default key without being marked.

At least one active signing key is required, since ID tokens are always signed (OpenID Connect Core, Section 2).

The algorithms that a key can produce follow from the key:

| Key | Algorithms |
| :--- | :--- |
| RSA | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`. `RS256` is used when the client does not ask for one. |
| EC, P-256 | `ES256` |
| EC, P-384 | `ES384` |
| EC, P-521 | `ES512` |

A key can be limited to one algorithm by assigning `jose-alg` in the credential metadata.

<a name="decryption-keys"></a>
### Decryption keys

Clients may encrypt request objects to the OpenID Provider. A decryption key is:

- **active**: published in the JWKS and used for decryption, or
- **previous**: not published, but still used for decryption.

An RSA key supports `RSA-OAEP-256` and `RSA-OAEP`, and an EC key supports `ECDH-ES`, `ECDH-ES+A128KW`,
`ECDH-ES+A192KW` and `ECDH-ES+A256KW`. The algorithms of the active keys are published in the discovery document as
`request_object_encryption_alg_values_supported`. Decryption keys are optional.

<a name="key-requirements-and-key-ids"></a>
### Key requirements and key IDs

Following [Sweden Connect Security Requirements](https://docs.swedenconnect.se/federation/security-requirements.html),
Section 3, an RSA key must be at least 2048 bits, and an EC key must be on the P-256, P-384 or P-521 curve. Other keys
stop the application from starting.

Every published key has a key ID, `kid`, as Section 4 of the same document requires. The key ID is the `key-id` of the
credential metadata when assigned, and otherwise the RFC 7638 thumbprint of the public key. Either way it stays the
same across restarts, so clients that cache the JWKS keep finding the key. The key IDs of the signing keys must be
unique, and so must those of the decryption keys.

The JWKS publishes the public keys only, with `use` set to `sig` or `enc`, and with the certificate chain when the
credential has one.

<a name="rolling-over-a-key"></a>
### Rolling over a key

Section 4 of the security requirements says how a key is replaced without disrupting the clients.

**A signing key** must be published before it is used, at least as long before as the clients may cache the JWKS:

1. Add the new key as `future`. It is published but not used.
2. Wait at least as long as the clients cache the JWKS, or as long as the federation metadata is valid.
3. Make the new key `active` and the default key, and remove the old key.

```yaml
authn-server:
  oidc:
    keys:
      signing:
        - credential:
            bundle: sign-2026
          default-key: true
        - credential:
            bundle: sign-2027
          state: future
```

**A decryption key** is the other way around: the old key is removed from the JWKS at once, so that clients stop
encrypting with it, but it must still decrypt what was encrypted before the switch:

1. Add the new key as `active`, and change the old key to `previous`.
2. When no client can still be using the old key, remove it.

```yaml
authn-server:
  oidc:
    keys:
      decryption:
        - credential:
            bundle: enc-2027
        - credential:
            bundle: enc-2026
          state: previous
```

<a name="choosing-the-signing-key-for-a-client"></a>
## Choosing the signing key for a client

The key is chosen per client that a message is sent to, by [`SigningKeySelector`][SigningKeySelector]. The ID token
uses the client's ID token parameters, and the UserInfo response its UserInfo parameters.

| The client declares | The key and algorithm |
| :--- | :--- |
| One algorithm, `id_token_signed_response_alg` or `userinfo_signed_response_alg` | An active key that can produce the algorithm, the default key if it can. |
| A list of accepted algorithms, `id_token_signing_alg_values_supported` or `userinfo_signing_alg_values_supported` of [OpenID Connect Relying Party Metadata Choices](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0.html) | The default key if it can produce one of them, otherwise another active key that can. The algorithm is the first one in the client's list that the key can produce. |
| Nothing | The default key, with its preferred algorithm. |

A client that declares both gets its single algorithm. The value `none` in a list is ignored, since the message is
signed.

A client that declares nothing does not get the registration default of OpenID Connect (`RS256` for ID tokens).
[Sweden Connect OpenID Connect Metadata Requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html),
Section 4.1, leaves the choice to the OpenID Provider, so the default key decides.

If no active key can produce an algorithm that the client accepts, the message is not sent: this is an error, not a
fallback to another algorithm. Future keys are never used.

UserInfo responses are signed by default, see [The UserInfo endpoint](#the-userinfo-endpoint).

<a name="scopes-claims-and-authentication-contexts"></a>
## Scopes, claims and authentication contexts

What the OpenID Provider offers is worked out from what the authentication providers declare, see
[What the provider declares](authentication-module.html#what-the-provider-declares). The result is computed at startup
by [`SupportedScopesAndClaims`][SupportedScopesAndClaims].

**Claims.** The claims of a provider are its attributes, `getSupportedAttributes()`, mapped to claims through the
OpenID Connect [attribute mapping](attributes.html#mapping). For example, `attribute.personal-identity-number` gives
`https://id.oidc.se/claim/personalIdentityNumber`, and `attribute.mobile-number` gives both `phone_number` and
`msisdn`.

**Scopes.** A provider that declares scopes, `getSupportedScopes()`, offers exactly those. A provider that declares
none offers the scopes derived from its claims. A scope of the [scope registry](attributes.html#the-built-in-scopes)
is derived when all its essential claims are among the claims of the provider. In this check, the claims `sub` and
`auth_time` always count, since the OpenID Provider puts them in every ID token. A scope without essential claims, such
as `profile`, is derived when at least one of its claims is among them, and a scope without claims, such as
`https://id.oidc.se/scope/signApproval`, is only offered when it is declared.

:raised_hand: The scope `https://id.oidc.se/scope/naturalPersonNumber` has two essential claims, the personal identity
number and the coordination number. A provider that delivers only one of them does not get the scope derived. Declare
the scope, or configure the missing claim, if the provider should offer it.

The OpenID Provider offers the union of the scopes over all providers. The `openid` scope is always offered.

The settings of the OpenID Provider change this:

- `authn-server.oidc.scopes`, when set, replaces the derived scopes. Every scope must be in the scope registry.
- `authn-server.oidc.claims` is added to the claims of the providers. The claims also count when scopes are derived.

**The supported claims** are the claims of the providers, the configured claims, and every claim of every offered
scope. The last part is required by Section 5.1 of the Sweden Connect metadata requirements, even when a non-essential
claim of an offered scope is not delivered by any provider.

**Authentication contexts.** `acr_values_supported` is the union of the authentication context URIs of the providers,
`getSupportedAuthnContextUris()`. It is not configurable.

<a name="authentication-requests"></a>
## Authentication requests

Authentication requests are received on the authorization endpoint, with GET or POST. The OpenID Provider follows
OpenID Connect Core, Section 3.1.2, and the
[Swedish OpenID Connect Profile](https://www.oidc.se/specifications/swedish-oidc-profile-1_0.html), Section 2. Only the
authorization code flow is supported, so `response_type` must be `code`.

This section covers the processing of the request, up to the protocol-neutral authentication requirements. What
happens next is described in [The code flow](#the-code-flow).

<a name="how-a-request-is-processed"></a>
### How a request is processed

The request is processed in two parts, by
[`OidcAuthnRequestAuthenticationConverter`][OidcAuthnRequestAuthenticationConverter] and
[`OidcAuthnRequestAuthenticationProvider`][OidcAuthnRequestAuthenticationProvider].

The first part finds out where a response can be sent:

1. The client is looked up by `client_id` in the [client registry](client-registry.html). A client registered with
   the token endpoint authentication method `none` is not accepted, see [Clients](#clients).
2. A request object, if the request has one, is fetched and decoded, and its parameters replace those of the request,
   see [Request objects](#request-objects).
3. `redirect_uri` must be present and be one of the client's registered redirect URIs, compared as strings.
4. `response_mode` must be `query`, `form_post` or absent.

From this point, a failure is sent to the redirect URI as an error response, in the requested response mode and with
the `state` of the request. The second part checks the request and builds the requirements:

1. The parameters are parsed, and `response_type` must be `code`.
2. `state` must be present, unless that check is turned off.
3. A request object must be signed if that is required.
4. The client must be accepted, see [Which clients are accepted](#which-clients-are-accepted).
5. PKCE is checked.
6. The authentication requirements are built from the rest of the request.

<a name="clients"></a>
### Clients

The clients are found in the client registry, through its OpenID Connect backends and in their configured order, see
[OpenID Connect: three backends](client-registry.html#openid-connect-three-backends). There are no properties for the
backends yet, so they are added in an [adapter](configuration.html#adjusting-the-configuration-in-code):

```java
@Bean
AuthnServerConfigurerAdapter oidcClients(final List<OidcClientRecord> clients) {
  return (http, configurer) -> configurer.clientRegistryBackend(new ConfigurationClientBackend(clients));
}
```

What the OpenID Provider reads from the client metadata when it processes a request:

| Client metadata | Used for |
| :--- | :--- |
| `redirect_uris` | The accepted values of `redirect_uri`. |
| `request_uris` | The only values of `request_uri` that are fetched. |
| `jwks` or `jwks_uri` | Verifying signed request objects and signature requests. |
| `request_object_signing_alg` | When set, request objects must be signed with this algorithm. |
| `token_endpoint_auth_method` | The method the client must authenticate with at the token endpoint, see [Client authentication](#client-authentication). Public clients, with `none`, are not supported. |
| `token_endpoint_auth_signing_alg` | When set, the algorithm that client assertions must be signed with. |
| `client_secret` | The client secret, for the secret-based client authentication methods. |
| `default_acr_values` | The authentication contexts, as voluntary values, when the request asks for none. |
| `subject_type` and `sector_identifier_uri` | How the `sub` is computed, see [Identifying the user](attributes.html#identifying-the-user). |
| `id_token_signed_response_alg` | The algorithm the ID token is signed with, see [Choosing the signing key for a client](#choosing-the-signing-key-for-a-client). |
| `id_token_encrypted_response_alg` and `id_token_encrypted_response_enc` | Whether and how the ID token is encrypted, see [The ID token](#the-id-token). |

An unknown client and a client registry that fails end at the OpenID Provider, and are logged differently: the first
at `INFO`, since it is a normal outcome, and the second at `ERROR`, since a dependency is not working.

A client registered with the token endpoint authentication method `none`, a public client, is a client configuration
error. The request ends at the OpenID Provider, without a redirect, and the error is logged at `WARN`, since the
client registration needs to be corrected.

<a name="request-objects"></a>
### Request objects

A request object may be passed by value, in `request`, or by reference, in `request_uri`. Its parameters replace
those of the request with the same name, as OpenID Connect Core, Section 6.3.3, states. `client_id` must still be
given as a plain parameter.

- **By reference.** A `request_uri` is only fetched when it is one of the client's registered `request_uris`, so a
  client that has registered none cannot use `request_uri`. A fragment is ignored in the comparison and is not sent.
  The fetched request object is processed exactly like one passed by value. The default fetcher uses HTTP GET with a
  timeout of 5 seconds and accepts at most 100 KB. Replace it with
  `OidcProviderConfigurer.authnRequestProcessor(p -> p.requestUriFetcher(...))`.
- **Signed.** The signature is verified with the client's keys, from `jwks` or `jwks_uri` in its metadata. The
  accepted algorithms are `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` and `ES512`. A signed
  request object must hold `iss`, which must be the `client_id`, and `aud`, which must be the issuer or the URL of the
  authorization endpoint.
- **Encrypted.** An encrypted request object is decrypted with the [decryption keys](#decryption-keys). It may hold a
  signed request object (signed, then encrypted) or an unsigned one.
- **Unsigned.** An unsigned request object, `alg` `none`, is accepted by default. It is rejected when
  `authn-server.oidc.authorization-request.require-signed-request-object` is `true`, and when the client has registered
  `request_object_signing_alg`. A client that has registered an algorithm must sign with that algorithm.

For every request object, `client_id` and `iss`, when present, must be the `client_id` of the request, and a request
object whose `exp` has passed, or whose `nbf` has not been reached, is rejected. The clock skew of the OpenID Provider
applies.

If a request object cannot be fetched or decoded, there may be no redirect URI to answer to, since the request object
may be what holds it. The error is sent to the client when the plain parameters of the request hold a registered
redirect URI and a supported response mode, and otherwise ends at the OpenID Provider.

<a name="pkce-state-and-response-modes"></a>
### PKCE, state and response modes

**PKCE** (RFC 7636) is optional by default. With `authn-server.oidc.authorization-request.require-pkce` set to
`true` it is required. The only supported method is `S256`. A request with the method `plain`, or with a
`code_challenge` and no method, which means `plain` (RFC 7636, Section 4.3), is always answered with
`invalid_request`.

**`state`** is required by default, as the Swedish OpenID Connect Profile, Section 2.1, requires. A request without it
is answered with `invalid_request`. With `authn-server.oidc.authorization-request.require-state` set to `false`, such a
request is accepted, and the response carries no `state`.

**Response modes.** `query`, the default for the code flow, and `form_post` are supported. With `form_post`, the
response is posted to the client by a page that the browser submits by itself, like the SAML response page. Replace
the page with `OidcProviderConfigurer.authnRequestProcessor(p -> p.responsePage(...))`. Any other `response_mode`,
such as `fragment`, is answered with HTTP status 400 and no redirect, as OpenID Connect Core, Section 3.1.2.6, says.

<a name="which-clients-are-accepted"></a>
### Which clients are accepted

Once the redirect URI is established and the request has been parsed, the
[requester acceptance](client-registry.html#requester-acceptance) decides whether the client may use the OpenID
Provider. By default every known client is accepted. The rules for OpenID Connect are set under
`authn-server.oidc.requester-acceptance`: a whitelist of `client_id`s, and groups of required trust mark types, see
[Configuration](configuration.html#oidc-requester-acceptance). A trust mark type that the client does not hold is asked
for through the client registry before the client is rejected, see
[Trust marks on demand](client-registry.html#trust-marks-on-demand).

A client that is not accepted gets the error `unauthorized_client`.

<a name="what-the-request-is-turned-into"></a>
### What the request is turned into

The result is the protocol-neutral authentication requirements, as an
[`OidcAuthenticationRequirements`][OidcAuthenticationRequirements], which adds what only OpenID Connect has.

| Request | Requirement |
| :--- | :--- |
| `prompt=login` | Force authentication. |
| `prompt=none` | Passive authentication. `none` together with another value is `invalid_request`. |
| `prompt=consent` | Consent required. |
| `max_age` | The maximum authentication age. `max_age=0` is the same as `prompt=login`. |
| `scope` | The requested scopes that the OpenID Provider offers. Other scopes are ignored, as OpenID Connect Core says for scopes that are not understood. |
| `scope` and `claims` | The requested attributes. The offered scopes are expanded into their claims, the `claims` parameter is merged in, and the claims are mapped to generic attributes, see [What a request asks for](attributes.html#what-a-request-asks-for). |
| `acr_values`, `acr` in `claims`, or the client's `default_acr_values` | The authentication contexts, in the client's order of preference, and whether they are voluntary or required. |
| `login_hint` | The login hint. |
| `ui_locales` | The preferred languages of the user interface. |
| `id_token_hint` | The subject of the ID token. |

**Authentication contexts.** The requirements tell voluntary authentication contexts from required ones, see
[Which authentication contexts are acceptable](authentication-module.html#which-authentication-contexts-are-acceptable).

- `acr_values` requests the `acr` claim as a voluntary claim (OpenID Connect Core, Sections 3.1.2.1 and 5.5.1.1).
  The supported values are used in the client's order of preference, and if none is supported, the user is
  authenticated as if no value had been requested. Such a request never fails because of its `acr_values`.
- `acr` in the `claims` parameter wins over `acr_values`, and the Swedish profile says a client should not send both.
  Values that are not essential are voluntary, as above.
- Values of `acr` requested as essential are required. The values that no authentication provider supports are left
  out, and if none is left, the request is answered with `unmet_authentication_requirements`, as the Swedish profile,
  Section 2.2, requires.
- When the request has neither `acr_values` nor `acr` in the `claims` parameter, the client's registered
  `default_acr_values` are used, as voluntary values. A request that has either ignores the defaults.

**`id_token_hint`** must be an ID token issued by this OpenID Provider: signed by one of its signing keys, with the
issuer as `iss`, and with the client in `aud`. An expired token is accepted. Otherwise the request is answered with
`invalid_request`.

The login hint and the subject of the ID token hint may be personal data, and are never logged.

The data needed to answer the request and issue tokens, such as the redirect URI, `state`, `nonce` and the PKCE code
challenge, is kept as the protocol request data of the request, an
[`OidcAuthnRequestData`][OidcAuthnRequestData].

<a name="swedish-extensions"></a>
### Swedish extensions

The parameters of
[Authentication Request Parameter Extensions for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/request-parameter-extensions-1_1.html)
and the [Signature Extension for OpenID Connect](https://www.oidc.se/specifications/oidc-signature-extension-1_1.html)
are read, as plain parameters or from a request object.

- **User message**, `https://id.oidc.se/param/userMessage`. Read only when user messages are supported for OpenID
  Connect, `authn-server.oidc.supports-user-message`, and otherwise ignored. The MIME types `text/plain` and
  `text/markdown` are supported. An invalid message, or another MIME type, is answered with `invalid_request`.
- **Authentication provider**, `https://id.oidc.se/param/authnProvider`. Becomes the requested authentication
  provider.
- **Signature request**, `https://id.oidc.se/param/signRequest`. Read when the scope `https://id.oidc.se/scope/sign`
  or `https://id.oidc.se/scope/signApproval` is requested and offered, and otherwise ignored. It must then be present,
  either as a JWT of its own signed with the client's key, which may also be encrypted, or as a JSON object in a signed
  request object. `prompt` must hold both `login` and `consent`. For the sign scope, `tbs_data` must be present, and
  for sign approval only, it must not be. The sign message becomes a sign message that must be shown, with the data
  to be signed. A signature request that breaks a rule is answered with `invalid_request`.

<a name="failures"></a>
### Failures

Until the client and the redirect URI are known, there is nowhere safe to send a response. Failures up to that point
end at the OpenID Provider as an `UnrecoverableErrorException`, with one of the errors of
[`OidcUnrecoverableError`][OidcUnrecoverableError]. After that point, a failure is sent to the redirect URI as an error
response, with an `error_description` meant for the client's logs.

| Failure | Outcome |
| :--- | :--- |
| `client_id` is missing | Unrecoverable (`INVALID_AUTHN_REQUEST`) |
| The client is not known | Unrecoverable (`UNKNOWN_CLIENT`) |
| The client is registered with the token endpoint authentication method `none` | Unrecoverable (`INVALID_CLIENT_CONFIGURATION`) |
| The client registry fails when the client is looked up | Unrecoverable (`CLIENT_LOOKUP_FAILED`) |
| `redirect_uri` is missing or not registered | Unrecoverable (`INVALID_REDIRECT_URI`) |
| `response_mode` is not `query` or `form_post` | HTTP status 400 (`UNSUPPORTED_RESPONSE_MODE`) |
| The request object cannot be fetched or decoded, and the plain parameters give no redirect URI | Unrecoverable (`INVALID_AUTHN_REQUEST`) |
| The client asks for an encrypted ID token with algorithms that are not allowed, or has no key for them | Unrecoverable (`INVALID_CLIENT_CONFIGURATION`) |
| `request_uri` is not registered, or cannot be fetched | `invalid_request_uri` |
| The request object is invalid, not signed when it must be, or signed with the wrong algorithm | `invalid_request_object` |
| `response_type` is not `code` | `unsupported_response_type` |
| A parameter is missing or invalid, such as `scope` without `openid`, `state`, `prompt`, `max_age` or `id_token_hint` | `invalid_request` |
| PKCE is missing when required, or uses `plain`, also by leaving out `code_challenge_method` | `invalid_request` |
| The client is not accepted | `unauthorized_client` |
| The client registry fails during the acceptance check | Unrecoverable (`CLIENT_LOOKUP_FAILED`) |
| None of the essential `acr` values is supported | `unmet_authentication_requirements` |
| The user message or the signature request is invalid | `invalid_request` |

The errors that the authentication step reports are mapped as described in
[Errors](authentication-module.html#errors).

<a name="the-code-flow"></a>
## The code flow

Once the authentication request has been processed, the code flow continues:

1. The request is handed to the authentication providers, and the user is authenticated.
2. The client gets an authorization code at its redirect URI, in the response mode of the request and with `state`.
3. The client exchanges the code at the token endpoint for an access token and an ID token, authenticating itself.
4. The client calls the UserInfo endpoint with the access token.

<a name="authentication-and-the-authorization-code"></a>
### Authentication and the authorization code

The processed request goes to the authentication providers in the same way as a SAML request: the provider is chosen
from the requested authentication contexts, a previous authentication may be reused for single sign-on, and a
provider with pages of its own redirects the user and hands back on its resume path, see
[Writing an authentication module](authentication-module.html). The single sign-on policy of the provider wins over
the OpenID Connect policy, which wins over the shared one.

When the user has been authenticated, and before the code is issued:

- After a new authentication, the `value` and `values` of the `claims` parameter are compared with the user. Essential
  values that do not match give `access_denied`, see
  [When the user does not match the requested values](authentication-module.html#when-the-user-does-not-match-the-requested-values).
- The `sub` of the user for the client is computed, public or pairwise, see
  [Identifying the user](attributes.html#identifying-the-user). If the client asked for a `sub` with a value in the
  `claims` parameter, or with `id_token_hint`, it must be the same. Otherwise the client gets `access_denied` and no
  code.
- The attributes are released, by the OpenID Connect producers and voters followed by the shared ones, see
  [Releasing attributes](attributes.html#releasing-attributes), and turned into claims.

The code is a random value that may only be used once. It is bound to the client, the redirect URI, the PKCE code
challenge, the nonce, the requirements of the request, the authenticated user and the released claims. It is valid
for 1 minute by default, `authn-server.oidc.tokens.authorization-code-lifetime`. A lifetime above 10 minutes, the
maximum that RFC 6749, Section 4.1.2, recommends, is logged as a warning at startup, and the application still starts.

Every error after the request was accepted, such as a failed or cancelled authentication or a failed attribute
release, is sent to the redirect URI as an error response, in the response mode of the request and with `state`. The
errors are mapped as described in [Errors](authentication-module.html#errors). A failed authentication removes the
authentication from the session, as for SAML.

<a name="the-token-endpoint"></a>
### The token endpoint

The token endpoint accepts POST requests with the `authorization_code` grant, as OpenID Connect Core, Section 3.1.3,
and RFC 6749, Section 4.1.3, describe. No refresh tokens are issued, and `offline_access` is not offered. A request is
checked in this order:

1. The client is authenticated, see [Client authentication](#client-authentication).
2. `grant_type` must be `authorization_code`.
3. The code must be known, not expired, not used before, and issued to the client.
4. `redirect_uri` must be identical to the one of the authentication request.
5. When the request had a PKCE `code_challenge`, `code_verifier` must be present and match it (RFC 7636, Section
   4.6). A `code_verifier` sent for a request without a challenge is rejected.

A code that is used a second time is rejected, and the access token that was issued for it is revoked, as RFC 6749,
Section 4.1.2, says. Every response, also an error response, carries `Cache-Control: no-store`.

| Failure | Error |
| :--- | :--- |
| No client authentication, an unknown client, a wrong secret or signature, a method that is not enabled or not the registered one, or an invalid or reused client assertion | `invalid_client` (HTTP status 401) |
| More than one client authentication method | `invalid_request` |
| `grant_type` other than `authorization_code` | `unsupported_grant_type` |
| `grant_type` or `code` missing | `invalid_request` |
| The code is unknown, expired, used before or issued to another client | `invalid_grant` |
| `redirect_uri` missing or not the one of the authentication request | `invalid_grant` |
| `code_verifier` missing, not matching, or sent without a challenge | `invalid_grant` |
| The ID token cannot be encrypted for the client | `invalid_client` |
| The client registry fails | `server_error` (HTTP status 500) |

<a name="client-authentication"></a>
### Client authentication

A client must authenticate with the method it has registered as `token_endpoint_auth_method`. When it has registered
none, the default of OpenID Connect Dynamic Client Registration, `client_secret_basic`, applies. `none` is not
supported, so there are no public clients.

| Method | Enabled by default | How the client is verified |
| :--- | :--- | :--- |
| `private_key_jwt` | Yes | The client assertion is verified with the keys of the client, from `jwks` or `jwks_uri`. |
| `client_secret_basic` | No | The client secret, in the `Authorization` header. |
| `client_secret_post` | No | The client secret, as the `client_secret` parameter. |
| `client_secret_jwt` | No | The client assertion is verified with the client secret, with `HS256`, `HS384` or `HS512`. |

The methods are enabled with `authn-server.oidc.client-authentication-methods`, see
[Configuration](configuration.html#oidc-token-endpoint):

```yaml
authn-server:
  oidc:
    client-authentication-methods:
      - private_key_jwt
      - client_secret_basic
```

A client assertion, for `private_key_jwt` and `client_secret_jwt`, must hold:

- `iss` and `sub` equal to the `client_id`,
- `aud` holding the URL of the token endpoint or the issuer, as the Swedish OpenID Connect Profile, Section 3.1.1,
  recommends,
- `exp`, which has not passed,
- `iat`, which is not in the future,
- `jti`, which has not been used before. The value is remembered until the assertion expires.

The clock skew of the OpenID Provider applies. A `private_key_jwt` assertion may be signed with `RS256`, `RS384`,
`RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` or `ES512`. A client may have several keys, for example an RSA
key and an EC key, or an old and a new key during a rollover; the `kid` of the assertion selects the key, and without a
`kid` every matching key is tried. A client that has registered `token_endpoint_auth_signing_alg` must sign with that
algorithm.

The client secret is kept as the `client_secret` field of the client metadata, the name that OpenID Connect Dynamic
Client Registration uses. A client resolved through OpenID Federation never has a secret:

```java
metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, secret);
```

<a name="the-access-token"></a>
### The access token

The access token is an opaque random value. It reveals nothing about the user, and the OpenID Provider keeps what the
UserInfo endpoint needs together with it: the client, the `sub`, the scopes and the claims to deliver from the UserInfo
endpoint.

| Setting | Default |
| :--- | :--- |
| `authn-server.oidc.tokens.access-token-lifetime` | 5 minutes |
| `authn-server.oidc.tokens.access-token-single-use` | `true`, so that the first UserInfo call uses up the token |

With single use off, the token may be used at the UserInfo endpoint until it expires or is revoked.

<a name="the-id-token"></a>
### The ID token

The ID token follows the Swedish OpenID Connect Profile, Section 3.2.1:

| Claim | Value |
| :--- | :--- |
| `iss` | The issuer. |
| `sub` | The `sub` of the user for the client, public or pairwise. |
| `aud` | The `client_id`. |
| `exp` and `iat` | The expiry and the issuance time. |
| `auth_time` | The time the user was authenticated. When single sign-on was used, the time of the original authentication. |
| `nonce` | The `nonce` of the request, when it had one. |
| `acr` | The authentication context that was used. It is always present, also when `acr` was not requested and when requested voluntary values could not be met. The latter is logged at `INFO`. |

**Identity claims** are only included when they were requested, following Section 4.2 of the profile:

- A claim of the `claims` parameter goes where the parameter says, in the ID token or from the UserInfo endpoint.
- A claim of a requested scope goes where the scope definition says, see
  [The built-in scopes](attributes.html#the-built-in-scopes).
- A claim asked for in the ID token by the `claims` parameter, which is also covered by a requested scope delivered
  from the UserInfo endpoint, is delivered in both places.

A request with only the `openid` scope and no `claims` parameter gets no identity claims.

**Lifetime.** 5 minutes by default, `authn-server.oidc.tokens.id-token-lifetime`. The profile does not allow more than
5 minutes, so a longer lifetime is logged as a warning at startup, and the application still starts.

**Signing.** The ID token is always signed, with the key chosen for the client, see
[Choosing the signing key for a client](#choosing-the-signing-key-for-a-client).

**Encryption.** When the client has registered `id_token_encrypted_response_alg`, the signed ID token is encrypted
for the client (nested JWT). The key is taken from the client's `jwks` or `jwks_uri`: an encryption key of the type
the algorithm needs. Following
[Sweden Connect Security Requirements](https://docs.swedenconnect.se/federation/security-requirements.html), Section
3.2, the algorithms are:

- `id_token_encrypted_response_alg`: `RSA-OAEP`, `RSA-OAEP-256` or `ECDH-ES`.
- `id_token_encrypted_response_enc`: `A128CBC-HS256`, which is the default, `A256CBC-HS512`, `A128GCM` or `A256GCM`.

A client that asks for other algorithms, or has no usable key, is a client configuration error: its authentication
request ends at the OpenID Provider, and the error is logged at `WARN`.

<a name="the-userinfo-endpoint"></a>
### The UserInfo endpoint

The UserInfo endpoint, `/oidc/userinfo` by default, gives the client the claims that belong in UserInfo, as the
Swedish OpenID Connect Profile, Section 4.1, requires. It accepts GET and POST.

**Presenting the access token.** The token is accepted in two ways, following RFC 6750, Section 2:

- In the `Authorization` header: `Authorization: Bearer <token>`.
- As the `access_token` parameter of a form-encoded POST body.

The URI query parameter of RFC 6750, Section 2.3, is not accepted. A request that carries the token in more than one
way is rejected.

**Single use.** By default an access token may only be used once: the first successful call uses it up, and a second
call with the same token gets `invalid_token`. A call that fails does not use up the token. See
[The access token](#the-access-token) for how to turn this off.

**What the response holds.** The response holds `sub`, the same value as in the ID token, and the claims whose
delivery target includes UserInfo, following Section 4.2 of the profile:

- claims asked for under `userinfo` in the `claims` parameter,
- claims of a requested scope that the scope definition delivers from the UserInfo endpoint,
- a claim asked for in the ID token through the `claims` parameter, which is also covered by a requested scope
  delivered from the UserInfo endpoint.

A request with only the `openid` scope gets a response with only `sub`. The claims are those released when the
authentication completed, and kept with the access token. The release is not run again when the endpoint is called.

**Signing.** Responses are signed by default, `authn-server.oidc.sign-user-info`. A signed response is a JWT, signed
with the key chosen for the client, see [Choosing the signing key for a client](#choosing-the-signing-key-for-a-client),
and it also holds `iss` and `aud`. The content type is then `application/jwt`.

| `sign-user-info` | The client has registered `userinfo_signed_response_alg` | Response |
| :--- | :--- | :--- |
| `true` (default) | Yes or no | Signed JWT |
| `false` | No | Plain JSON (`application/json`) |
| `false` | Yes | Signed JWT |

**Encryption.** When the client has registered `userinfo_encrypted_response_alg`, the response is encrypted for the
client, with the same algorithms and key rules as the ID token, see [The ID token](#the-id-token). The content
encryption is given by `userinfo_encrypted_response_enc`, `A128CBC-HS256` by default. A signed response is signed and
then encrypted. When signing is off and the client has not asked for it, the response is encrypted only, as OpenID
Connect Core, Section 5.3.2, allows: the encrypted payload is the JSON claims set.

A client whose declared algorithms cannot be used, or that has no usable encryption key, gets the error
`invalid_client_metadata` (HTTP status 400) and no claims. This is logged at `WARN` as a client configuration error.

**Errors.** Errors follow RFC 6750, Section 3, including the `WWW-Authenticate` header. Every response, also an error
response, carries `Cache-Control: no-store`.

| Failure | Response |
| :--- | :--- |
| No access token | HTTP status 401, `WWW-Authenticate: Bearer` without an error code |
| The token is sent in the URI query, in more than one way, or is malformed | `invalid_request` (HTTP status 400) |
| The token is unknown, expired, revoked or already used | `invalid_token` (HTTP status 401) |
| The response cannot be signed or encrypted for the client | `invalid_client_metadata` (HTTP status 400) |

The request processing is found in [`UserInfoRequestProcessor`][UserInfoRequestProcessor].

<a name="where-codes-and-tokens-are-kept"></a>
### Where codes and tokens are kept

Authorization codes, access tokens and the `jti` values of used client assertions are kept in stores:
[`AuthorizationCodeStore`][AuthorizationCodeStore], [`AccessTokenStore`][AccessTokenStore] and
[`ClientAssertionReplayCache`][ClientAssertionReplayCache]. The defaults keep them in memory, which only serves the
node they run on. A deployment with several nodes keeps them in Redis, by setting `authn-server.storage.type`, or the
setting of each store, to `redis`, see [Running several nodes](configuration.html#running-several-nodes). Otherwise it
needs sticky sessions, so that the authentication request, the token request and the UserInfo request of a client
reach the same node.

The Redis stores give the same results as the in-memory ones, also when several nodes use them at once: a code is
redeemed, a single use access token is used, and a client assertion is accepted, on one node only.

A store bean of the application, for example an `AccessTokenStore`, replaces the store that the settings choose.
Without Spring Boot, stores are assigned on the configurer:

```java
oidc.authnRequestProcessor(p -> p
    .authorizationCodeStore(codes)
    .accessTokenStore(tokens)
    .clientAssertionReplayCache(assertions));
```

<a name="the-discovery-document"></a>
## The discovery document

The discovery document holds:

| Parameter | Value |
| :--- | :--- |
| `issuer` | The issuer. |
| `jwks_uri` | The URL of the JWKS. |
| `id_token_signing_alg_values_supported` | The algorithms the active signing keys can produce, those of the default key first. |
| `request_object_encryption_alg_values_supported` | The algorithms of the active decryption keys. Left out without decryption keys. |
| `scopes_supported` | The offered scopes. |
| `claims_supported` | The supported claims. |
| `acr_values_supported` | The authentication context URIs of the providers. |
| `subject_types_supported` | The subject types of the subject generator factory, by default `public` and `pairwise`. |
| `ui_locales_supported` | The configured UI locales. Left out when none are configured. |
| `authorization_endpoint` | The URL of the authorization endpoint. |
| `response_types_supported` | `code`. |
| `response_modes_supported` | `query` and `form_post`. |
| `claims_parameter_supported` | `true`. |
| `request_parameter_supported` | `true`. |
| `request_uri_parameter_supported` | `true`. |
| `require_request_uri_registration` | `true`. |
| `request_object_signing_alg_values_supported` | The algorithms that signed request objects are accepted with, and `none` when unsigned request objects are accepted. |
| `code_challenge_methods_supported` | `S256`. |
| `https://id.oidc.se/disco/userMessageSupported` | `true` when user messages are supported for OpenID Connect, see [Authentication Request Parameter Extensions for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/request-parameter-extensions-1_1.html). Left out otherwise. |
| `https://id.oidc.se/disco/userMessageSupportedMimeTypes` | `text/plain` and `text/markdown`, when user messages are supported. Left out otherwise. |
| `https://id.oidc.se/disco/authnProviderSupported` | `true`. |
| `token_endpoint` | The URL of the token endpoint. |
| `grant_types_supported` | `authorization_code`. |
| `token_endpoint_auth_methods_supported` | The enabled client authentication methods. |
| `token_endpoint_auth_signing_alg_values_supported` | The algorithms accepted for client assertions: those of `private_key_jwt` and of `client_secret_jwt`, when enabled. Never `none`. Left out when neither method is enabled. |
| `id_token_encryption_alg_values_supported` | `RSA-OAEP-256`, `RSA-OAEP` and `ECDH-ES`. |
| `id_token_encryption_enc_values_supported` | `A128CBC-HS256`, `A256CBC-HS512`, `A128GCM` and `A256GCM`. |
| `userinfo_endpoint` | The URL of the UserInfo endpoint. |
| `userinfo_signing_alg_values_supported` | The algorithms the active signing keys can produce, as for the ID token. |
| `userinfo_encryption_alg_values_supported` | `RSA-OAEP-256`, `RSA-OAEP` and `ECDH-ES`. |
| `userinfo_encryption_enc_values_supported` | `A128CBC-HS256`, `A256CBC-HS512`, `A128GCM` and `A256GCM`. |

<a name="extending-the-document"></a>
### Extending the document

Parameters are added through configuration, as a map of name to value. A value may be a string, a boolean, a list or
a map:

```yaml
authn-server:
  oidc:
    discovery:
      additional-parameters:
        service_documentation: https://op.example.com/docs
        op_policy_uri: https://op.example.com/policy
        "[https://example.com/disco/features]":
          - one
          - two
```

Names that hold a `:` or a `/` must be given within brackets. An additional parameter cannot replace a parameter that
the OpenID Provider sets, and the application does not start if it tries to, or if a value is invalid for a
parameter that OpenID Connect defines.

To change the document in ways the properties cannot express, assign a customizer in an
[adapter](configuration.html#adjusting-the-configuration-in-code). It gets the built document, including the
additional parameters, as a Nimbus `OIDCProviderMetadata`, and may change anything:

```java
@Bean
AuthnServerConfigurerAdapter discoveryAdjustments() {
  return (http, configurer) -> configurer.protocol(OidcProviderConfigurer.class, oidc -> oidc
      .discoveryEndpoint(discovery -> discovery.providerMetadataCustomizer(
          metadata -> metadata.setCustomParameter("https://example.com/disco/flag", true))));
}
```

A change that should appear in the discovery document belongs here, also when the OpenID Provider is a member of an
OpenID Federation: the entity configuration is built from the discovery document, so both documents get the change.
See [Changing the entity configuration](#changing-the-entity-configuration).

<a name="openid-federation"></a>
## OpenID Federation

The OpenID Provider can be a member of an [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html),
such as the Sweden Connect federation, where an OpenID Provider is registered from its published entity
configuration. This section is about the OpenID Provider's own membership. Clients resolved through a federation are
described in [The federation backend](client-registry.html#the-federation-backend).

<a name="joining-a-federation"></a>
### Joining a federation

Federation is off by default. To join a federation, enable it, and give the federation keys and the authority hints:

```yaml
authn-server:
  oidc:
    federation:
      enabled: true
      authority-hints:
        - https://fed.swedenconnect.se/intermediate
      keys:
        - credential:
            bundle: federation-2026
```

- The **entity identifier** is the issuer.
- The **authority hints** are the entity identifiers of the immediate superiors of the OpenID Provider in the
  federation, the intermediate entities or trust anchors it is registered with. At least one is required, since the
  OpenID Provider is a leaf entity (OpenID Federation 1.0, Section 3.1.2).
- The **federation keys** sign the entity configuration, see [Federation keys](#federation-keys).

The application does not start when federation is enabled and the keys or the authority hints are missing. It does
not start either when the [descriptive metadata](#descriptive-metadata) lacks what the Sweden Connect federation
requires: at least one e-mail address in `contacts`, and a `logo_uri` that is an HTTPS URL.

All properties are listed in [Configuration](configuration.html#oidc-federation). In code, the same settings are made
with `OidcProviderConfigurer.federation(...)`, see [`OidcFederationConfigurer`][OidcFederationConfigurer].

<a name="federation-keys"></a>
### Federation keys

The federation keys are separate from the OpenID Connect signing keys, as OpenID Federation 1.0, Section 3.1.1,
recommends. They are configured as a list, like the [signing keys](#signing-keys), and a key is:

- **active**: published in the `jwks` of the entity configuration and used for signing, or
- **future**: published but never used.

The first active key signs the entity configuration. The key requirements and the key IDs follow the same rules as for
the OpenID Connect keys, see [Key requirements and key IDs](#key-requirements-and-key-ids). The signing algorithm is
`RS256` for an RSA key and the `ES` algorithm of the curve for an EC key, which is what both the Swedish OpenID
Federation profile, Section 6, and Sweden Connect Security Requirements, Section 3, allow.

A federation key is rolled over in the same way as a signing key, following Section 4 of the security requirements:

1. Add the new key as `future`. It is published in the entity configuration but not used.
2. Wait at least as long as the lifetime of the entity configuration, so that every party that has cached the old
   entity configuration has fetched a new one.
3. Make the new key `active` and remove the old key.

```yaml
authn-server:
  oidc:
    federation:
      keys:
        - credential:
            bundle: federation-2026
        - credential:
            bundle: federation-2027
          state: future
```

<a name="the-entity-configuration"></a>
### The entity configuration

The entity configuration is a signed JWT with the type `entity-statement+jwt`, served with the content type
`application/entity-statement+jwt`. It holds, following OpenID Federation 1.0, Section 3:

| Claim | Value |
| :--- | :--- |
| `iss` and `sub` | The entity identifier, which is the issuer. |
| `iat` and `exp` | When it was signed, and when it expires. The lifetime is 1 day by default, `authn-server.oidc.federation.entity-configuration-lifetime`. |
| `jwks` | The federation keys, active and future. |
| `authority_hints` | The configured authority hints. |
| `trust_marks` | The trust marks of the OpenID Provider, when it has any, see [The trust marks of the OpenID Provider](#the-trust-marks-of-the-openid-provider). |
| `metadata` | The `openid_provider` metadata only. The OpenID Provider is a leaf entity, and never publishes `federation_entity` metadata (Swedish OpenID Federation profile, Section 2.2). |

The `openid_provider` metadata is the [discovery document](#the-discovery-document), as it is after the additional
parameters and the customizer of the discovery document have been applied, with these parameters added unless the
discovery document already has them:

- the [descriptive metadata](#descriptive-metadata), such as `display_name#sv`, `organization_name#sv`, `logo_uri` and
  `contacts`,
- `client_registration_types_supported` with the value `automatic`, since clients are resolved through the
  federation.

**How it is kept fresh.** The signed entity configuration is kept in memory and served from there. Each time it is
asked for, the OpenID Provider checks whether it is still fresh, and builds and signs it again only when needed:

- when three quarters of its lifetime have passed, so that a new version is published well before the old one expires,
  as Section 2.4.1 of the Swedish OpenID Federation profile requires, and
- when its content has changed: a trust mark has been renewed, added or has expired, or a federation key has changed
  state.

The OpenID Connect keys are part of the discovery document. They, like the federation keys, are read at startup, so a
change of key state takes effect when the application is restarted, and the entity configuration is then built anew.

<a name="descriptive-metadata"></a>
### Descriptive metadata

The descriptive information about the service and its organization is given once for all protocols, under
`authn-server.entity-information`, see [Entity information](configuration.html#entity-information). The same values
are then published in the SAML metadata and in the OpenID Provider metadata, and a protocol may override any of them.

The information is mapped to the parameters of
[Sweden Connect OpenID Connect Metadata Requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html),
Section 3:

| Parameter | Taken from |
| :--- | :--- |
| `display_name` | The UI display names, one parameter per language, such as `display_name#sv` and `display_name#en`. |
| `description` | The UI descriptions, one parameter per language. |
| `organization_name` | The organization names, one parameter per language. |
| `organization_uri` | The first organization URL. |
| `organization_identifier` | `urn:glue:iso6523:0007:<number>` when the organization number is ten digits, and otherwise left out. |
| `logo_uri` | The first logo without a language, or else the first logo. A logo given as a path is relative to the base URL. |
| `contacts` | The e-mail addresses of the technical and support contact persons, without duplicates. A `mailto:` prefix is removed. |

Each parameter may also be given directly under `authn-server.oidc.entity-information`, which wins over the mapped
value, see [Entity information for OpenID Connect](configuration.html#oidc-entity-information). In code, the overrides
are `OidcProviderConfigurer.entityInformation(...)` and `OidcProviderConfigurer.entityMetadata(...)`, and the resulting
values are given by `OidcProviderConfigurer.getEntityMetadata()`, see [`OidcEntityMetadata`][OidcEntityMetadata].

The parameters are published in the entity configuration and not in the discovery document. When the discovery
document holds one of them, for example set by its customizer, the value of the discovery document is used in both
documents, so that they never disagree.

<a name="the-trust-marks-of-the-openid-provider"></a>
### The trust marks of the OpenID Provider

The trust marks that the OpenID Provider holds, such as the level of assurance trust marks of the Sweden Connect
federation, are published in its entity configuration. They are configured per trust mark type, separately from the
trust marks that are required of clients, since the OpenID Provider may hold other marks than those it requires:

```yaml
authn-server:
  oidc:
    federation:
      trust-marks:
        - type: https://id.swedenconnect.se/loa/loa3
          issuer: https://fed.swedenconnect.se/tmi-loa
          endpoint: https://fed.swedenconnect.se/tmi-loa/trust_mark
          jwks: file:/opt/config/tmi-loa-jwks.json
      trust-mark-cache-directory: /var/op/trust-marks
```

Each trust mark is fetched from the trust mark endpoint of its issuer (OpenID Federation 1.0, Section 8.6) when the
application starts, and again when three quarters of its lifetime have passed. A trust mark without `exp` is kept as
it is and never fetched again.

**The check.** A fetched trust mark is only published when it passes the check: its signature is verified with the
configured keys of the issuer (`jwks`), `typ` must be `trust-mark+jwt`, `iss` must be the issuer, `sub` must be the
entity identifier of the OpenID Provider, `trust_mark_type` must be the configured type, and it must not have expired.
The trust chain of the issuer is not validated.

**Failures.** A trust mark that cannot be fetched, or that fails the check, never stops the OpenID Provider, at startup
or later:

- The failure is logged as an error, and a new attempt is made after the retry interval, 5 minutes by default,
  `authn-server.oidc.federation.trust-mark-retry-interval`.
- The current trust mark, if there is one, is still published until it expires.
- At startup without a trust mark, the entity configuration is published without it, and gets it once it has been
  fetched.

The state of each trust mark type, whether a valid trust mark is published and whether the latest attempt failed, is
recorded in [`ProviderTrustMarks`][ProviderTrustMarks]. With Spring Boot it is a bean, so that a health check can read
it with `getStates()`.

**The cache directory.** When `trust-mark-cache-directory` is set, every accepted trust mark is written there, and the
stored trust marks are read at startup. This means that the OpenID Provider publishes its trust marks at once after a
restart, also when an issuer cannot be reached. A stored trust mark that has expired, or that fails the check, is not
used. Without a cache directory nothing is stored.

**Several nodes.** The trust marks and their state are kept in a [`ProviderTrustMarkStore`][ProviderTrustMarkStore],
in memory by default. When they are kept in Redis, by `authn-server.storage.type` or
`authn-server.oidc.storage.trust-marks`, one node at a time fetches and renews them, every node publishes them, and
`getStates()` gives the same answer on every node. The cache directory is then not used. See
[Background jobs and trust marks](configuration.html#background-jobs-in-a-cluster).

<a name="changing-the-entity-configuration"></a>
### Changing the entity configuration

There are two ways to change what the OpenID Provider publishes, and they differ in which documents they reach:

- **The discovery document**, `authn-server.oidc.discovery.additional-parameters` and the discovery customizer, see
  [Extending the document](#extending-the-document). The entity configuration is built from the discovery document, so
  a change made here reaches **both** documents. A change that only concerns the OpenID Provider metadata belongs
  here.
- **The entity configuration**, `authn-server.oidc.federation.additional-parameters` and the entity configuration
  customizer. They are applied last and reach **only** the entity configuration. Use them for the claims of the
  entity statement, such as `trust_anchor_hints`, and for metadata that only makes sense in a federation.

The additional parameters of the entity configuration are set as claims. A `metadata` parameter is merged into the
metadata, per entity type and parameter:

```yaml
authn-server:
  oidc:
    federation:
      additional-parameters:
        trust_anchor_hints:
          - https://fed.swedenconnect.se/trust-anchor
```

The customizer gets the claims as a mutable map, where `metadata` and its `openid_provider` entry are mutable maps
too, and may change anything but `iss`, `sub`, `iat` and `exp`, which the OpenID Provider sets. It runs each time the
entity configuration is built. Publishing `federation_entity` metadata stops the application from starting.

```java
@Bean
AuthnServerConfigurerAdapter entityConfigurationAdjustments() {
  return (http, configurer) -> configurer.protocol(OidcProviderConfigurer.class, oidc -> oidc
      .federation(federation -> federation.entityConfigurationCustomizer(claims -> {
        @SuppressWarnings("unchecked")
        final Map<String, Object> op =
            (Map<String, Object>) ((Map<String, Object>) claims.get("metadata")).get("openid_provider");
        op.put("https://example.com/federation-only", true);
      })));
}
```

[AccessTokenStore]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/token/AccessTokenStore.java
[AuthorizationCodeStore]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/token/AuthorizationCodeStore.java
[ClientAssertionReplayCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/token/ClientAssertionReplayCache.java
[OidcEntityMetadata]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/federation/OidcEntityMetadata.java
[OidcFederationConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/config/OidcFederationConfigurer.java
[OidcAuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/authentication/OidcAuthenticationRequirements.java
[OidcAuthnRequestAuthenticationConverter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/authnrequest/OidcAuthnRequestAuthenticationConverter.java
[OidcAuthnRequestAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/authnrequest/OidcAuthnRequestAuthenticationProvider.java
[OidcAuthnRequestData]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/authnrequest/OidcAuthnRequestData.java
[OidcUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/error/OidcUnrecoverableError.java
[ProviderTrustMarkStore]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/federation/ProviderTrustMarkStore.java
[ProviderTrustMarks]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/federation/ProviderTrustMarks.java
[SigningKeySelector]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/keys/SigningKeySelector.java
[SupportedScopesAndClaims]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/scope/SupportedScopesAndClaims.java
[UserInfoRequestProcessor]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/userinfo/UserInfoRequestProcessor.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
