![Logo](images/sweden-connect.png)

# The OpenID Provider

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes the OpenID Provider: where it publishes its discovery document and its keys, how the keys are
configured and rolled over, how the key that a message to a client is signed with is chosen, how the offered scopes,
the supported claims and the authentication contexts are worked out from the authentication providers, and how to
extend the discovery document. The properties are described in
[Configuration](configuration.html#the-openid-provider).

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
- [The discovery document](#the-discovery-document)
    - [Extending the document](#extending-the-document)

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

The discovery document is always published at the issuer followed by `/.well-known/openid-configuration`, as OpenID
Connect Discovery, Section 4, requires. It is therefore not under the OIDC path. An issuer with a path moves the
document along with it: with the issuer `https://op.example.com/op1`, the document is published at
`https://op.example.com/op1/.well-known/openid-configuration`. The issuer must be the base URL or begin with it, since
the server can only serve paths under the base URL.

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

UserInfo responses are signed by default. When they are, a client that has not registered
`userinfo_signed_response_alg` still gets a signed response. Turn signing off with `authn-server.oidc.sign-user-info`.

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
| `https://id.oidc.se/disco/userMessageSupported` | `true` when user messages are supported for OpenID Connect, see [Authentication Request Parameter Extensions for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/request-parameter-extensions.html). Left out otherwise. |

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

[SigningKeySelector]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/keys/SigningKeySelector.java
[SupportedScopesAndClaims]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/scope/SupportedScopesAndClaims.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
