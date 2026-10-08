![Logo](images/sweden-connect.png)

# Configuration

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes how the Spring Authentication Server is configured: the properties of the Spring Boot
auto-configuration, how the URLs of the server are laid out, how to run several nodes that share their state through
Redis, how an application adjusts the configuration in code, and how the server is set up without Spring Boot.

- [Getting started](#getting-started)
- [Enabling protocols](#enabling-protocols)
- [URL layout](#url-layout)
- [Shared settings](#shared-settings)
    - [Single sign-on](#single-sign-on)
    - [Subject identifiers](#subject-identifiers)
    - [Entity information](#entity-information)
- [The SAML Identity Provider](#the-saml-identity-provider)
    - [Credentials](#credentials)
    - [Endpoints](#endpoints)
    - [The IdP metadata](#the-idp-metadata)
    - [Service Provider metadata](#sp-metadata)
    - [Request processing](#request-processing)
    - [Replay protection](#replay-protection)
    - [Requester acceptance](#requester-acceptance)
- [The OpenID Provider](#the-openid-provider)
    - [Keys](#oidc-keys)
    - [Clients](#oidc-clients)
    - [OIDC endpoints](#oidc-endpoints)
    - [Authorization requests](#oidc-authorization-requests)
    - [Requester acceptance](#oidc-requester-acceptance)
    - [The token endpoint and tokens](#oidc-token-endpoint)
    - [Scopes and claims](#oidc-scopes-and-claims)
    - [The discovery document](#oidc-discovery)
    - [Entity information for OpenID Connect](#oidc-entity-information)
    - [OpenID Federation](#oidc-federation)
    - [Clients from OpenID Federation](#oidc-federation-clients)
    - [Joining Sweden Connect](#joining-sweden-connect)
- [Running several nodes](#running-several-nodes)
    - [Dependencies](#redis-dependencies)
    - [Where state is kept](#where-state-is-kept)
    - [The Redis connection](#the-redis-connection)
    - [Key names](#redis-key-names)
    - [The TLS host name check](#redis-host-name-check)
    - [Redis Cluster](#redis-cluster)
    - [Background jobs and trust marks](#background-jobs-in-a-cluster)
- [Adjusting the configuration in code](#adjusting-the-configuration-in-code)
- [Using the configurers without Spring Boot](#using-the-configurers-without-spring-boot)
- [Migrating from saml-identity-provider](#migrating-from-saml-identity-provider)

<a name="getting-started"></a>
## Getting started

Include the starter for each protocol the server offers:

- `authn-server-saml-spring-boot-starter` for a SAML Identity Provider.
- `authn-server-oidc-spring-boot-starter` for an OpenID Provider.

A server that offers both protocols includes both starters.

```xml
<dependency>
  <groupId>se.swedenconnect.spring.authnserver</groupId>
  <artifactId>authn-server-saml-spring-boot-starter</artifactId>
  <version>${authn-server.version}</version>
</dependency>
```

A single-protocol starter never pulls in the other protocol. The smallest working SAML Identity Provider needs a base
URL, a credential and a source of Service Provider metadata:

```yaml
authn-server:
  base-url: https://idp.example.com
  saml:
    enabled: true
    credentials:
      default-credential:
        bundle: idp-credential
    metadata-providers:
      - location: https://md.swedenconnect.se/role/sp.xml
        validation-certificate: file:/opt/config/metadata-signing.crt
        backup-location: /var/idp/sp-metadata-backup.xml
```

With this, the IdP metadata is published at `https://idp.example.com/saml2/metadata`.

The smallest working OpenID Provider needs a base URL and a signing key:

```yaml
authn-server:
  base-url: https://op.example.com
  oidc:
    enabled: true
    keys:
      signing:
        - credential:
            bundle: op-sign
```

With this, the discovery document is published at `https://op.example.com/.well-known/openid-configuration`.

The authentication modules are
declared as [`UserAuthenticationProvider`][UserAuthenticationProvider] beans, see
[Writing an authentication module](authentication-module.html).

The whole server uses one `SecurityFilterChain`, named `authnServerSecurityFilterChain`. It matches the endpoints of
the enabled protocols and nothing else, so the application is free to set up its own chains for its other pages.

The server audits its authentication flows with spring-audit-support, which refuses to start unless
`spring.application.name` is set. Where the audit events are stored is configured with spring-audit-support's
`audit.*` properties. See [Auditing](audit.html).

<a name="enabling-protocols"></a>
## Enabling protocols

A protocol is offered when its module is on the classpath and it has been enabled:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.saml.enabled` | Whether the SAML Identity Provider is enabled. | `false` |
| `authn-server.oidc.enabled` | Whether the OpenID Provider is enabled. | `false` |

The application does not start if no protocol is enabled, or if a protocol is enabled but its module is not on the
classpath.

<a name="url-layout"></a>
## URL layout

Every URL of the server is built from three parts:

1. The **base URL**, `authn-server.base-url`: protocol, host and context path, for example
   `https://idp.example.com/auth`. It must not end with a `/`.

2. The **protocol path**, for example `authn-server.saml.path`, which defaults to `/saml2`, or
   `authn-server.oidc.path`, which defaults to `/oidc`. All endpoints of the protocol are placed under it.

3. The **endpoint**, relative to the protocol path, for example `/metadata`.

So with the defaults, the SAML metadata is published at `https://idp.example.com/auth/saml2/metadata`. Changing the
protocol path moves every endpoint of that protocol, both where it is served and where the SAML metadata points. An
empty protocol path places the endpoints directly under the base URL.

A protocol may also place some endpoints directly under the base URL. The OpenID Provider does this for its discovery
document, which is published at the issuer followed by `/.well-known/openid-configuration`. The issuer defaults to the
base URL, so the document is found at `https://idp.example.com/auth/.well-known/openid-configuration`. An issuer with a
path, which must begin with the base URL, moves the document along with it, see
[The OpenID Provider](openid-provider.html#where-things-are-published). The OpenID Federation entity configuration,
at the issuer followed by `/.well-known/openid-federation`, is placed in the same way.

The SAML entity ID defaults to the base URL. In a server that offers both protocols, the SAML entity ID and the OpenID
Connect issuer may thereby be the same URL. That is fine, since they are identifiers in different protocols. Assign
`authn-server.saml.entity-id` to use another entity ID.

SAML Holder-of-key needs client TLS, which normally means another host or port. For that case,
`authn-server.saml.hok-base-url` replaces the base URL for the Holder-of-key endpoints. They are then the Holder-of-key
base URL, the SAML path and the endpoint.

<a name="shared-settings"></a>
## Shared settings

The settings that are common to all protocols are placed directly under `authn-server`. Some of them may be overridden
per protocol, under the protocol's prefix, for example `authn-server.saml.clock-skew`. A protocol value, when set,
wins over the shared one.

| Property | Description | Default value | Per protocol |
| :--- | :--- | :--- | :--- |
| `authn-server.base-url` | The base URL of the server, see [URL layout](#url-layout). | Required | No |
| `authn-server.sso.*` | The single sign-on policy, see [Single sign-on](#single-sign-on). | See below | Yes |
| `authn-server.clock-skew` | The time that clocks of other parties may differ from the server clock. | 30 seconds | Yes |
| `authn-server.supports-user-message` | Whether the server can display a user message sent by the requester. For SAML, see the [User Message Extension](https://docs.swedenconnect.se/technical-framework/updates/18_-_User_Message_Extension_in_SAML_Authentication_Requests.html). | `false` | Yes |
| `authn-server.subject-identifier.*` | How subject identifiers are computed, see [Subject identifiers](#subject-identifiers). | See below | Yes |
| `authn-server.entity-information.*` | The names, logos and contact persons that every protocol publishes, see [Entity information](#entity-information). | - | Yes |
| `authn-server.authn-flow-max-age` | How long the server waits for the user to come back from an authentication module that has pages of its own. Applied to the session-based storage of every redirect provider. | 30 minutes | No |
| `authn-server.storage.type` | Where the HTTP session and the stores are kept, `memory` or `redis`, see [Running several nodes](#running-several-nodes). | `memory` | Per store |
| `authn-server.cache-directory` | A directory where the server keeps state that should survive a restart when it keeps its state in memory: the OpenID Provider's own trust marks, the OpenID Federation client cache and the record of known clients, see [State that survives a restart](management.html#state-that-survives-a-restart). | Nothing is kept | No |

<a name="single-sign-on"></a>
### Single sign-on

The properties give the [`SsoPolicy`][SsoPolicy] of the server, described in
[Writing an authentication module](authentication-module.html#the-policy).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `enabled` | Whether single sign-on is allowed at all. | `true` |
| `time-limit` | How old a previous authentication may be for it to be reused. Must be positive. | 60 minutes |
| `same-requester-required` | Whether a previous authentication may only be reused for the requester it was made for. | `true` |

The protocol policy under `authn-server.saml.sso` takes the values it does not set from `authn-server.sso`. For
example, the following gives SAML a time limit of 20 minutes and lets any SAML Service Provider reuse an
authentication, while OpenID Connect keeps the default policy with a time limit of 20 minutes:

```yaml
authn-server:
  sso:
    time-limit: 20m
  saml:
    sso:
      same-requester-required: false
```

An authentication provider may have a policy of its own, which wins over both. The order is: provider, protocol,
shared.

A policy that allows single sign-on for as long as the user's session lives, without a time limit, cannot be given as
properties. Assign `SsoPolicy.forSessionLifetime()`, or a policy with no time limit, in an
[adapter](#adjusting-the-configuration-in-code).

<a name="subject-identifiers"></a>
### Subject identifiers

The SAML `NameID` and the OpenID Connect `sub` are computed from the user identity and a server secret, see
[Attributes](attributes.html).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `secret` | The secret that takes part in the computation. The UTF-8 bytes of the string are used. Assigning a secret is strongly recommended. | None |
| `hash-algorithm` | The JCE name of the hash algorithm. | `SHA-256` |

<a name="entity-information"></a>
### Entity information

The descriptive information about the service and its organization is given once, under
`authn-server.entity-information`, and published by every protocol: in the SAML metadata, and in the `openid_provider`
metadata of the OpenID Federation entity configuration.

| Property | Description |
| :--- | :--- |
| `ui-info.display-names` | The name of the service, as shown to users, keyed by language tag. |
| `ui-info.descriptions` | A short description of the service, keyed by language tag. |
| `ui-info.logotypes[]` | The logos. Each has `height`, `width`, an optional `language-tag`, and either `url` or `path`. A `path` is relative to the base URL. |
| `organization.names` | The names of the organization, keyed by language tag. |
| `organization.display-names` | The display names of the organization, keyed by language tag. |
| `organization.urls` | The web pages of the organization, keyed by language tag. |
| `organization.number` | The organization number. |
| `contact-persons.*` | The contact persons, keyed by type: `technical`, `support`, `administrative`, `billing`, `other` or `security`. Each has `company`, `given-name`, `surname`, `email-addresses[]` and `telephone-numbers[]`. |

```yaml
authn-server:
  entity-information:
    ui-info:
      display-names:
        sv: Exempel-IdP
        en: Example Identity Provider
      logotypes:
        - path: /images/logo.svg
          height: 256
          width: 256
    organization:
      names:
        sv: Exempel AB
        en: Example Ltd
      urls:
        sv: https://www.example.se
      number: "5561234567"
    contact-persons:
      technical:
        email-addresses:
          - operations@example.com
      support:
        email-addresses:
          - support@example.com
```

A protocol may override any part of it, in the same way as the [single sign-on settings](#single-sign-on): the SAML
values are given under `authn-server.saml.metadata`, see [The IdP metadata](#the-idp-metadata), and the OpenID Connect
values under `authn-server.oidc.entity-information`, see
[Entity information for OpenID Connect](#oidc-entity-information). A protocol value replaces the shared value it
corresponds to: each of the display names, the descriptions, the logos, the organization names, display names, URLs
and number is replaced as a whole, and a contact person replaces the shared contact person of the same type while the
other shared contact persons are kept.

How the information is published is described in [The IdP metadata](#the-idp-metadata) for SAML, and in
[Descriptive metadata](openid-provider.html#descriptive-metadata) for OpenID Connect.

<a name="the-saml-identity-provider"></a>
## The SAML Identity Provider

The SAML properties are placed under `authn-server.saml`.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `enabled` | Whether the SAML Identity Provider is enabled. | `false` |
| `path` | The SAML path, see [URL layout](#url-layout). | `/saml2` |
| `entity-id` | The SAML entity ID of the Identity Provider. | The base URL |
| `hok-base-url` | The base URL for the Holder-of-key endpoints, when they need another host or port than the base URL. Must not end with a `/`. | The base URL |
| `requires-signed-requests` | Whether the Identity Provider requires signed authentication requests. Published in the metadata as `WantAuthnRequestsSigned`. | `true` |
| `sso.*` | The single sign-on policy for SAML, see [Single sign-on](#single-sign-on). | `authn-server.sso.*` |
| `clock-skew` | The clock skew for SAML. | `authn-server.clock-skew` |
| `supports-user-message` | Whether user messages are supported for SAML. | `authn-server.supports-user-message` |
| `subject-identifier.*` | The subject identifier settings for SAML. | `authn-server.subject-identifier.*` |
| `credentials.*` | The credentials, see [Credentials](#credentials). | Required |
| `endpoints.*` | The endpoints, see [Endpoints](#endpoints). | See below |
| `metadata.*` | The IdP metadata, see [The IdP metadata](#the-idp-metadata). | See below |
| `metadata-providers[].*` | The sources of Service Provider metadata, see [Service Provider metadata](#sp-metadata). | Required |
| `max-message-age` | The maximum age of a received authentication request. | 3 minutes |
| `assertions.encrypt` | Whether assertions are encrypted, see [Request processing](#request-processing). | `true` |
| `assertions.not-after` | How long an assertion is valid after it was issued. Gives `NotOnOrAfter` of the conditions and of the subject confirmation. Must be positive. | 5 minutes |
| `assertions.not-before` | How long before it was issued an assertion is valid. Gives `NotBefore` of the conditions. | 10 seconds |
| `authn-context.*` | How requested authentication contexts are resolved, see [Request processing](#request-processing). | Exact comparison only |
| `replay.*` | The protection against replayed requests, see [Replay protection](#replay-protection). | See below |
| `requester-acceptance.*` | Which Service Providers may use the Identity Provider, see [Requester acceptance](#requester-acceptance). | Every Service Provider |

The values are checked when the filter chain is built, and the application does not start if a required value is
missing or a value is invalid.

<a name="credentials"></a>
### Credentials

The credentials are configured through the [credentials-support](https://docs.swedenconnect.se/credentials-support/)
library. Each credential is a
[PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java),
that is, a reference to a credential bundle, a key store entry, or PEM files.

| Property | Description | Bean name |
| :--- | :--- | :--- |
| `default-credential.*` | The default credential. Used for each use below that has no credential of its own. | `authn-server.saml.credentials.Default` |
| `sign.*` | The credential that the Identity Provider signs responses and assertions with. | `authn-server.saml.credentials.Sign` |
| `future-sign` | A certificate that will be the future signing certificate. It is set before a key rollover, so that it is published in the metadata. A resource or the PEM encoding of the certificate. | `authn-server.saml.credentials.FutureSign` |
| `encrypt.*` | The encryption credential. Service Providers encrypt data for the Identity Provider with its certificate, and the Identity Provider decrypts with it. | `authn-server.saml.credentials.Encrypt` |
| `previous-encrypt.*` | The previous encryption credential, kept after a key rollover. | `authn-server.saml.credentials.PreviousEncrypt` |
| `metadata-sign.*` | The credential that the Identity Provider signs its metadata with. | `authn-server.saml.credentials.MetadataSign` |

The rules:

- A signing credential is required. Without `sign`, the default credential is used.
- An encryption credential is required. Without `encrypt`, the default credential is used.
- Without `metadata-sign`, the metadata is signed with the default credential. Without either, the metadata is not
  signed.

Each credential may instead be declared as a bean of the type
[PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java)
(`X509Certificate` for the future signing certificate) with the bean name in the table. The bean then replaces the
property.

:raised_hand: Configuring the credentials as credential bundles, and referring to them, is recommended:

```yaml
credential:
  bundles:
    keystore:
      idp-store:
        location: file:/opt/config/idp-credentials.jks
        password: secret
        type: JKS
    jks:
      sign:
        name: "IdP Signature Credential"
        store-reference: idp-store
        key:
          alias: sign
          key-password: secret
      encrypt:
        name: "IdP Encrypt/decrypt Credential"
        store-reference: idp-store
        key:
          alias: encrypt
          key-password: secret

authn-server:
  saml:
    credentials:
      sign:
        bundle: sign
      encrypt:
        bundle: encrypt
      metadata-sign:
        bundle: sign
```

<a name="endpoints"></a>
### Endpoints

The endpoints are given relative to the SAML path, see [URL layout](#url-layout). They are placed under
`authn-server.saml.endpoints`.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `redirect-authn` | Where authentication requests are received with the HTTP redirect binding. | `/redirect/authn` |
| `post-authn` | Where authentication requests are received with the HTTP POST binding. | `/post/authn` |
| `hok-redirect-authn` | Where authentication requests are received with the HTTP redirect binding and Holder-of-key. Holder-of-key is not offered unless set. | - |
| `hok-post-authn` | Where authentication requests are received with the HTTP POST binding and Holder-of-key. Holder-of-key is not offered unless set. | - |
| `metadata` | Where the IdP metadata is published. | `/metadata` |

With the default SAML path, the endpoints are `/saml2/redirect/authn`, `/saml2/post/authn` and `/saml2/metadata`.

<a name="the-idp-metadata"></a>
### The IdP metadata

The Identity Provider publishes its SAML metadata at the metadata endpoint. The response has the content type
`application/samlmetadata+xml` when the request accepts it, and `application/xml` otherwise.

Most of the metadata is worked out from the rest of the configuration:

- The entity ID.
- The `SingleSignOnService` elements, from the endpoints, including the Holder-of-key endpoints when they are set.
- `WantAuthnRequestsSigned`, from `requires-signed-requests`.
- The `KeyDescriptor` elements: the signing certificate, the future signing certificate, and the encryption
  certificate. When the signing or the encryption credential is not set, the default credential is published for that
  use, or for both uses.
- The `NameIDFormat` elements. When a
  [`NameIDGeneratorFactory`](https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/nameid/NameIDGeneratorFactory.java)
  bean is declared, its formats are used. Otherwise the persistent and transient formats are declared.
- The assurance certification attribute, holding the authentication contexts that the authentication providers
  support.
- The entity category attribute, holding the entity categories that the authentication providers declare. When the
  providers declare any entity categories and user messages are supported for SAML, the
  `http://id.swedenconnect.se/general-ec/1.0/supports-user-message` category is added.

The rest is given under `authn-server.saml.metadata`:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `template` | A template for the metadata, an XML document holding partial SAML metadata. The values of the configuration are added to it, or replace what it holds. | - |
| `cache-duration` | How long the published metadata may be cached. | 24 hours |
| `validity-period` | For how long published metadata is valid. The metadata is signed again when needed. | 7 days |
| `digest-methods[]` | Algorithm URIs for the `alg:DigestMethod` elements. | - |
| `include-digest-methods-under-role` | Whether the `alg:DigestMethod` elements are placed under the `IDPSSODescriptor` instead of under the `EntityDescriptor`. | `false` |
| `signing-methods[].*` | The `alg:SigningMethod` elements, each with `algorithm` and optionally `min-key-size` and `max-key-size`. | - |
| `include-signing-methods-under-role` | Whether the `alg:SigningMethod` elements are placed under the `IDPSSODescriptor` instead of under the `EntityDescriptor`. | `false` |
| `encryption-methods[].*` | The `md:EncryptionMethod` elements of the encryption key, see below. They must match the encryption key. | - |
| `ui-info.*` | The `mdui:UIInfo` element, see below. | `authn-server.entity-information.ui-info.*` |
| `requested-principal-selection[]` | Attribute names for the `psc:RequestedPrincipalSelection` extension. | - |
| `organization.*` | The `md:Organization` element, see below. | `authn-server.entity-information.organization.*` |
| `contact-persons.*` | The `md:ContactPerson` elements, keyed by type: `technical`, `support`, `administrative`, `billing`, `other` or `security`. A `security` contact is published as `other` with the REFEDS security contact type. Each has `company`, `given-name`, `surname`, `email-addresses[]` and `telephone-numbers[]`. | `authn-server.entity-information.contact-persons.*` |

An encryption method has:

| Property | Description |
| :--- | :--- |
| `algorithm` | The algorithm URI. |
| `key-size` | The key size. |
| `oaep-params` | The OAEP parameters, in Base64. |
| `digest-method` | The digest algorithm URI, for key transport algorithms that need one. |

`ui-info`, `organization` and `contact-persons` have the shape of the [shared entity information](#entity-information),
and override it for SAML. Values that are not given here are taken from `authn-server.entity-information`, so the
information is normally given only there. The organization number is published as `mdorgext:OrganizationNumber`.

In the following example, SAML gets a display name of its own and a security contact on top of the shared contact
persons, and takes everything else from the shared information:

```yaml
authn-server:
  saml:
    metadata:
      ui-info:
        display-names:
          en: Example Identity Provider (SAML)
          sv: Exempel-IdP (SAML)
      contact-persons:
        security:
          email-addresses:
            - security@example.com
```

To change the metadata in ways the properties cannot express, assign a customizer that gets the built
`EntityDescriptor` before it is signed:

```java
configurer.protocol(Saml2IdpConfigurer.class, saml -> saml.idpMetadataEndpoint(
    metadata -> metadata.entityDescriptorCustomizer(ed -> { ... })));
```

<a name="sp-metadata"></a>
### Service Provider metadata

The Identity Provider finds the Service Providers in the [client registry](client-registry.html). The metadata sources
given here become the SAML backend of the registry, see [SAML: metadata sources](client-registry.html#saml-metadata-sources) for how each
kind of source is read. A SAML Identity Provider needs at least one source, unless the application assigns a client
registry or a SAML backend of its own in an [adapter](#adjusting-the-configuration-in-code).

Each entry of `authn-server.saml.metadata-providers[]` has:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `location` | The location of the metadata: a URL, a file or a classpath resource. | Required |
| `https-trust-bundle` | For an HTTPS location, the name of a [Spring SSL bundle](https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl) that gives the trusted certificates. | The Java trust store |
| `skip-hostname-verification` | For an HTTPS location, whether hostname verification is skipped. For testing only. | `false` |
| `backup-location` | For a URL location, where downloaded metadata is backed up, so that the server can start when the source cannot be reached. A file, or a directory for MDQ. Strongly recommended. | - |
| `mdq` | For a URL location, whether the [MDQ protocol](https://www.ietf.org/id/draft-young-md-query-17.html) is used. | `false` |
| `validation-certificate` | The certificate that the metadata signature is validated with. A resource or the PEM encoding of the certificate. Strongly recommended for a URL location. | - |
| `http-proxy.*` | For a URL location, an HTTP proxy: `host`, `port`, and optionally `user-name` and `password`. | - |

Several sources are combined into one, searched in the order they are given.

<a name="request-processing"></a>
### Request processing

How the Identity Provider processes an authentication request, and which failures are answered to the Service
Provider, is described in [The SAML Identity Provider](saml-identity-provider.html). These properties affect it:

- `requires-signed-requests`: whether every request must be signed. A request must also be signed if the Service
  Provider metadata states `AuthnRequestsSigned`.
- `max-message-age` and `clock-skew`: how old a request may be, and how much the clocks may differ.
- `assertions.encrypt`: whether assertions are encrypted. When they are, a request from a Service Provider whose
  metadata has no encryption key is answered with `Requester` / `RequestDenied`.
- `supports-user-message`: when user messages are supported, a `UserMessage` with a MIME type that is not supported
  is answered with an error. When they are not, such a message is ignored.
- `subject-identifier.*`: the secret and hash algorithm of the `NameID` generator, which also checks the
  `NameIDPolicy` of the request.

The `exact` comparison of a `RequestedAuthnContext` is always supported. The `minimum`, `better` and `maximum`
comparisons are supported when a mapping is given under `authn-server.saml.authn-context`: `minimum-mappings`,
`better-mappings` and `maximum-mappings`. Each maps a requested URI to the URIs it means for that comparison. The keys
must be given within brackets, since they are URLs:

```yaml
authn-server:
  saml:
    authn-context:
      minimum-mappings:
        "[http://id.elegnamnden.se/loa/1.0/loa2]":
          - http://id.elegnamnden.se/loa/1.0/loa2
          - http://id.elegnamnden.se/loa/1.0/loa3
          - http://id.elegnamnden.se/loa/1.0/loa4
        "[http://id.elegnamnden.se/loa/1.0/loa3]":
          - http://id.elegnamnden.se/loa/1.0/loa3
          - http://id.elegnamnden.se/loa/1.0/loa4
```

A request with a comparison that has no mapping, or a URI that has none, is answered with `Requester` /
`RequestUnsupported`.

<a name="replay-protection"></a>
### Replay protection

The ID of every received request is kept for a while, and a request with an ID that has already been seen is rejected.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `replay.type` | Where the IDs are kept, `memory` or `redis`, overriding `authn-server.storage.type`, see [Running several nodes](#running-several-nodes). | `authn-server.storage.type` |
| `replay.expiration` | For how long the IDs are kept. | 5 minutes |
| `replay.context` | The context under which the IDs are stored. | `idp-replay-checker` |

:raised_hand: The in-memory store only protects the node it runs on. A deployment with several nodes keeps the IDs in
Redis, so that a request replayed to another node is also rejected. A store of your own is added by declaring an
OpenSAML `ReplayCache` bean, or a whole `MessageReplayChecker` bean, which replace the store chosen by the setting.

<a name="requester-acceptance"></a>
### Requester acceptance

By default, every Service Provider that is found in the metadata may use the Identity Provider. The rules under
`authn-server.saml.requester-acceptance` restrict that. How the rules work, and how to add a rule of your own, is
described in [The client registry](client-registry.html#requester-acceptance).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `whitelist[]` | The entityIDs of the accepted Service Providers. | - |
| `required-marks[][]` | Groups of entity categories. Every group must be satisfied, and a group is satisfied by any one of its entity categories. | - |
| `mode` | How the rules are combined: `ALL`, every rule must accept, or `ANY`, one accepting rule is enough. | `ALL` |

```yaml
authn-server:
  saml:
    requester-acceptance:
      required-marks:
        - - http://id.elegnamnden.se/ec/1.0/loa3-pnr
          - http://id.elegnamnden.se/ec/1.0/loa4-pnr
        - - http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding
```

A Service Provider that is not accepted gets an error response with the status `Responder` / `RequestDenied`.

<a name="the-openid-provider"></a>
## The OpenID Provider

The OpenID Connect properties are placed under `authn-server.oidc`. How the OpenID Provider uses them is described in
[The OpenID Provider](openid-provider.html).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `enabled` | Whether the OpenID Provider is enabled. | `false` |
| `path` | The OIDC path, see [URL layout](#url-layout). | `/oidc` |
| `issuer` | The issuer identifier. It must be the base URL, or begin with the base URL followed by a path. The discovery document is published at the issuer followed by `/.well-known/openid-configuration`. | The base URL |
| `sso.*` | The single sign-on policy for OpenID Connect, see [Single sign-on](#single-sign-on). | `authn-server.sso.*` |
| `clock-skew` | The clock skew for OpenID Connect. | `authn-server.clock-skew` |
| `max-jwt-age` | The maximum age of a JWT that a client signs, measured from its `iat`: signed request objects, signature request JWTs and client assertions. The clock skew is added to it. A JWT without `iat` is accepted. Must be positive when set. | No maximum age |
| `supports-user-message` | Whether user messages are supported for OpenID Connect. When they are, the `https://id.oidc.se/param/userMessage` parameter is read, and the discovery document declares `https://id.oidc.se/disco/userMessageSupported`. When they are not, the parameter is ignored. | `authn-server.supports-user-message` |
| `subject-identifier.*` | The subject identifier settings for OpenID Connect. | `authn-server.subject-identifier.*` |
| `keys.*` | The signing and decryption keys, see [Keys](#oidc-keys). | Required |
| `clients[]` | The OpenID Connect clients, given in files or inline, see [Clients](#oidc-clients). | - |
| `endpoints.*` | The endpoints, see [OIDC endpoints](#oidc-endpoints). | See below |
| `authorization-request.*` | The processing of authentication requests, see [Authorization requests](#oidc-authorization-requests). | See below |
| `requester-acceptance.*` | Which clients are accepted, see [Requester acceptance](#oidc-requester-acceptance). | Every known client |
| `tokens.*` | The lifetimes of codes and tokens, see [The token endpoint and tokens](#oidc-token-endpoint). | See below |
| `client-authentication-methods[]` | The client authentication methods enabled at the token endpoint, see [The token endpoint and tokens](#oidc-token-endpoint). | `private_key_jwt` |
| `sign-user-info` | Whether UserInfo responses are signed. When they are, a client that has not registered `userinfo_signed_response_alg` still gets a signed response. When they are not, only a client that has registered it gets a signed response, see [The UserInfo endpoint](openid-provider.html#the-userinfo-endpoint). | `true` |
| `scopes[]` | The offered scopes, see [Scopes and claims](#oidc-scopes-and-claims). | Derived from the authentication providers |
| `claims[]` | Claims supported on top of those of the authentication providers, see [Scopes and claims](#oidc-scopes-and-claims). | - |
| `ui-locales[]` | The languages of the user interface, as language tags, published as `ui_locales_supported`. The Sweden Connect federation requires `sv` and `en`. | - |
| `discovery.*` | The discovery document, see [The discovery document](#oidc-discovery). | - |
| `entity-information.*` | The entity information for OpenID Connect, see [Entity information for OpenID Connect](#oidc-entity-information). | `authn-server.entity-information.*` |
| `federation.*` | The OpenID Provider as a member of an OpenID Federation, see [OpenID Federation](#oidc-federation). | Not enabled |

The values are checked when the filter chain is built, and the application does not start if a required value is
missing or a value is invalid.

<a name="oidc-keys"></a>
### Keys

The keys are given as two lists under `authn-server.oidc.keys`. Each entry has a credential, a
[PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java),
the same as for the [SAML credentials](#credentials).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `signing[].credential.*` | The credential holding the signing key. | Required |
| `signing[].state` | `active`, the key is published and used, or `future`, the key is published but not used. | `active` |
| `signing[].default-key` | Whether this is the default key, used for clients that do not ask for an algorithm. Exactly one active key must be the default key, unless there is only one active key. | `false` |
| `decryption[].credential.*` | The credential holding the decryption key, used for encrypted request objects. | Required |
| `decryption[].state` | `active`, the key is published and used, or `previous`, the key is not published but still decrypts. | `active` |

At least one active signing key is required. An RSA key must be at least 2048 bits, and an EC key must be on P-256,
P-384 or P-521. The rules, the key IDs and how to roll over a key are described in
[The OpenID Provider](openid-provider.html#keys).

```yaml
authn-server:
  oidc:
    keys:
      signing:
        - credential:
            bundle: op-sign-rsa
          default-key: true
        - credential:
            bundle: op-sign-ec
      decryption:
        - credential:
            bundle: op-enc
```

<a name="oidc-clients"></a>
### Clients

The OpenID Provider takes its clients from two sources that are set up with properties: the configured clients of
`authn-server.oidc.clients`, described here, and the clients resolved through OpenID Federation, see
[Clients from OpenID Federation](#oidc-federation-clients). An OpenID Provider may use either of them, or both, in which
case the configured clients are asked first. A client repository, or a client source of the application's own, is
added in an [adapter](#adjusting-the-configuration-in-code), see
[OpenID Connect: three backends](client-registry.html#openid-connect-three-backends). An OpenID Provider without any
client source does not start.

`authn-server.oidc.clients` is a list where each entry is either a file or one client given inline.

| Property | Description |
| :--- | :--- |
| `clients[].location` | A resource, file or classpath, holding one client as a JSON object, or a JSON array of such objects. |
| `clients[].client-id` | The `client_id` of an inline client. |
| `clients[].metadata` | The client metadata of an inline client, as a JSON object in a string. |
| `clients[].client-secret` | The client secret of an inline client that authenticates with one, see [Client authentication](openid-provider.html#client-authentication). |
| `clients[].trust-mark-types[]` | Trust mark types that the operator assigns to an inline client, see below. |

An entry has either a `location` or the inline fields, never both. An inline client needs `client-id` and `metadata`.

A client object in a file has the same parts as an inline client: `client_id`, `metadata` as a nested JSON object, and
optionally `client_secret` and `trust_mark_types`, an array of strings:

```json
[
  {
    "client_id": "https://rp.example.com",
    "trust_mark_types": [
      "https://tm.example.com/public-sector"
    ],
    "metadata": {
      "client_name#sv": "Exempeltjänsten",
      "client_name#en": "The Example Service",
      "redirect_uris": [ "https://rp.example.com/callback" ],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks_uri": "https://rp.example.com/jwks"
    }
  }
]
```

The same client inline, next to a file:

```yaml
authn-server:
  oidc:
    clients:
      - location: file:/opt/config/oidc-clients.json
      - client-id: https://rp.example.com
        metadata: >
          {"client_name#sv": "Exempeltjänsten", "client_name#en": "The Example Service",
           "redirect_uris": ["https://rp.example.com/callback"],
           "token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://rp.example.com/jwks"}
        trust-mark-types:
          - https://tm.example.com/public-sector
```

The `metadata` is exactly the client's registered metadata, so it can be copied to or from the client's registration
unchanged. The following rules apply to both forms, and a client that breaks one of them stops startup with a message
that names the client and where it was given:

- A client secret never goes in the metadata. It is given as `client-secret` for an inline client, and as
  `client_secret` next to `metadata` in a file.
- A `client_id` in the metadata is accepted only when it equals the client's `client_id`.
- The metadata must be valid OpenID Connect client metadata.
- A `client_id` may only be given once, over all entries, files and inline clients alike.
- A location must be readable and hold a JSON object or an array of JSON objects.

**Operator-assigned trust mark types.** The trust mark types of a client are not trust marks. Nothing is verified, and
the operator vouches for them. They let the operator give a locally configured client the same treatment as a
federation client that holds a real trust mark of that type, for example under
`authn-server.oidc.requester-acceptance.required-marks`, see [Requester acceptance](#oidc-requester-acceptance). This
is useful for testing, and for using the meaning of trust mark assignments outside a federation.

The clients of the property are served by a client source named `properties`. That is the name shown by the
[Actuator](management.html) and used in the [audit events](audit.html) for clients that are added or removed. The
source is asked before any OpenID Connect client source added in code. Two client sources of the same protocol may not
have the same name, so a source added in code may not be named `properties`.

The clients are read once, at startup. A changed file has no effect until the server is restarted.

<a name="oidc-endpoints"></a>
### OIDC endpoints

The endpoints are given relative to the OIDC path, see [URL layout](#url-layout). They are placed under
`authn-server.oidc.endpoints`.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `jwks` | Where the JWKS is published. | `/jwks` |
| `authorization` | Where authentication requests are received, with GET and POST. | `/authorize` |
| `token` | Where token requests are received, with POST. | `/token` |
| `userinfo` | Where UserInfo requests are received, with GET and POST. | `/userinfo` |

With the default OIDC path, the JWKS is published at `/oidc/jwks`, the authorization endpoint is `/oidc/authorize`,
the token endpoint is `/oidc/token` and the UserInfo endpoint is `/oidc/userinfo`.
The discovery document is not an endpoint under the OIDC path; it follows the issuer.

<a name="oidc-authorization-requests"></a>
### Authorization requests

How the OpenID Provider processes an authentication request, and which failures are sent to the client, is described
in [The OpenID Provider](openid-provider.html#authentication-requests). These properties, under
`authn-server.oidc.authorization-request`, affect it:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `require-pkce` | Whether PKCE is required. When `false`, it is optional. The `plain` method is never accepted, and public clients are not supported. | `false` |
| `require-signed-request-object` | Whether request objects must be signed. When `false`, an unsigned request object is accepted, unless the client has registered `request_object_signing_alg`. The discovery document declares `none` as a request object signing algorithm only when this is `false`. | `false` |
| `require-state` | Whether authentication requests must carry `state`. When `false`, a request without `state` is accepted, and its response carries no `state`. | `true` |
| `login-without-prompt` | Whether an authentication request without `prompt` is treated as `prompt=login`, as the OpenID Connect Profile for Sweden Connect, Section 2.2.1, requires. When `false`, such a request may be answered with single sign-on. | `true` |

```yaml
authn-server:
  oidc:
    authorization-request:
      require-pkce: true
      require-signed-request-object: true
```

The clock skew, `authn-server.oidc.clock-skew`, applies to the `exp`, `nbf` and `iat` of request objects, and is added
to the maximum age, `authn-server.oidc.max-jwt-age`, of signed request objects.

<a name="oidc-requester-acceptance"></a>
### Requester acceptance

By default, every client that the client registry knows may use the OpenID Provider. The rules under
`authn-server.oidc.requester-acceptance` restrict that, in the same way as for SAML. How the rules work is described in
[The client registry](client-registry.html#requester-acceptance).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `whitelist[]` | The `client_id`s of the accepted clients. | - |
| `required-marks[][]` | Groups of trust mark types. Every group must be satisfied, and a group is satisfied by any one of its trust mark types. A trust mark type that the client does not hold is asked for through the client registry before the client is rejected. | - |
| `mode` | How the rules are combined: `ALL`, every rule must accept, or `ANY`, one accepting rule is enough. | `ALL` |

```yaml
authn-server:
  oidc:
    requester-acceptance:
      required-marks:
        - - https://tm.example.com/public-sector
```

A client that is not accepted gets the error `unauthorized_client`.

<a name="oidc-token-endpoint"></a>
### The token endpoint and tokens

How the code flow, the token endpoint and the tokens work is described in
[The OpenID Provider](openid-provider.html#the-code-flow).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `tokens.authorization-code-lifetime` | How long an authorization code is valid. A lifetime above 10 minutes is logged as a warning. | 1 minute |
| `tokens.access-token-lifetime` | How long an access token is valid. | 5 minutes |
| `tokens.access-token-single-use` | Whether an access token may only be used once, at the UserInfo endpoint. When `false`, it may be used until it expires. | `true` |
| `tokens.id-token-lifetime` | How long an ID token is valid. A lifetime above 5 minutes, which the Swedish OpenID Connect Profile does not allow, is logged as a warning. | 5 minutes |
| `client-authentication-methods[]` | The client authentication methods enabled at the token endpoint: `private_key_jwt`, `client_secret_basic`, `client_secret_post` and `client_secret_jwt`. `none` is not supported. | `private_key_jwt` |

```yaml
authn-server:
  oidc:
    tokens:
      authorization-code-lifetime: 30s
      access-token-single-use: false
    client-authentication-methods:
      - private_key_jwt
      - client_secret_basic
```

:raised_hand: Codes, access tokens and used client assertions are kept in memory by default, which only serves the
node they run on. A deployment with several nodes keeps them in Redis, see
[Running several nodes](#running-several-nodes), or needs sticky sessions.

<a name="oidc-scopes-and-claims"></a>
### Scopes and claims

By default, the offered scopes and the supported claims are worked out from the attributes and scopes that the
authentication providers declare, see
[The OpenID Provider](openid-provider.html#scopes-claims-and-authentication-contexts).

- `scopes` replaces the derived scopes. Each scope must be in the scope registry, and `openid` is always offered.
- `claims` is added to the claims of the providers. The claims count when scopes are derived and are published as
  `claims_supported`. The claims of the offered scopes are not added automatically.

```yaml
authn-server:
  oidc:
    scopes:
      - https://id.oidc.se/scope/naturalPersonInfo
      - https://id.oidc.se/scope/naturalPersonNumber
    ui-locales:
      - sv
      - en
```

A `ScopeRegistry` bean replaces the default registry, which holds the built-in scopes, and an `OidcAttributeMapping`
bean replaces the default attribute mapping. A `SubjectGeneratorFactory` bean replaces the default subject generator
factory, whose subject types are published as `subject_types_supported`.

<a name="oidc-discovery"></a>
### The discovery document

Most of the discovery document is worked out from the rest of the configuration, see
[The OpenID Provider](openid-provider.html#the-discovery-document). Other parameters are added under
`authn-server.oidc.discovery`:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `additional-parameters.*` | Parameters added to the discovery document, as a map of name to value, for example `service_documentation` or `op_policy_uri`. A value may be a string, a boolean, a list or a map. A parameter that the OpenID Provider sets itself cannot be given. | - |

```yaml
authn-server:
  oidc:
    discovery:
      additional-parameters:
        service_documentation: https://op.example.com/docs
        op_policy_uri: https://op.example.com/policy
```

A customizer set in an [adapter](#adjusting-the-configuration-in-code) changes the built document, see
[Extending the document](openid-provider.html#extending-the-document).

<a name="oidc-entity-information"></a>
### Entity information for OpenID Connect

The [shared entity information](#entity-information) is overridden for OpenID Connect under
`authn-server.oidc.entity-information`, with `ui-info`, `organization` and `contact-persons` in the same shape. The
descriptive parameters of the OpenID Provider metadata are worked out from the result, see
[Descriptive metadata](openid-provider.html#descriptive-metadata), and each of them may also be given directly:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `display-name` | `display_name`, keyed by language tag. | The UI display names |
| `description` | `description`, keyed by language tag. | The UI descriptions |
| `organization-name` | `organization_name`, keyed by language tag. | The organization names |
| `organization-uri` | `organization_uri`. | The first organization URL |
| `organization-identifier` | `organization_identifier`. | Derived from a ten-digit organization number |
| `logo-uri` | `logo_uri`. | The first logo without a language, or else the first logo |
| `contacts[]` | `contacts`. | The e-mail addresses of the technical and support contact persons |

```yaml
authn-server:
  oidc:
    entity-information:
      logo-uri: https://cdn.example.com/op-logo.svg
      contacts:
        - op-support@example.com
```

<a name="oidc-federation"></a>
### OpenID Federation

The OpenID Provider as a member of an OpenID Federation is configured under `authn-server.oidc.federation`, see
[OpenID Federation](openid-provider.html#openid-federation).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `enabled` | Whether the OpenID Provider publishes an entity configuration. | `false` |
| `authority-hints[]` | The entity identifiers of the immediate superiors. At least one is required when federation is enabled. | - |
| `keys[]` | The federation keys, each with a `credential` and a `state`, `active` or `future`. At least one active key is required when federation is enabled. | - |
| `entity-configuration-lifetime` | The lifetime of the entity configuration. | 1 day |
| `additional-parameters.*` | Parameters applied to the entity configuration only, as a map of name to value, for example `trust_anchor_hints`. A `metadata` entry is merged into the metadata per entity type and parameter. | - |
| `trust-marks[]` | The trust marks of the OpenID Provider, each with `type`, `issuer` (the entity identifier of the issuer), `jwks` (the location of a JWK Set document with the federation keys of the issuer) and, optionally, `endpoint` (its trust mark endpoint). Without `endpoint`, the `federation_trust_mark_endpoint` that the issuer publishes in its entity configuration is used. | - |
| `trust-anchor.*` | The trust anchor, see [Clients from OpenID Federation](#oidc-federation-clients). | - |
| `clients.*` | The client source that resolves clients through the federation, see [Clients from OpenID Federation](#oidc-federation-clients). | Enabled |
| `trust-mark-cache-directory` | A directory where fetched trust marks are stored, so that they are available after a restart. Overrides the directory `oidc/trust-marks` of `authn-server.cache-directory`. Not used when the trust marks are kept in Redis. | Nothing is stored |
| `trust-mark-retry-interval` | How long to wait before a failed attempt to fetch a trust mark is made again. | 5 minutes |

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
        - credential:
            bundle: federation-2027
          state: future
      trust-marks:
        - type: https://id.swedenconnect.se/loa/loa3
          issuer: https://fed.swedenconnect.se/tmi-loa
          jwks: file:/opt/config/tmi-loa-jwks.json
      trust-mark-cache-directory: /var/op/trust-marks
```

When federation is enabled, the application does not start without federation keys and authority hints, or when the
[descriptive metadata](openid-provider.html#descriptive-metadata) has no e-mail address in `contacts` or no HTTPS
`logo_uri`.

<a name="oidc-federation-clients"></a>
### Clients from OpenID Federation

A member of a federation also accepts clients, relying parties, that are resolved through the federation. The client
source is configured under `authn-server.oidc.federation.clients`, and the trust anchor that clients are resolved
against under `authn-server.oidc.federation.trust-anchor`. How the source works is described in
[The federation backend](client-registry.html#the-federation-backend).

The source is only used when federation is enabled, and it is then on by default. An OpenID Provider that is a member
but takes no clients from the federation turns it off with `clients.enabled: false`. When the source is on, the trust
anchor is required, and the application does not start without it. An OpenID Provider that resolves clients through a
federation that it is not a member of is not supported.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `trust-anchor.entity-id` | The entity identifier of the trust anchor. | Required |
| `trust-anchor.jwks` | The location of a JWK Set document with the federation keys of the trust anchor. | Required |
| `clients.enabled` | Whether clients are resolved through the federation. | `true` |
| `clients.resolver.entity-id` | The entity identifier of the resolver. | The trust anchor |
| `clients.resolver.endpoint` | The resolve endpoint. | The `federation_resolve_endpoint` that the resolver publishes |
| `clients.resolver.jwks` | The location of a JWK Set document with the federation keys of the resolver. Required when the resolver is not the trust anchor. | The trust anchor's keys |
| `clients.trust-mark-issuers[]` | The issuers that are asked for a trust mark that a client does not hold, one per trust mark type, see below. | - |
| `clients.trust-mark-status-interval` | The interval between two checks of the status of the trust marks obtained from the issuers. | 1 hour |
| `clients.cache.maximum-age` | How long a resolved client is kept at the most, regardless of what the resolve response says. | No limit |
| `clients.cache.not-found-time-to-live` | How long the answer that the resolver does not know a client is kept. | 1 minute |
| `clients.cache.refresh.enabled` | Whether the background job that refreshes frequently used clients before they expire runs. | `false` |
| `clients.cache.refresh.interval` | How often the job runs. | 1 minute |
| `clients.cache.refresh.refresh-ahead` | How long before an entry expires that it is refreshed. | 5 minutes |
| `clients.cache.refresh.minimum-lookups` | How many times a client must have been looked up within `lookup-period` to be refreshed. | 10 |
| `clients.cache.refresh.lookup-period` | The period that lookups are counted within. | 10 minutes |
| `clients.cache.refresh.maximum-clients` | The largest number of clients that one run refreshes. | 100 |
| `clients.cache.refresh.maximum-tracked-clients` | The largest number of clients that lookups are counted for. | 1000 |

A trust mark issuer has:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `type` | The trust mark type. | Required |
| `issuer` | The entity identifier of the issuer. | Required |
| `jwks` | The location of a JWK Set document with the federation keys of the issuer. Required when the issuer is not the trust anchor. | The trust anchor's keys |
| `endpoint` | The trust mark endpoint. | The `federation_trust_mark_endpoint` that the issuer publishes |
| `status-endpoint` | The trust mark status endpoint. An issuer without one gets no status checks. | The `federation_trust_mark_status_endpoint` that the issuer publishes, if any |

**Endpoints.** No endpoint path is ever assumed. An endpoint that is not configured is taken from the
`federation_entity` metadata of the entity configuration of the resolver or the issuer (OpenID Federation 1.0, Section
5.1.1). The entity configuration is fetched when one of its endpoints is first needed, verified with the keys
configured for the entity, or the trust anchor's keys when the entity is the trust anchor, and kept in memory on each
node until its `exp`. Only the endpoints that are not configured are looked up.

**When the federation cannot be reached.** Nothing is fetched at startup, so the OpenID Provider starts, and serves
SAML and its configured clients, when the trust anchor, the resolver or an issuer cannot be reached. A failed fetch,
or an entity configuration that does not publish a needed endpoint, is handled like a failed resolve or trust mark
call: the client is not resolved, or the trust mark not obtained, the failure shows in the
[health of the federation services](management.html#oidc-federation-health), and the next request tries again.

**The order of the sources.** The configured clients of `authn-server.oidc.clients` are asked first, so an operator's
entry overrides what the federation says about the same `client_id`. Client sources added in an
[adapter](#adjusting-the-configuration-in-code) come next, and the federation source, named `federation`, last. A
`FederationClientBackend` added in an adapter replaces the federation source of the properties.

The federation cache is kept where `authn-server.storage.type`, or `authn-server.oidc.storage.federation-cache`, says,
see [Where state is kept](#where-state-is-kept).

```yaml
authn-server:
  oidc:
    federation:
      enabled: true
      trust-anchor:
        entity-id: https://ta.example.com
        jwks: file:/opt/config/ta-jwks.json
      clients:
        trust-mark-issuers:
          - type: https://tm.example.com/public-sector
            issuer: https://tmi.example.com
            jwks: file:/opt/config/tmi-jwks.json
        cache:
          refresh:
            enabled: true
```

A standalone resolver, one that is not the trust anchor, is given with its own keys:

```yaml
authn-server:
  oidc:
    federation:
      clients:
        resolver:
          entity-id: https://resolver.example.com
          jwks: file:/opt/config/resolver-jwks.json
```

<a name="joining-sweden-connect"></a>
### Joining Sweden Connect

An OpenID Provider that joins the Sweden Connect federation takes the trust anchor's entity identifier and its
federation keys from [Sweden Connect - OpenID Federation Structure](https://docs.swedenconnect.se/federation/oidf-structure.html),
for `authn-server.oidc.federation.trust-anchor`, and the entity identifiers of the resolver and the trust mark issuers
from the same document. The endpoints of these entities do not need to be configured; they are found in their entity
configurations. The keys of the trust anchor are what everything else is verified against, so they are the one value
that must be taken from a trusted copy of that document.

The authority hint, `authn-server.oidc.federation.authority-hints`, is the intermediate that the OpenID Provider is
registered under, and the OpenID Provider's own trust marks, `authn-server.oidc.federation.trust-marks`, are those that
it has been granted, see [OpenID Federation](openid-provider.html#openid-federation).

<a name="running-several-nodes"></a>
## Running several nodes

By default the server keeps what it needs between requests in the memory of the node: the HTTP session, which holds
single sign-on and the authentication in progress, and the stores of the protocols, such as the IDs of received SAML
requests and the OpenID Connect authorization codes and access tokens. A deployment with several nodes then needs
sticky load balancing, and a node that restarts loses what it held.

With Redis, the nodes share all of it. Any node can serve any request, and a node that restarts loses nothing.

<a name="redis-dependencies"></a>
### Dependencies

Redis support is optional, and the starters do not bring it. Add Spring Data Redis, and Spring Session for Redis when
the HTTP session is kept in Redis:

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-session-data-redis</artifactId>
</dependency>
```

Spring Data Redis uses the Lettuce client. To use Jedis instead, add `redis.clients:jedis` and set
`spring.data.redis.client-type` to `jedis`. Redisson is not supported.

<a name="where-state-is-kept"></a>
### Where state is kept

One setting decides where the HTTP session and all stores are kept:

```yaml
authn-server:
  storage:
    type: redis
```

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.storage.type` | Where the HTTP session and all stores are kept: `memory` or `redis`. | `memory` |

With `memory`, everything stays in the memory of the node. Spring Boot is kept from putting the HTTP session in Redis,
also if Spring Session for Redis is on the classpath, since the HTTP session always follows this setting.

With `redis`, the HTTP session is kept in Redis by Spring Session. Spring Boot sets this up when its session module,
which `spring-boot-starter-session-data-redis` brings, is present, and then its settings apply, for example
`spring.session.data.redis.repository-type`, `spring.session.data.redis.flush-mode` and
`server.servlet.session.timeout`. Without Spring Boot's session module, the server sets up Spring Session with its
defaults.

Each store may be kept elsewhere than the setting says, with a setting of its own. The HTTP session has no such
setting.

| Property | The store |
| :--- | :--- |
| `authn-server.saml.replay.type` | The IDs of received SAML requests, see [Replay protection](#replay-protection). |
| `authn-server.oidc.storage.authorization-codes` | Authorization codes. |
| `authn-server.oidc.storage.access-tokens` | Access tokens. |
| `authn-server.oidc.storage.client-assertions` | The `jti` values of used client assertions, `private_key_jwt` and `client_secret_jwt`. |
| `authn-server.oidc.storage.federation-cache` | The cache of clients resolved through OpenID Federation, with its lookup counts and the lock of its background jobs, see [Background jobs and trust marks](#background-jobs-in-a-cluster). |
| `authn-server.oidc.storage.trust-marks` | The OpenID Provider's own trust marks and their state. |

The record of known clients, which tells which clients have been [added and removed](management.html#clients-added-and-removed)
since the previous start, follows `authn-server.storage.type`. In Redis it is the hash `<prefix>:known-clients`. The
state of the federation services that the `oidc-federation` health indicator reports follows
`authn-server.oidc.storage.federation-cache`.

```yaml
authn-server:
  storage:
    type: memory
  oidc:
    storage:
      authorization-codes: redis
      access-tokens: redis
```

A store bean that the application declares, such as an `AccessTokenStore` or an OpenSAML `ReplayCache`, replaces the
store that the setting chooses.

The application does not start, and the message names what is missing, when something is to be kept in Redis and:

- Spring Data Redis is not on the classpath,
- there is no Redis connection, or the connection does not work, or
- the HTTP session is to be kept in Redis, that is, `authn-server.storage.type` is `redis`, and Spring Session for
  Redis is not on the classpath. A store set to `redis` while `authn-server.storage.type` is `memory` does not need
  Spring Session.

<a name="the-redis-connection"></a>
### The Redis connection

The connection is configured with Spring Boot's own settings, `spring.data.redis.*`, for a single Redis, Redis Sentinel
or Redis Cluster, see
[Spring Boot's Redis documentation](https://docs.spring.io/spring-boot/reference/data/nosql.html#data.nosql.redis).
TLS key and trust stores are given in a Spring Boot
[SSL bundle](https://docs.spring.io/spring-boot/reference/features/ssl.html):

```yaml
spring:
  ssl:
    bundle:
      pem:
        redis:
          truststore:
            certificate: file:/opt/config/redis-ca.crt
          keystore:
            certificate: file:/opt/config/redis-client.crt
            private-key: file:/opt/config/redis-client.key
  data:
    redis:
      host: redis.example.com
      port: 6380
      username: authn-server
      password: ${REDIS_PASSWORD}
      ssl:
        enabled: true
        bundle: redis
```

The key store is only needed when Redis requires client certificates. At startup, when something is kept in Redis,
the server checks that the connection works.

<a name="redis-key-names"></a>
### Key names

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.redis.key-prefix` | The prefix that starts every key the server writes, and the default namespace of the HTTP sessions. | `authn-server` |

Two deployments that share one Redis are kept apart by giving them different prefixes. The sessions are kept under
`<prefix>:sessions:`, unless `spring.session.data.redis.namespace` is set.

The entries of the stores are written as JSON, so that an entry written by an older version of the server can be read
after an upgrade, also during a rolling upgrade. Every entry expires in Redis when it expires in the store: a code
when it is no longer retained, a token with its lifetime, a replay ID when it no longer needs to be remembered, and a
cache entry with the cache entry. The state of a trust mark of the OpenID Provider is kept one day after the trust mark
expires, so that its failures are still reported.

<a name="redis-host-name-check"></a>
### The TLS host name check

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.redis.ssl.skip-hostname-verification` | Whether the check that the server certificate matches the host name is skipped. | `false` |

With TLS, the server certificate of Redis must be issued by an issuer in the trust store, and match the host name the
server connects to. Skipping the host name check is for nodes that are reached by addresses that their certificates
do not hold, as when Redis Cluster nodes are reached by IP address. The certificate is still checked against the trust
store, so a certificate from an issuer that is not trusted is rejected.

The setting means the same for both clients. For Lettuce, the certificate is verified in its `CA` mode. For Jedis, the
host name is checked unless the check is skipped, which Spring Boot by itself does not do for Jedis.

<a name="redis-cluster"></a>
### Redis Cluster

**NAT translation.** The nodes of a Redis Cluster tell the client their addresses. When the cluster is behind NAT, the
addresses that the nodes report are not the ones the server can reach. Each entry translates one address:

```yaml
spring:
  data:
    redis:
      cluster:
        nodes:
          - redis1.example.com:2001
          - redis2.example.com:2002
          - redis3.example.com:2003
authn-server:
  redis:
    cluster:
      nat-translation:
        - from: "172.20.0.31:2001"
          to: "redis1.example.com:2001"
        - from: "172.20.0.32:2002"
          to: "redis2.example.com:2002"
        - from: "172.20.0.33:2003"
          to: "redis3.example.com:2003"
```

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.redis.cluster.nat-translation[].from` | The address that a node reports, as `host:port`. | - |
| `authn-server.redis.cluster.nat-translation[].to` | The address that the server uses instead, as `host:port`. | - |

NAT translation is only supported with Lettuce. The application does not start when it is configured and the
connection uses Jedis.

**Reading from replicas.** Which nodes are read from is Spring Boot's setting `spring.data.redis.lettuce.read-from`,
for example `upstream`, `replica-preferred` or `any`. The default, reading from the primary nodes, is the safe choice:
the server often reads what it has just written, such as a session or an authorization code, and a replica may not
have it yet.

<a name="background-jobs-in-a-cluster"></a>
### Background jobs and trust marks

Some work runs in the background on every node. When its state is kept in Redis, one node at a time does it.

**The federation cache.** The refresh of the federation cache and the status checks of the trust marks of clients,
see [The client registry](client-registry.html#the-federation-backend), work on the federation cache. When the cache
is kept in Redis:

- Each round of a job runs on one node. The node that starts a round takes a lock in Redis, held for the interval of
  the job, and the other nodes skip the round. A node that stops while it holds the lock blocks the job for at most
  one round.
- The lookup counts that decide which clients the refresh renews are kept in Redis, so that the threshold applies to
  the traffic of all nodes.

The application sets up the federation backend and its jobs, see
[The client registry](client-registry.html#the-federation-backend). With Spring Boot, a `FederationCache` bean is
declared according to `authn-server.oidc.storage.federation-cache`, and the backend and the jobs are built from it.
Kept in memory, the cache is written to `authn-server.cache-directory`, when given, so that it survives a restart.

**The trust marks of the OpenID Provider.** When they are kept in Redis:

- One node at a time fetches and renews them, using the same kind of lock, held for one minute.
- Every node publishes the trust marks from Redis in its entity configuration.
- The state of each trust mark type, as `ProviderTrustMarks.getStates()` gives it, is the same on every node.
- `authn-server.oidc.federation.trust-mark-cache-directory` and `authn-server.cache-directory` are not used for
  them. Redis already keeps the trust marks when a
  node restarts.

With `memory`, every node runs the jobs and fetches the trust marks itself, as with a single node.

<a name="adjusting-the-configuration-in-code"></a>
## Adjusting the configuration in code

The properties are applied to configurers: [`AuthnServerConfigurer`][AuthnServerConfigurer] for the shared values,
and one configurer per protocol, [`Saml2IdpConfigurer`][Saml2IdpConfigurer] and
[`OidcProviderConfigurer`][OidcProviderConfigurer]. Each value has a method on its configurer.

To adjust the configuration, declare any number of [`AuthnServerConfigurerAdapter`][AuthnServerConfigurerAdapter]
beans. An adapter gets the `HttpSecurity` object of the server's filter chain and the shared configurer, and reaches
the protocol configurers from there. The adapters are invoked after the property values have been applied, in
Spring's order, so a value that an adapter sets is the one used.

```java
@Bean
AuthnServerConfigurerAdapter samlAdjustments() {
  return (http, configurer) -> configurer
      .ssoPolicy(SsoPolicy.forSessionLifetime())
      .protocol(Saml2IdpConfigurer.class, saml -> saml
          .entityId("https://idp.example.com/saml")
          .idpMetadataEndpoint(metadata -> metadata.cacheDuration(Duration.ofHours(1))));
}
```

The values are checked when the filter chain is built, after all adapters have been invoked.

The attribute producers, the attribute release voters, the single sign-on voters and the post-authentication
processors are also adjusted in an adapter, in the shared lists of the `AuthnServerConfigurer` or in the lists of a
protocol configurer. How the lists work is described in
[The SAML Identity Provider](saml-identity-provider.html#producers-voters-and-processors).

<a name="using-the-configurers-without-spring-boot"></a>
## Using the configurers without Spring Boot

The configurers do not depend on Spring Boot or on the properties. An application without Spring Boot creates the
configurers itself and applies them to its filter chain. For SAML, it must also initialize OpenSAML before the chain
is built, using `OpenSAMLInitializer` from [opensaml-security-ext](https://github.com/swedenconnect/opensaml-security-ext).

```java
@Configuration
@EnableWebSecurity
public class AuthnServerConfiguration {

  @Bean
  SecurityFilterChain authnServerSecurityFilterChain(final HttpSecurity http,
      final List<UserAuthenticationProvider> providers, final PkiCredential credential) throws Exception {

    final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
        .baseUrl("https://idp.example.com")
        .protocol(new Saml2IdpConfigurer()
            .defaultCredential(credential));
    providers.forEach(configurer::authenticationProvider);

    AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
    return http.build();
  }
}
```

An OpenID Provider is added in the same way, with its signing keys:

```java
configurer.protocol(new OidcProviderConfigurer()
    .signingKeys(List.of(SigningKey.active(signCredential))));
```

`applyDefaultSecurity` makes the chain match the endpoints of the configured protocols and applies the configurer.
Values may still be changed after the call, since they are read when the chain is built.

<a name="migrating-from-saml-identity-provider"></a>
## Migrating from saml-identity-provider

For an Identity Provider built on [saml-identity-provider](https://github.com/swedenconnect/saml-identity-provider),
most properties move from `saml.idp` to `authn-server.saml`. The base URL and the settings that are common to all
protocols move to `authn-server`, and the endpoints are now relative to the SAML path. Set `authn-server.saml.enabled`
to `true`.

| saml-identity-provider | Spring Authentication Server | Note |
| :--- | :--- | :--- |
| `saml.idp.entity-id` | `authn-server.saml.entity-id` | Now optional, defaults to the base URL. |
| `saml.idp.base-url` | `authn-server.base-url` | Shared. |
| `saml.idp.hok-base-url` | `authn-server.saml.hok-base-url` | |
| `saml.idp.requires-signed-requests` | `authn-server.saml.requires-signed-requests` | |
| `saml.idp.clock-skew-adjustment` | `authn-server.clock-skew` | Shared, `authn-server.saml.clock-skew` for SAML only. |
| `saml.idp.sso-duration-limit` | `authn-server.sso.time-limit` | Shared, `authn-server.saml.sso.time-limit` for SAML only. A value of 0 turned single sign-on off; now set `authn-server.sso.enabled` to `false`. A time limit that is not positive stops the application from starting. |
| `saml.idp.supports-user-message` | `authn-server.supports-user-message` | Shared, `authn-server.saml.supports-user-message` for SAML only. |
| `saml.idp.credentials.*` | `authn-server.saml.credentials.*` | The same credentials and fallback rules. The bean names change from `saml.idp.credentials.<Name>` to `authn-server.saml.credentials.<Name>`. |
| `saml.idp.endpoints.redirect-authn` | `authn-server.saml.endpoints.redirect-authn` | Relative to the SAML path, so `/saml2/redirect/authn` becomes `/redirect/authn`. |
| `saml.idp.endpoints.post-authn` | `authn-server.saml.endpoints.post-authn` | Relative to the SAML path, so `/saml2/post/authn` becomes `/post/authn`. |
| `saml.idp.endpoints.hok-redirect-authn` | `authn-server.saml.endpoints.hok-redirect-authn` | Relative to the SAML path. |
| `saml.idp.endpoints.hok-post-authn` | `authn-server.saml.endpoints.hok-post-authn` | Relative to the SAML path. |
| `saml.idp.endpoints.metadata` | `authn-server.saml.endpoints.metadata` | Relative to the SAML path, so `/saml2/metadata` becomes `/metadata`. |
| `saml.idp.metadata.*` | `authn-server.saml.metadata.*` | The metadata is now always published. |
| `saml.idp.metadata.ui-info.*` | `authn-server.entity-information.ui-info.*` | Shared, so that the OpenID Provider publishes the same information. `authn-server.saml.metadata.ui-info.*` still works, for SAML only. |
| `saml.idp.metadata.organization.*` | `authn-server.entity-information.organization.*` | Shared. `authn-server.saml.metadata.organization.*` still works, for SAML only. |
| `saml.idp.metadata.contact-persons.*` | `authn-server.entity-information.contact-persons.*` | Shared. `authn-server.saml.metadata.contact-persons.*` still works, for SAML only. |
| `saml.idp.metadata-providers[]` | `authn-server.saml.metadata-providers[]` | The same properties. |
| `saml.idp.max-message-age` | `authn-server.saml.max-message-age` | |
| `saml.idp.authn-context.*` | `authn-server.saml.authn-context.*` | |
| `saml.idp.assertions.encrypt` | `authn-server.saml.assertions.encrypt` | |
| `saml.idp.assertions.not-after` | `authn-server.saml.assertions.not-after` | |
| `saml.idp.assertions.not-before` | `authn-server.saml.assertions.not-before` | |
| `saml.idp.replay.*` | `authn-server.saml.replay.*` | `type` now follows `authn-server.storage.type` when it is not set, instead of choosing Redis when Redis is available, see [Replay protection](#replay-protection). |
| `saml.idp.session.module` | `authn-server.storage.type` | Shared by the HTTP session and all stores, see [Running several nodes](#running-several-nodes). |
| `spring.data.redis.ssl-ext.enable-hostname-verification` | `authn-server.redis.ssl.skip-hostname-verification` | Inverted: set to `true` to skip the check. The server certificate is still checked against the trust store, see [The TLS host name check](#redis-host-name-check). |
| `spring.data.redis.ssl-ext.credential.*`, `spring.data.redis.ssl-ext.trust.*` | `spring.ssl.bundle.*` and `spring.data.redis.ssl.bundle` | Key and trust stores are configured with a Spring Boot SSL bundle, see [The Redis connection](#the-redis-connection). |
| `spring.data.redis.cluster-ext.nat-translation[]` | `authn-server.redis.cluster.nat-translation[]` | The same `from` and `to`. Now for Lettuce, which Spring Data Redis uses by default; not supported with Jedis. |
| `spring.data.redis.cluster-ext.read-mode` | `spring.data.redis.lettuce.read-from` | Spring Boot's own setting, see [Redis Cluster](#redis-cluster). `MASTER` is `upstream`, `SLAVE` is `replica-preferred` and `MASTER_SLAVE` is `any`. |

Endpoints that were moved away from `/saml2` are set up by changing `authn-server.saml.path`, if they share a prefix,
or by giving each endpoint relative to an empty SAML path.

The `saml.idp.audit.*` properties are gone. Auditing is done with spring-audit-support, and its repositories are
configured with its `audit.*` properties. The audit event types and their data have changed as well, see
[Auditing](audit.html).

Redisson is not supported. A deployment that used the Redisson starter configures the connection with Spring Boot's
`spring.data.redis.*` settings instead, see [The Redis connection](#the-redis-connection).

`Saml2ServiceProviderFilter` is replaced by [requester acceptance](#requester-acceptance), which works for both
protocols. A filter bean becomes a `RequesterPredicate` for SAML, added in an adapter; a predicate reads the Service
Provider metadata with `record.getProtocolMetadata(EntityDescriptor.class)`.

:raised_hand: A Service Provider that is not accepted now gets the status `Responder` / `RequestDenied`. The
saml-identity-provider library answered with `Responder` / `AuthnFailed`.

`Saml2IdpConfigurerAdapter` is replaced by [`AuthnServerConfigurerAdapter`][AuthnServerConfigurerAdapter], which gets
the shared configurer instead of the SAML one. `configurer.protocol(Saml2IdpConfigurer.class, saml -> ...)` reaches
the SAML configurer. The settings object, `IdentityProviderSettings`, no longer exists; each value is a method on its
configurer.

The lists of `Saml2UserAuthenticationConfigurer` move to the configurers. `attributeProducers`,
`attributeReleaseVoters` and `postAuthenticationProcessors` exist both on the `AuthnServerConfigurer`, for entries that
apply to all protocols, and on the `Saml2IdpConfigurer`, for SAML only. Single sign-on voters, which could only be
added to a provider before, have the same two lists. `assertionCustomizer` moves to `Saml2IdpConfigurer.authnRequestProcessor(...)`, and
the resume paths of the redirect providers no longer need to be registered, see
[The SAML Identity Provider](saml-identity-provider.html#modules-with-pages-of-their-own).

[AuthnServerConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/config/AuthnServerConfigurer.java
[AuthnServerConfigurerAdapter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/config/AuthnServerConfigurerAdapter.java
[OidcProviderConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/config/OidcProviderConfigurer.java
[Saml2IdpConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/config/Saml2IdpConfigurer.java
[SsoPolicy]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/sso/SsoPolicy.java
[UserAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/UserAuthenticationProvider.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
