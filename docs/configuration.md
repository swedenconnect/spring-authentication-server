![Logo](images/sweden-connect.png)

# Configuration

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes how the Spring Authentication Server is configured: the properties of the Spring Boot
auto-configuration, how the URLs of the server are laid out, how an application adjusts the configuration in code, and
how the server is set up without Spring Boot.

- [Getting started](#getting-started)
- [Enabling protocols](#enabling-protocols)
- [URL layout](#url-layout)
- [Shared settings](#shared-settings)
    - [Single sign-on](#single-sign-on)
    - [Subject identifiers](#subject-identifiers)
- [The SAML Identity Provider](#the-saml-identity-provider)
    - [Credentials](#credentials)
    - [Endpoints](#endpoints)
    - [The IdP metadata](#the-idp-metadata)
- [Adjusting the configuration in code](#adjusting-the-configuration-in-code)
- [Using the configurers without Spring Boot](#using-the-configurers-without-spring-boot)
- [Migrating from saml-identity-provider](#migrating-from-saml-identity-provider)

<a name="getting-started"></a>
## Getting started

Include one of the starters:

- `authn-server-spring-boot-starter` for a server offering both SAML and OpenID Connect.
- `authn-server-saml-spring-boot-starter` for a SAML Identity Provider only.
- `authn-server-oidc-spring-boot-starter` for an OpenID Provider only.

```xml
<dependency>
  <groupId>se.swedenconnect.spring.authnserver</groupId>
  <artifactId>authn-server-saml-spring-boot-starter</artifactId>
  <version>${authn-server.version}</version>
</dependency>
```

A single-protocol starter never pulls in the other protocol. The smallest working SAML Identity Provider needs a base
URL and a credential:

```yaml
authn-server:
  base-url: https://idp.example.com
  saml:
    enabled: true
    credentials:
      default-credential:
        bundle: idp-credential
```

With this, the IdP metadata is published at `https://idp.example.com/saml2/metadata`. The authentication modules are
declared as [`UserAuthenticationProvider`][UserAuthenticationProvider] beans, see
[Writing an authentication module](authentication-module.html).

The whole server uses one `SecurityFilterChain`, named `authnServerSecurityFilterChain`. It matches the endpoints of
the enabled protocols and nothing else, so the application is free to set up its own chains for its other pages.

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

2. The **protocol path**, for example `authn-server.saml.path`, which defaults to `/saml2`. All endpoints of the
   protocol are placed under it.

3. The **endpoint**, relative to the protocol path, for example `/metadata`.

So with the defaults, the SAML metadata is published at `https://idp.example.com/auth/saml2/metadata`. Changing the
protocol path moves every endpoint of that protocol, both where it is served and where the SAML metadata points. An
empty protocol path places the endpoints directly under the base URL.

A protocol may also place some endpoints directly under the base URL. The OpenID Provider will do this for its
discovery document and its OpenID Federation entity configuration, since its issuer is the base URL.

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
| `authn-server.authn-flow-max-age` | How long the server waits for the user to come back from an authentication module that has pages of its own. | 30 minutes | No |

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
| `ui-info.*` | The `mdui:UIInfo` element, see below. | - |
| `requested-principal-selection[]` | Attribute names for the `psc:RequestedPrincipalSelection` extension. | - |
| `organization.*` | The `md:Organization` element, see below. | - |
| `contact-persons.*` | The `md:ContactPerson` elements, keyed by type: `technical`, `support`, `administrative`, `billing`, `other` or `security`. A `security` contact is published as `other` with the REFEDS security contact type. Each has `company`, `given-name`, `surname`, `email-addresses[]` and `telephone-numbers[]`. | - |

An encryption method has:

| Property | Description |
| :--- | :--- |
| `algorithm` | The algorithm URI. |
| `key-size` | The key size. |
| `oaep-params` | The OAEP parameters, in Base64. |
| `digest-method` | The digest algorithm URI, for key transport algorithms that need one. |

The `ui-info` element has `display-names` and `descriptions`, both keyed by language tag, and `logotypes[]`. A logotype
has `height`, `width`, an optional `language-tag`, and either `url` or `path`. A `path` is relative to the base URL.

The `organization` element has `names`, `display-names` and `urls`, all keyed by language tag, and an optional
`number`, which is published as `mdorgext:OrganizationNumber`.

```yaml
authn-server:
  saml:
    metadata:
      ui-info:
        display-names:
          en: Example Identity Provider
          sv: Exempel-IdP
        logotypes:
          - path: /images/logo.svg
            height: 256
            width: 256
      organization:
        names:
          en: Example Organization
        display-names:
          en: Example
        urls:
          en: https://www.example.com
      contact-persons:
        technical:
          email-addresses:
            - operations@example.com
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

<a name="adjusting-the-configuration-in-code"></a>
## Adjusting the configuration in code

The properties are applied to configurers: [`AuthnServerConfigurer`][AuthnServerConfigurer] for the shared values,
and one configurer per protocol, such as [`Saml2IdpConfigurer`][Saml2IdpConfigurer]. Each value has a method on its
configurer.

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

<a name="using-the-configurers-without-spring-boot"></a>
## Using the configurers without Spring Boot

The configurers do not depend on Spring Boot or on the properties. An application without Spring Boot creates the
configurers itself and applies them to its filter chain. It must also initialize OpenSAML before the chain is built,
using `OpenSAMLInitializer` from [opensaml-security-ext](https://github.com/swedenconnect/opensaml-security-ext).

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

Endpoints that were moved away from `/saml2` are set up by changing `authn-server.saml.path`, if they share a prefix,
or by giving each endpoint relative to an empty SAML path.

The properties below are not yet available. They will be added, with the same structure, together with the features
they configure: `saml.idp.max-message-age`, `saml.idp.authn-context.*`, `saml.idp.assertions.*`,
`saml.idp.metadata-providers[]`, `saml.idp.replay.*`, `saml.idp.session.*` and `saml.idp.audit.*`.

`Saml2IdpConfigurerAdapter` is replaced by [`AuthnServerConfigurerAdapter`][AuthnServerConfigurerAdapter], which gets
the shared configurer instead of the SAML one. `configurer.protocol(Saml2IdpConfigurer.class, saml -> ...)` reaches
the SAML configurer. The settings object, `IdentityProviderSettings`, no longer exists; each value is a method on its
configurer.

[AuthnServerConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/config/AuthnServerConfigurer.java
[AuthnServerConfigurerAdapter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/config/AuthnServerConfigurerAdapter.java
[Saml2IdpConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/config/Saml2IdpConfigurer.java
[SsoPolicy]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/sso/SsoPolicy.java
[UserAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/UserAuthenticationProvider.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
