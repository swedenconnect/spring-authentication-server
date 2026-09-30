![Logo](images/sweden-connect.png)

# The SAML Identity Provider

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes how the SAML Identity Provider handles an authentication request from start to end: how the
request is received and turned into the protocol-neutral authentication requirements, how the user is authenticated,
how single sign-on is decided, how the released attributes are chosen, what the response holds, which failures are
answered to the Service Provider, and how to replace the parts of the processing. The properties are described in
[Configuration](configuration.html#the-saml-identity-provider).

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

## How a request flows

1. The Service Provider sends an `AuthnRequest` to one of the authentication endpoints. The request is decoded,
   validated and turned into authentication requirements, see [Receiving a request](#receiving-a-request).

2. The requirements are handed to the authentication providers, together with the authentication in the session that
   may be reused. The first provider that can serve the request handles it, see
   [Authenticating the user](#authenticating-the-user).

3. Either the provider answers at once, from single sign-on or with a new authentication, or it sends the user to the
   pages of its module. In the second case, the flow continues when the user comes back to the resume path, see
   [Modules with pages of their own](#modules-with-pages-of-their-own).

4. The post-authentication processors run on the result, the released attributes are chosen, and the assertion and the
   response are built, see [The response](#the-response).

5. The authentication is kept in the session for single sign-on, and the response is posted to the assertion consumer
   service of the Service Provider.

A failure after the assertion consumer service has been established is answered to the Service Provider with an error
response, see [Failures](#failures).

## Receiving a request

Authentication requests are received on the authentication endpoints under the SAML path, see
[URL layout](configuration.html#url-layout):

- `/saml2/redirect/authn` for the HTTP redirect binding.
- `/saml2/post/authn` for the HTTP POST binding.
- The Holder-of-key endpoints, when they are configured. A request received on a Holder-of-key endpoint is processed
  in the same way, and is marked as a Holder-of-key request for the response.

The processing is done by [`Saml2AuthnRequestAuthenticationConverter`][Converter], which decodes the request and finds
the Service Provider, and [`Saml2AuthnRequestAuthenticationProvider`][Provider], which validates it and builds the
authentication requirements. In this order:

1. The message is decoded, and must be an `AuthnRequest` of SAML version 2 with an `ID` and an `Issuer`.
2. The `Destination` of the message must be the endpoint it was received on.
3. The message must not be older than the maximum message age, allowing for the clock skew.
4. The Service Provider is looked up in the [client registry](client-registry.html).
5. The replay check: a request with an ID that has already been seen is rejected.
6. The assertion consumer service is established: the one the request asks for, by URL or by index, or the default
   one of the Service Provider metadata. It must be in the metadata.
7. The signature is validated against the signing keys of the Service Provider metadata. An unsigned request is
   rejected if the Identity Provider requires signed requests, or if the metadata states `AuthnRequestsSigned`.
8. When assertions are encrypted, the Service Provider metadata must have a key to encrypt them for.
9. The [requester acceptance](client-registry.html#requester-acceptance) check decides whether the Service Provider
   may use the Identity Provider.
10. The `NameIDPolicy` is checked by the `NameID` generator factory, see [Attributes](attributes.html).
11. The authentication requirements are built.

## What the requirements hold

The result is a [`SamlAuthenticationRequirements`][SamlAuthenticationRequirements], described in
[Writing an authentication module](authentication-module.html#what-the-module-receives):

- `ForceAuthn` and `IsPassive`. A request with both is invalid.
- The requested authentication contexts, from `RequestedAuthnContext`. The `exact` comparison gives the requested
  URIs. The other comparisons are resolved through configured mappings, see
  [Request processing](configuration.html#request-processing).
- The requested attributes, worked out from the metadata, the request and the entity categories, see
  [Attributes](attributes.html).
- The requested authentication providers, from the `IDPList` of `Scoping`, and the original requesters, from its
  `RequesterID` elements.
- The sign message, from a `SignMessage` extension. It is only accepted from a Service Provider that declares the
  signature service entity category, and only when its `DisplayEntity` is the Identity Provider or not given; in all
  other cases it is ignored. An encrypted message is decrypted with the encryption credential of the Identity Provider,
  or the previous one after a key rollover.
- The user message, from a `UserMessage` extension.
- The entity categories that the Service Provider declares.
- The `SADRequest` extension, which is only accepted from a signature service and is otherwise ignored.

The requirements are handed on together with the SAML data that the response is built from:
[`Saml2AuthnRequestData`][Saml2AuthnRequestData], holding the request, where to send the response, whether the request
came on a Holder-of-key endpoint, and the `NameID` generator.

<a name="authenticating-the-user"></a>
## Authenticating the user

The processed request is handed to the installed [authentication providers](authentication-module.html), in the order
they were installed. With Spring Boot, every `UserAuthenticationProvider` bean is installed, in Spring's order.

### Choosing the provider

A provider that cannot deliver any of the requested authentication contexts returns `null`, and the next one is
asked. The first provider that returns something handles the request. When no provider handles it, the Service
Provider gets `Requester` / `NoAuthnContext`.

A request without a `RequestedAuthnContext` can be served by any provider, so the first one handles it. Install the
providers in the order they should be preferred.

### Single sign-on

The session holds one authentication for the whole server, whichever protocol it was made for, since single sign-on
is shared between SAML and OpenID Connect. It is kept in the Spring Security `SecurityContext` of the session. When a
request comes in, that authentication is given to the provider, and the provider decides whether it may be reused, as
described in [Writing an authentication module](authentication-module.html#single-sign-on).

The single sign-on policy of a provider, when it has one, wins over the SAML policy under `authn-server.saml.sso`,
which wins over the shared policy under `authn-server.sso`. With the default policy, an authentication is reused for
60 minutes, and only for the Service Provider it was made for.

When an authentication is reused, it is answered with the requirements of the new request. The attributes that are
released are therefore what the new request asks for, not what the original request asked for.

After a successful response, the authentication is saved in the session. An authentication that may not be reused,
such as one where a sign message was displayed, is not saved, and it also removes any earlier authentication from the
session. An authentication in progress on the pages of a module, or a request that fails, leaves the session as it
was.

<a name="modules-with-pages-of-their-own"></a>
### Modules with pages of their own

A provider that authenticates the user on pages of its own, see
[Writing an authentication module](authentication-module.html#modules-with-pages-of-their-own), sends the user to its
authentication path. The server's filter chain serves both paths of every such provider:

- The authentication path is open to everyone, since the user is not authenticated yet. Other pages of the module are
  served by the application's own security configuration.
- The resume path is where the user comes back. The resume is handled once for the whole server: the authentication
  in progress records which protocol it was started for, and the flow continues in that protocol. For SAML, the
  response is sent to the Service Provider that sent the request, with the relay state of the request.

A request to the resume path that has no matching authentication in progress, one that has expired or has already
been resumed, and one for a protocol that is not enabled, is the unrecoverable invalid session error, and the user is
shown an error page. An error that the module reports, including a cancel, is answered to the Service Provider.

<a name="producers-voters-and-processors"></a>
## Producers, voters and processors

Four kinds of components take part in the authentication and the response:

- The attribute producers decide which attributes may be released. The first producer to release an attribute wins.
- The attribute release voters decide which of those are kept, see [Attributes](attributes.html#releasing-attributes).
- The single sign-on voters decide whether an authentication may be reused.
- The post-authentication processors check, and may change, the result before it is answered.

Each kind is a shared list on the `AuthnServerConfigurer`, for entries that apply to all protocols, plus a list on
each protocol configurer. For a SAML request the SAML entries come first, followed by the shared ones. The order
matters, since the first producer to release an attribute wins and the voters are asked in order. The single sign-on
voters and the post-authentication processors of a provider itself run before both lists.

The defaults are:

| List | SAML | Shared |
| :--- | :--- | :--- |
| Attribute producers | `SwedenConnectAttributeProducer` | - |
| Attribute release voters | `SwedenConnectAttributeReleaseVoter` | `IncludeAllAttributeReleaseVoter` |
| Single sign-on voters | - | - |
| Post-authentication processors | - | `SwedenConnectPostAuthenticationProcessor` |

Together they give the rules of the Swedish eID Framework: the requested attributes are released, with the sign
message digest and the SAD for a signature service, a coordination number is only released to a Service Provider
that accepts it, and a sign message that had to be displayed but was not fails the request. This is the same result as
the defaults of saml-identity-provider. The `SADFactory` of the producer defaults to one that signs with the signing
credential of the Identity Provider.

Add entries in an [adapter](configuration.html#adjusting-the-configuration-in-code). An entry that applies to all
protocols goes in the shared list:

```java
@Bean
AuthnServerConfigurerAdapter releaseRules() {
  return (http, configurer) -> configurer
      .attributeReleaseVoters(voters -> voters.addFirst(new AllowedAttributesVoter()))
      .postAuthenticationProcessors(processors -> processors.add(new MyChecks()))
      .protocol(Saml2IdpConfigurer.class, saml -> saml
          .attributeProducers(producers -> producers.addFirst(new MySamlOnlyProducer()))
          .ssoVoters(voters -> voters.add(new MySamlOnlySsoVoter())));
}
```

The lists are read when the filter chain is built, so changes after that have no effect. The single sign-on voters
and post-authentication processors of the lists reach the providers that extend `AbstractUserAuthenticationProvider`.

<a name="the-response"></a>
## The response

A successful authentication is answered with a signed `Response` holding one assertion, built by
[`Saml2AssertionBuilder`][Saml2AssertionBuilder]:

- The `Subject` holds the `NameID` from the generator that was set up when the request was processed, see
  [Attributes](attributes.html#identifying-the-user), and one `SubjectConfirmation`.
- The subject confirmation is `bearer`, with the assertion consumer service as `Recipient`, the ID of the request as
  `InResponseTo`, and the address the user was authenticated from. For a request received on a Holder-of-key
  endpoint, it is `holder-of-key` instead, with the certificate that the client presented in the TLS handshake in a
  `KeyInfo`, as the SAML V2.0 Holder-of-Key Web Browser SSO Profile requires. A request on a Holder-of-key endpoint
  without a client certificate is answered with `Responder` / `AuthnFailed`.
- The `Conditions` limit the audience to the Service Provider, and give the validity period from
  `authn-server.saml.assertions.not-before` and `not-after`.
- The `AuthnStatement` holds the authentication instant, the address of the user, and the authentication context of
  the authentication. The `attribute.authentication-provider` attribute, set by a module that delegates the
  authentication, becomes `AuthenticatingAuthority`.
- The `AttributeStatement` holds the released attributes, mapped to SAML attributes by the
  [`SamlAttributeMapping`][SamlAttributeMapping]. Assign a mapping of your own with
  `Saml2IdpConfigurer.attributeMapping(...)`, see [Attributes](attributes.html#mapping).

The assertion is signed when the Service Provider metadata states `WantAssertionsSigned`, and always for
Holder-of-key. It is encrypted for the Service Provider when `authn-server.saml.assertions.encrypt` is `true`, which is
the default, with a key and the algorithms of the Service Provider metadata. The response is always signed.

The response is posted to the assertion consumer service by the response page, together with the relay state. The
default page is a form that the browser submits by itself.

<a name="failures"></a>
## Failures

Until the Service Provider is known and the assertion consumer service has been established, there is nowhere to send
a response. Failures up to that point end at the Identity Provider as an `UnrecoverableErrorException`, with one of
the errors of [`SamlUnrecoverableError`][SamlUnrecoverableError]. After that point, a failure is answered to the
Service Provider with a signed error response, posted to the assertion consumer service together with the relay
state.

| Failure | Outcome |
| :--- | :--- |
| The message cannot be decoded, is not an `AuthnRequest`, or lacks version, ID or issuer | Unrecoverable |
| The `Destination` does not match the endpoint | Unrecoverable |
| The message is too old | Unrecoverable |
| The Service Provider is not known | Unrecoverable (`UNKNOWN_PEER`) |
| The client registry fails when the Service Provider is looked up | Unrecoverable (`PEER_LOOKUP_FAILED`) |
| The request has already been received | Unrecoverable |
| The assertion consumer service is not in the metadata | Unrecoverable |
| The signature is missing or invalid | Unrecoverable |
| The Service Provider has no key for encrypted assertions | `Requester` / `RequestDenied` |
| The Service Provider is not accepted | `Responder` / `RequestDenied` |
| The `NameIDPolicy` asks for a format that is not supported | `Requester` / `InvalidNameIDPolicy` |
| `ForceAuthn` and `IsPassive` are both set | `Requester` / `RequestUnsupported` |
| The requested authentication context cannot be resolved | `Requester` / `RequestUnsupported` |
| The `SignMessage` cannot be decrypted or has nothing to display | `Requester` / `RequestUnsupported` |
| The `UserMessage` has a MIME type that is not supported, and user messages are supported | `Requester` / `RequestUnsupported` |
| The `SADRequest` is invalid | `Requester` / `RequestUnsupported` |
| A request on a Holder-of-key endpoint has no client certificate | `Responder` / `AuthnFailed` |
| No provider can deliver a requested authentication context | `Requester` / `NoAuthnContext` |
| The authentication fails, or the module reports an error | The status of the error, see [Errors](authentication-module.html#errors) |
| A sign message had to be displayed, but was not | `Responder` / `AuthnFailed` |
| The resume path is reached without a matching authentication in progress | Unrecoverable (`INVALID_SESSION`) |

An unknown Service Provider and a registry that fails are logged differently: the first at `INFO`, since it is a
normal outcome, and the second at `ERROR`, since a dependency is not working.

The status message of an error response is resolved from the message code of the error against a `MessageSource`, when
one is given, and is otherwise the description of the error.

## Replacing parts of the processing

The components have defaults built from the configuration. Replace them in an
[adapter](configuration.html#adjusting-the-configuration-in-code) through the
[`Saml2AuthnRequestProcessorConfigurer`][ProcessorConfigurer]:

```java
@Bean
AuthnServerConfigurerAdapter samlProcessing(final MessageSource messageSource) {
  return (http, configurer) -> configurer.protocol(Saml2IdpConfigurer.class, saml -> saml
      .authnRequestProcessor(processor -> processor
          .messageSource(messageSource)
          .responsePage(myResponsePage)));
}
```

The replay checker, the requested attribute resolver, the sign message extractor, the assertion consumer service
validator, the response page, the message source, and customizers for assertions and responses can be replaced this
way. The assertion customizer gets the assertion before it is signed and encrypted.

[Converter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestAuthenticationConverter.java
[ProcessorConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/config/Saml2AuthnRequestProcessorConfigurer.java
[Provider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestAuthenticationProvider.java
[Saml2AssertionBuilder]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/response/Saml2AssertionBuilder.java
[Saml2AuthnRequestData]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestData.java
[SamlAttributeMapping]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/attributes/SamlAttributeMapping.java
[SamlAuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authentication/SamlAuthenticationRequirements.java
[SamlUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/error/SamlUnrecoverableError.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
