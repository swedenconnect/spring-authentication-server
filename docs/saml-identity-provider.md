![Logo](images/sweden-connect.png)

# The SAML Identity Provider

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page describes how the SAML Identity Provider receives an authentication request and turns it into the
protocol-neutral authentication requirements that the authentication modules work with, which failures are answered to
the Service Provider, and how to replace the parts of the processing. The properties are described in
[Configuration](configuration.html#the-saml-identity-provider).

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

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
validator, the response page, the message source and a customizer for responses can be replaced this way.

[Converter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestAuthenticationConverter.java
[ProcessorConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/config/Saml2AuthnRequestProcessorConfigurer.java
[Provider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestAuthenticationProvider.java
[Saml2AuthnRequestData]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authnrequest/Saml2AuthnRequestData.java
[SamlAuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authentication/SamlAuthenticationRequirements.java
[SamlUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/error/SamlUnrecoverableError.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
