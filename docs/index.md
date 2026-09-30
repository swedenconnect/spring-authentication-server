![Logo](images/sweden-connect.png)

# Spring Authentication Server

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

The [spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository comprises
base libraries for building a SAML Identity Provider, an OpenID Provider, or a server that is both, according to the
[Swedish eID Framework specifications](https://docs.swedenconnect.se/technical-framework) and the
[Swedish OpenID Connect specifications](https://www.oidc.se/specifications/).

User authentication is implemented once and serves both protocols. A deployment that offers both gets shared single
sign-on across them, and a deployment that offers only one never has to know that the other exists.

## Modules

The libraries:

- `authn-server-core` - The protocol-neutral parts: user authentication, single sign-on, authentication requirements,
  the user identity model and errors.

- `authn-server-saml` - SAML Identity Provider support.

- `authn-server-oidc` - OpenID Provider support.

- `authn-server-autoconfigure` - Spring Boot auto-configuration for all of the above. A protocol is configured only
  when its module is on the classpath and it has been enabled.

The Spring Boot starters:

- `authn-server-spring-boot-starter` - Both SAML and OpenID Connect.

- `authn-server-saml-spring-boot-starter` - SAML only.

- `authn-server-oidc-spring-boot-starter` - OpenID Connect only.

## Documentation

- [Writing an authentication module](authentication-module.html) - How to authenticate users: what an authentication
  module receives, what it returns, how single sign-on is decided, and the errors a module can raise.

- [Attributes](attributes.html) - The protocol-neutral attribute model, the built-in attributes, how they map to SAML
  attributes and OpenID Connect claims, how a request is worked out into the attributes it asks for, how what is
  released is decided, and how the identifier of the user, the SAML `NameID` and the OpenID Connect `sub`, is produced.

- [The client registry](client-registry.html) - How the server finds out about a requester: the protocol-neutral
  record and its marks, the SAML metadata sources, the three OpenID Connect backends, and resolving clients through
  OpenID Federation with caching, trust marks on demand and trust mark status checks.

- [The SAML Identity Provider](saml-identity-provider.html) - How a request flows from the Service Provider through
  the authentication to the response: how requests are processed, how the provider is chosen, single sign-on and its
  policies, modules with pages of their own, the producers, voters and processors and their order, what the response
  holds, which failures are answered to the Service Provider, and how to replace the processing components.

- [The OpenID Provider](openid-provider.html) - Where the discovery document and the keys are published, how the
  signing and decryption keys are configured and rolled over, how the signing key for a client is chosen, how the
  scopes, claims and authentication contexts are worked out from the authentication providers, how to extend the
  discovery document, and how the OpenID Provider joins an OpenID Federation: its entity configuration, federation
  keys, trust marks and descriptive metadata.

- [Configuration](configuration.html) - The properties of the auto-configuration, the URL layout of the server, the
  entity information that every protocol publishes, adjusting the configuration in code, using the configurers without
  Spring Boot, and migrating the configuration of an Identity Provider built on saml-identity-provider.

- [Release Notes](release-notes.html)

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
