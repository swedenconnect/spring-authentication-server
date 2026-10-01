![Logo](docs/images/sweden-connect.png)


# Sweden Connect Spring Authentication Server

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg) ![Maven Central](https://img.shields.io/maven-central/v/se.swedenconnect.spring.authnserver/spring-authentication-server-parent.svg)

This repository comprises of Spring Security libraries for building a SAML Identity Provider, an
OpenID Provider, or an authentication server that acts as both, according to the
[Swedish eID Framework specifications](https://docs.swedenconnect.se/technical-framework) and the
[Swedish OpenID Connect specifications](https://www.oidc.se/specifications/).

User authentication is implemented once and is used by both protocols, including single sign-on
across SAML and OpenID Connect.

-----

## About

The repository comprises of the following modules:

- `authn-server-core` - Protocol-neutral support for user authentication, single sign-on,
authentication requirements and the user identity model.

- `authn-server-saml` - The Spring Security implementation of a SAML Identity Provider.

- `authn-server-oidc` - The Spring Security implementation of an OpenID Provider.

- `authn-server-autoconfigure` - Spring Boot autoconfiguration for the authentication server.

- Spring Boot starters:

    - `authn-server-spring-boot-starter` - SAML Identity Provider and OpenID Provider.

    - `authn-server-saml-spring-boot-starter` - SAML Identity Provider only.

    - `authn-server-oidc-spring-boot-starter` - OpenID Provider only.

The [sweden-connect-reference](sweden-connect-reference) module is the Sweden Connect reference authentication
server, a SAML Identity Provider and OpenID Provider with simulated user authentication, built on the libraries.

## Documentation

See [https://docs.swedenconnect.se/spring-authentication-server](https://docs.swedenconnect.se/spring-authentication-server/) for documentation about Java classes and configuration.

Also, see the [Release Notes](https://docs.swedenconnect.se/spring-authentication-server/release-notes.html).

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
