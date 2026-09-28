![Logo](images/sweden-connect.png)

# Spring Authentication Server

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

The [spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository comprises
base libraries for building a SAML Identity Provider, an OpenID Provider, or a server that is both.

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

- [Configuration](configuration.html) - Auto-configuration and the complete set of properties.

- [Release Notes](release-notes.html)

-----

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
