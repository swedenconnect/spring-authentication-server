![Logo](images/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

### Version 1.0.1

**Date:** _Not yet released_

- An OpenID Provider may now offer a scope without supporting all of its claims. `claims_supported` lists only the
  claims that the OpenID Provider can deliver.
- The Sweden Connect reference server delivers a simulated user's coordination number as a coordination number, not
  as a personal identity number.
- An OpenID Provider treats an authentication request without `prompt` as `prompt=login`, as the OpenID Connect Profile for Sweden Connect requires. This can be turned off for deployments outside Sweden Connect. See [#12](https://github.com/swedenconnect/spring-authentication-server/issues/12).

-----

### Version 1.0.0

**Date:** 2026-10-06

- Initial version.

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
