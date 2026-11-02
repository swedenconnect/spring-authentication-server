![Logo](images/sweden-connect.png)

# Sweden Connect Reference OpenID Provider

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page is for developers of Relying Parties that use the Sweden Connect Reference OpenID Provider.

## Table of Contents

1. [**About the service**](#about-the-service)

2. [**Authentication contexts**](#authentication-contexts)

3. [**Scopes and claims**](#scopes-and-claims)

4. [**Simulated users**](#simulated-users)

5. [**Signature approval and user messages**](#signature-approval-and-user-messages)

6. [**Testing error handling**](#testing-error-handling)

7. [**Limitations compared with a production OpenID Provider**](#limitations)

8. [**More information and support**](#more-information-and-support)

<a name="about-the-service"></a>
## 1. About the service

The Reference OpenID Provider helps developers test a Relying Party against Sweden Connect. No real authentication takes place. The user selects a simulated person from a list instead. Authentication requests are processed, and ID tokens and UserInfo responses are issued, according to the [OpenID Connect Profile for Sweden Connect](https://docs.swedenconnect.se/technical-framework/updates/OpenID_Connect_Profile_for_Sweden_Connect.html) and the [Swedish OpenID Connect specifications](https://www.oidc.se/specifications/).

The service must never be used to protect real services or real user data, since anyone who reaches it can authenticate as any simulated person.

The service is open source and is part of the [Spring Authentication Server](https://github.com/swedenconnect/spring-authentication-server) repository, in the [sweden-connect-reference](https://github.com/swedenconnect/spring-authentication-server/tree/main/sweden-connect-reference) module. The same service also acts as a SAML Identity Provider, which this page does not cover.

The endpoints, keys and supported features of a deployment are published in its discovery document, at the issuer followed by `/.well-known/openid-configuration`. Where the discovery document differs from this page, the discovery document applies.

<a name="authentication-contexts"></a>
## 2. Authentication contexts

The service supports these values for `acr`:

- `http://id.elegnamnden.se/loa/1.0/loa2`
- `http://id.elegnamnden.se/loa/1.0/loa3`
- `http://id.elegnamnden.se/loa/1.0/loa4`
- `http://id.swedenconnect.se/loa/1.0/uncertified-loa3`

The values are simulated. An ID token from this service says nothing about the actual assurance level of the person using the browser.

When a request accepts several values, the tester selects one of them on the login page. The ID token always holds the `acr` claim.

<a name="scopes-and-claims"></a>
## 3. Scopes and claims

The service offers these scopes:

- `openid`
- `profile`
- `https://id.oidc.se/scope/naturalPersonInfo`
- `https://id.oidc.se/scope/naturalPersonNumber`
- `https://id.oidc.se/scope/signApproval`

In addition to `sub`, `auth_time` and `acr`, the service can deliver these claims:

- `https://id.oidc.se/claim/personalIdentityNumber`
- `https://id.oidc.se/claim/coordinationNumber`
- `given_name`
- `family_name`
- `name`
- `birthdate`

A person has either a personal identity number or a coordination number, never both. A scope can also cover claims that are not listed here, and those claims are not delivered.

<a name="simulated-users"></a>
## 4. Simulated users

The login page shows the Relying Party's name and logotype, and a list of simulated persons.

- **Selecting a person.** The tester selects a person from the list, and the last selection is remembered in a cookie.
- **Adding a person.** Under "Advanced", the tester can enter a personal identity number and a name. The person is saved in a cookie in the tester's browser. At most 40 added persons are kept, and the oldest is dropped when more are added.
- **Requesting a person.** When a request asks for a specific personal identity number as a requested value of the personal identity number claim, and that person is in the list, the person is selected and the selection is locked.

<a name="signature-approval-and-user-messages"></a>
## 5. Signature approval and user messages

The service supports the Signature Approval use case of the [Signature Extension for OpenID Connect](https://www.oidc.se/specifications/oidc-signature-extension-1_2.html). The request asks for the `https://id.oidc.se/scope/signApproval` scope and holds a signature request with the `https://id.oidc.se/param/signRequest` parameter. The login page then asks the tester to sign and shows the sign message.

The service supports the user message parameter, `https://id.oidc.se/param/userMessage`, of the [Authentication Request Parameter Extensions](https://www.oidc.se/specifications/request-parameter-extensions-1_1.html). A user message is shown when the request has no sign message.

Sign messages and user messages can have the MIME type `text/plain` or `text/markdown`. Messages are shown in the language of the page. The pages are available in Swedish (`sv`) and English (`en`).

<a name="testing-error-handling"></a>
## 6. Testing error handling

Under "Simulate Error" on the login page, the tester can send an error back to the Relying Party instead of authenticating, with a message of the tester's choice. The available errors are `AUTHN_FAILED`, `CANCEL`, `FRAUD`, `POSSIBLE_FRAUD`, `UNKNOWN_PRINCIPAL`, `NO_AUTHN_CONTEXT`, `NOT_AUTHORIZED` and `SIGN_MESSAGE_NOT_DISPLAYED`. Each is turned into the matching OpenID Connect error response.

<a name="limitations"></a>
## 7. Limitations compared with a production OpenID Provider

- User authentication is simulated, and all persons are test identities.
- The Signing use case and the `https://id.oidc.se/scope/sign` scope are not supported, since the simulated authentication cannot produce a user signature.
- Only the claims in [Section 3, "Scopes and claims"](#scopes-and-claims) are delivered.
- Refresh tokens are not issued.

<a name="more-information-and-support"></a>
## 8. More information and support

- [Source code and issue tracker](https://github.com/swedenconnect/spring-authentication-server)
- [The reference service: building, deploying and configuring it](https://github.com/swedenconnect/spring-authentication-server/blob/main/sweden-connect-reference/README.md)
- [Spring Authentication Server documentation](https://docs.swedenconnect.se/spring-authentication-server/)
- Contact: [operations@swedenconnect.se](mailto:operations@swedenconnect.se)

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
