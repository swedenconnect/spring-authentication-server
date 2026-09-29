![Logo](images/sweden-connect.png)

# The authentication result

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

User authentication is implemented once and serves both SAML and OpenID Connect. What the authentication step produces
is therefore protocol-neutral, and it is kept in the user session so that it can be reused for single sign-on, also by
the other protocol. This page describes the authenticated user, the authentication result that holds it, and the
tracking that the single sign-on policies work on.

Both classes live in `authn-server-core` and know nothing about either protocol.

## The authenticated user

An `AuthenticatedUser` is what the authentication step found out about the user. It is a Spring Security `UserDetails`,
and it holds:

- The user's [generic attributes](attributes.html). There is always at least one.

- The identifier of the primary attribute. It must appear among the attributes, and its value is the user name that
  `getUsername()` returns.

- The authentication context URI under which the user was authenticated. Sweden Connect uses the same URIs as SAML
  `AuthnContextClassRef` and as OpenID Connect `acr`, so one value serves both protocols.

- The authentication instant.

- The IP address of the client that the user was authenticated from.

- Whether a sign message was displayed for the user, and in which language. The language is recorded because an
  OpenID Connect sign message may be given in several languages, and only the one that was actually displayed matters.

```java
AuthenticatedUser user = new AuthenticatedUser(
    List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
        GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Agda"),
        GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")),
    AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
    "http://id.elegnamnden.se/loa/1.0/loa3",
    Instant.now(),
    "192.168.1.14");

user.setSignMessageDisplayed(true, "sv");
```

The constructor rejects an empty set of attributes, a primary attribute that does not appear among the attributes with
a value, and a missing authentication context URI, authentication instant or client IP address.

A server that proxies the authentication to another service does not record the authenticating authority here. The
authentication step sets the `attribute.authentication-provider` attribute instead, and the SAML layer turns that into
`<AuthenticatingAuthority>`.

## The authentication result

A `UserAuthentication` is a Spring Security `Authentication` holding the authenticated user. It is what the SAML layer
turns into an assertion and the OpenID Connect layer into a set of tokens, and it is the object that is stored in the
session.

```java
UserAuthentication authentication = new UserAuthentication(user);
```

The user is both the principal and the details of the token, and `getName()` returns the user name.

### Reuse for single sign-on

`isReuseForSso()` tells whether the result may be reused. It may, by default.

A result where a sign message was displayed for the user is never reusable, and that cannot be changed. Section 2.4 of
the Sweden Connect OpenID Connect profile forbids saving a signature approval for single sign-on, and the same holds
for a SAML signature service. Calling `setReuseForSso(true)` for such a result has no effect.

```java
user.setSignMessageDisplayed(true, "sv");

authentication.setReuseForSso(true);
authentication.isReuseForSso();   // false
```

Even when a result is reusable the server may choose not to save it. When it is not reusable it is never saved.

### Protocol specific request data

The generic layer carries the data of the request that the result was produced for, but never looks at it. It is
whatever the protocol layer needs in order to look at the actual request, and the SAML layer keeps its authentication
request token there.

```java
authentication.setProtocolRequestData(requestToken);
...
Saml2AuthnRequestToken token = authentication.getProtocolRequestData(Saml2AuthnRequestToken.class);
```

The data is cleared before the result is saved for single sign-on. By then the request has been answered and there is
no reason to keep it in the session.

```java
authentication.clearProtocolRequestData();
```

### Usage tracking

An `AuthenticationUsageTrack` holds one `AuthenticationUse` record per time the result has been used. Each record
holds:

- The protocol that the requester used, SAML or OpenID Connect.

- The requester, a SAML SP entityID or an OpenID Connect `client_id`.

- The identifier of the request, which is the ID of the SAML `AuthnRequest`. OpenID Connect has no such identifier, so
  the value is `null` for that protocol.

- The instant of the use. For the first record this is the authentication instant of the user.

- The identifiers of the generic attributes that the requester asked for.

The first record is the original authentication. Every record after that is a use where single sign-on was applied,
which is what `isSsoApplied()` reports.

```java
authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1a2b3c",
    List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME));

authentication.isSsoApplied();   // false, this was the original authentication

authentication.registerUse(AuthenticationProtocol.OIDC, "client-1", null,
    List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));

authentication.isSsoApplied();   // true
```

The records hold this much because the single sign-on policies are configurable, from no single sign-on at all to
single sign-on for as long as the session lives. The default policy allows single sign-on for a limited time with the
same authentication context, and only for the same requester. Section 2.2.1 of the Sweden Connect OpenID Connect
profile also requires `interaction_required` when a different set of claims is requested, which is why the requested
attributes are part of each record.

## Serialization

The result is stored in the session, so everything it holds survives Java serialization: the user with its attributes,
the reuse flag, the usage records and the protocol specific request data. Anything a protocol layer puts in the
protocol specific request data must be `Serializable` too.

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
