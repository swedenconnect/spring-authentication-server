![Logo](images/sweden-connect.png)

# Writing an authentication module

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

An authentication module is the part of the server that actually authenticates the user. It shows a login screen, talks
to a BankID server, verifies a client certificate, or delegates to another Identity Provider. Everything around it, the
protocol endpoints, the request parsing, the assertion and token building, is the library's job.

User authentication is implemented once and serves both SAML and OpenID Connect. A module is therefore written against
protocol-neutral types only, all of them in `authn-server-core`. Write the module once and it works in an Identity
Provider, in an OpenID Provider, and in a server that is both, with single sign-on shared between the two.

A module has one job: take what the requester asked for, authenticate the user, and say who the user is and how it was
done.

- It receives an `AuthenticationRequirements` object.
- It returns a `UserAuthentication` object holding an `AuthenticatedUser`.

This guide covers those two objects. It will grow as the library does: the provider interface that a module plugs into,
the single sign-on policies and the redirect flow to a module's own web pages are not built yet.

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

## What the module receives

[`AuthenticationRequirements`][AuthenticationRequirements] is what the requester asked for, with the differences
between the two protocols already resolved. The module does not need to know which protocol was used.

This is the mapping, in case you need to reason about a request you are looking at:

| What the module sees | SAML | OpenID Connect |
| :--- | :--- | :--- |
| `isForceAuthn()` | `ForceAuthn` | `prompt=login` |
| `getMaxAuthnAge()` | - | `max_age` |
| `isPassiveAuthn()` | `IsPassive` | `prompt=none` |
| `isConsentRequired()` | - | `prompt=consent` |
| `getRequestedAttributes()` | `RequestedAttribute`, from the request or from metadata | the `claims` parameter |
| `getAuthnContextRequirements()` | `AuthnContextClassRef` in `RequestedAuthnContext` | `acr_values` |
| `getRequestedAuthnProviders()` | `IDPList` under `Scoping` | `authnProvider` |
| `getOriginalRequesters()` | `RequesterID` under `Scoping` | `originalClientId`, `originalClientToken` |
| `getUserMessage()` | the `UserMessage` extension | `userMessage` |
| `getSignMessage()` | the `SignMessage` extension | `sign_message` in `signRequest` |

### Whether to authenticate the user again

`isForceAuthn()` means the user must be authenticated again even if an earlier authentication could have been reused. A
maximum authentication age of zero means the same thing, since that is how OpenID Connect defines `max_age=0`, so the
module only has to look at `isForceAuthn()`.

`isPassiveAuthn()` means the module must not interact with the user at all. A module that can only work by asking the
user something cannot serve such a request and must say so rather than show a screen.

### Which authentication contexts are acceptable

`getAuthnContextRequirements()` holds the authentication context URIs the requester accepts, in its order of
preference, because that is how `acr_values` is defined. Sweden Connect uses the same URIs in SAML and in OpenID
Connect, so this is one list for both protocols.

The module picks the context it can deliver, authenticates at that level, and reports the URI it actually used as part
of the authenticated user.

### Which attributes are requested

`getRequestedAttributes()` holds the requested attributes in the generic form described in
[Attributes](attributes.html). A requested attribute may be essential, and it may carry the values the requester will
accept.

There is no separate notion of principal selection. When a SAML requester sends a `PrincipalSelection` extension, or an
OpenID Connect client sends a claims request with a `value`, the module sees a requested attribute that carries that
value and is not essential. A hint that the user is `197705232382` therefore arrives as a requested
`attribute.personal-identity-number` with that value, and a module that can prefill a field should look for exactly
that.

A module returns the attributes it actually established. It is not obliged to return everything that was asked for, and
it may return more.

### Where to authenticate, and who is really asking

`getRequestedAuthnProviders()` is the requester asking for a particular authentication service or mechanism. A server
that offers several should honour it when it can.

`getOriginalRequesters()` matters when the requester is itself a proxy and is passing on who originally asked. Each
[`OriginalRequester`][OriginalRequester] is an identifier and an optional token. SAML allows any number of identifiers
and carries no token; OpenID Connect allows one identifier and may add a token whose format no specification defines.
Use it for what you display to the user, never for an access decision, since it is the proxy's claim about a third
party.

### The user message

`getUserMessage()` is a message the requester wants shown together with the authentication, for example "You are about
to sign in to the Tax Agency". If the module shows a screen, it should show this message.

A [`GenericUserMessage`][GenericUserMessage] holds the message in one or more languages, one
[`LocalizedMessage`][LocalizedMessage] per language, and all of them share one MIME type. Ask for the language you are
rendering in:

```java
LocalizedMessage message = requirements.getUserMessage().getMessage("sv-SE");
String text = message != null ? message.getText() : null;
```

`getMessage` prefers an exact language match, then a message in the same primary language, so `sv-SE` finds an `sv`
message, and last the message that is not tied to a language. It returns `null` when there is nothing to show in that
language, which is a real possibility: SAML requires a language on every message, and only OpenID Connect allows one
message without one.

Both specifications carry the message as Base64 of UTF-8, so that is how it is held. `getText()` decodes it. Render it
according to `getMimeType()`, which is `text/plain`, `text/markdown` or `text/html`; see
[`MessageMimeType`][MessageMimeType]. A module that cannot render Markdown or HTML should not fall back to showing the
raw markup.

### The sign message

`getSignMessage()` is different in kind. It is not information, it is what the user is approving, and it belongs to a
signature operation. A [`GenericSignMessage`][GenericSignMessage] holds the same messages and MIME type as a user
message, and adds two things:

- `isMustShow()`. When it is set and the module cannot display the message, the operation must fail. It must not
  authenticate the user and quietly leave the message unshown. SAML states this in `MustShow`; OpenID Connect always
  requires the message to be shown.

- `getTbsData()`, the data to be signed, Base64 encoded. Only the OpenID Connect signing case carries it.

A module that displays a sign message must record that it did, and in which language, on the authenticated user. That
is what makes the result non-reusable, see
[When a result must not be reused](#when-a-result-must-not-be-reused-for-single-sign-on) below.

An encrypted SAML sign message is decrypted before the module sees it, and the SAML `DisplayEntity` has already been
checked against the server's own entityID. Neither reaches the module.

### What SAML adds

A protocol may ask for more than the generic model holds, so `AuthenticationRequirements` can be subtyped. A module
written against the generic type works everywhere; a module that only ever runs in an Identity Provider may look for
[`SamlAuthenticationRequirements`][SamlAuthenticationRequirements], which adds the entity categories the Service
Provider declares in its metadata and the `SADRequest` extension that a signature service sends.

```java
if (requirements instanceof final SamlAuthenticationRequirements saml) {
  ...
}
```

## What the module returns

### The authenticated user

[`AuthenticatedUser`][AuthenticatedUser] is what the module established about the user. It is a Spring Security
`UserDetails`.

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
```

The five things the module must supply:

- The attributes it established, in the generic form. There must be at least one.

- The identifier of the primary attribute, which is the one that identifies the user. Its value becomes the user name,
  so it must be one of the attributes above. For a Swedish eID this is normally the personal identity number.

- The authentication context URI the module actually authenticated at, which is not necessarily the requester's first
  choice.

- The authentication instant.

- The IP address of the client the user was authenticated from.

The constructor rejects an empty set of attributes, a primary attribute that is not among them, and a missing
authentication context, instant or client address. Getting one of these wrong is a programming error, not a runtime
condition, so it fails immediately rather than producing a half-valid result.

A module that delegates the authentication to another service does not record the authenticating authority separately.
Set the `attribute.authentication-provider` attribute and the SAML layer turns it into `<AuthenticatingAuthority>`.

If the module displayed a sign message, say so and say in which language, because an OpenID Connect sign message may
have been offered in several and only the one shown matters:

```java
user.setSignMessageDisplayed(true, "sv");
```

### The authentication result

[`UserAuthentication`][UserAuthentication] is a Spring Security `Authentication` wrapping the user. It is what the SAML
layer turns into an assertion and the OpenID Connect layer into tokens, and it is what is kept in the session for
single sign-on.

```java
UserAuthentication authentication = new UserAuthentication(user);
```

The user is the principal, and `getName()` returns the user name. For most modules that is the whole of it: create the
object and return it.

Because the object lives in the session, everything it holds must survive Java serialization. That includes the
attribute values a module puts on the user, so a module that invents its own attribute value type must make it
`Serializable`.

### When a result must not be reused for single sign-on

By default a result may be reused, and `isReuseForSso()` says so. A module turns that off when the authentication was
tied to this one request:

```java
authentication.setReuseForSso(false);
```

One case is decided for the module: when a sign message was displayed, the result is never reusable and that cannot be
undone. Section 2.4 of the Sweden Connect OpenID Connect profile forbids saving a signature approval for single
sign-on, and the same holds for a SAML signature service. Recording the displayed sign message on the user is enough;
`setReuseForSso(true)` afterwards has no effect.

Turning reuse off is a decision that the result must not be saved. Leaving it on is not a decision that it will be: the
server may still choose not to save it.

### How use of the result is tracked

The library records every time a result is used, one record per use, in an
[`AuthenticationUsageTrack`][AuthenticationUsageTrack]. A record holds the protocol, the requester, the request
identifier where the protocol has one, the instant and the attributes that requester asked for. The first record is the
original authentication, and `isSsoApplied()` tells whether there were more.

A module does not write these records. It is worth knowing they exist, because they are what the single sign-on
policies will decide from: how long ago the user was authenticated, at which context, for which requester, and whether
a different set of attributes is being asked for the second time. That last one is why the requested attributes are
part of each record; the Sweden Connect OpenID Connect profile, Section 2.2.1, requires `interaction_required` when a
different set of claims is requested.

The requirements and the protocol data of the request are cleared from the result before it is saved, so a module must
not expect them to still be there when a result comes back from the session.

[AuthenticatedUser]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticatedUser.java
[AuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticationRequirements.java
[AuthenticationUsageTrack]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticationUsageTrack.java
[GenericSignMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/GenericSignMessage.java
[GenericUserMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/GenericUserMessage.java
[LocalizedMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/LocalizedMessage.java
[MessageMimeType]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/MessageMimeType.java
[OriginalRequester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/OriginalRequester.java
[SamlAuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authentication/SamlAuthenticationRequirements.java
[UserAuthentication]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/UserAuthentication.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
