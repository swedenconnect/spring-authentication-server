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

- It receives an `AuthenticationRequirements` object, wrapped in a `UserAuthenticationInputToken`.
- It returns a `UserAuthentication` object holding an `AuthenticatedUser`.

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

## Writing the provider

A module plugs into the server as a [`UserAuthenticationProvider`][UserAuthenticationProvider], which is a Spring
Security `AuthenticationProvider`. Extend [`AbstractUserAuthenticationProvider`][AbstractUserAuthenticationProvider] and
implement three methods:

```java
public class MyAuthenticationProvider extends AbstractUserAuthenticationProvider {

  @Override
  public @Nonnull String getName() {
    return "my-provider";
  }

  @Override
  public @Nonnull List<String> getSupportedAuthnContextUris() {
    return List.of(LOA3, LOA4);
  }

  @Override
  protected @Nonnull Authentication authenticate(final @Nonnull UserAuthenticationInputToken token,
      final @Nonnull List<String> authnContextUris) {
    ...
    return new UserAuthentication(user);
  }
}
```

The base class does everything around the authentication, in this order:

1. The requested authentication contexts are filtered against the ones the provider supports. If none remain, the
   provider does not handle the request at all and the next provider is asked. When no provider handles it, the
   requester gets `NO_AUTHN_CONTEXT`.

2. Single sign-on is decided. If a previous authentication may be reused, it is returned and `authenticate` is never
   called.

3. If the request required that the user was not interacted with, and single sign-on was refused, the request fails
   with `PASSIVE_NOT_POSSIBLE`.

4. Otherwise `authenticate` is called with the contexts that remain, in the requester's order of preference.

So `authenticate` is called only when the provider can serve the request and the user really has to authenticate. It
picks a context from `authnContextUris`, authenticates at that level, and returns the result.

Whatever the result comes from, single sign-on or a new authentication, the base class then gives it the requirements
and the protocol data of the request, records its use, and runs the
[post-authentication processing](#post-authentication-processing). A module does not do any of that itself.

Several providers may be installed, each supporting its own authentication contexts. A provider is asked only about
requests it can serve, so a module never has to check whether it is the right one.

### What the provider declares

Besides its authentication contexts, a provider may declare what it offers. The server publishes the declarations in
the SAML metadata and in the OpenID Connect discovery document. Each has a default method on
`UserAuthenticationProvider` that returns an empty list, so a provider overrides only what applies to it.

| Method | What it declares | Used by |
| :--- | :--- | :--- |
| `getSupportedAuthnContextUris()` | The authentication contexts the provider can deliver. Required. | SAML: the assurance certification attribute. OpenID Connect: `acr_values_supported`. |
| `getEntityCategories()` | SAML entity categories. | SAML: the entity category attribute. |
| `getSupportedAttributes()` | The generic attributes the provider can deliver, by identifier, such as `attribute.personal-identity-number`. | OpenID Connect: the supported claims, and the scopes when none are declared. |
| `getSupportedScopes()` | The OpenID Connect scopes the provider offers. | OpenID Connect: the offered scopes. |

```java
@Override
public @Nonnull List<String> getSupportedAttributes() {
  return List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME,
      AttributeIdentifiers.SURNAME, AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.DATE_OF_BIRTH);
}
```

A provider that declares its attributes normally does not need to declare scopes, since the OpenID Provider derives
them from the claims. Declare scopes when the derived set is wrong for the provider, for example a scope whose
essential claims the provider delivers only some of. How scopes and claims are worked out is described in
[The OpenID Provider](openid-provider.html#scopes-claims-and-authentication-contexts).

The declarations only tell what the server offers. They do not limit what the provider releases: a provider still
returns everything it knows about the user, see [The authenticated user](#the-authenticated-user). See
[Configuration](configuration.html#the-idp-metadata) for the SAML metadata.

A module that cannot authenticate the user inside this call, because it needs pages of its own, is written slightly
differently, see [Modules with pages of their own](#modules-with-pages-of-their-own).

## What the module receives

[`AuthenticationRequirements`][AuthenticationRequirements] is what the requester asked for, with the differences
between the two protocols already resolved. The module does not need to know which protocol was used. The
[`UserAuthenticationInputToken`][UserAuthenticationInputToken] adds who is asking, the identifier of the request, the
previous authentication if there is one, and the protocol data of the request.

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

`isPassiveAuthn()` means the module must not interact with the user at all. The base class already fails such a request
when single sign-on was refused, so `authenticate` is reached for a passive request only if the module can authenticate
the user without asking anything, for instance from a client certificate.

### Which authentication contexts are acceptable

`getAuthnContextRequirements()` holds the authentication context URIs the requester accepts, in its order of
preference, because that is how `acr_values` is defined. Sweden Connect uses the same URIs in SAML and in OpenID
Connect, so this is one list for both protocols.

A module does not read this list. It gets the contexts that are left after filtering, in the same order, as the second
argument to `authenticate`. It picks the one it delivers and reports it as part of the authenticated user.

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

A module that displays a sign message must record that it did, and in which language, on the authenticated user. The
post-authentication processing checks that, and a result where the message was not displayed fails with
`SIGN_MESSAGE_NOT_DISPLAYED`.

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

The same goes for the protocol data of the request, which the generic layer carries without looking at it. A module
that needs the request itself asks for it and casts it to the type its protocol module uses:

```java
Object requestData = token.getProtocolRequestData();
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

## Single sign-on

Single sign-on is what makes a previous authentication answer a new request, and it works across the two protocols: a
user who signed in at a SAML Service Provider can be let straight through at an OpenID Connect client.

### The rules that always apply

These are checked before any policy or voter, and no configuration turns them off:

- The requester asked for a new authentication, with `ForceAuthn` or `prompt=login`.
- The previous authentication is older than the maximum authentication age the requester accepts.
- The previous authentication may not be reused, which is the case when a sign message was displayed for it.
- The request carries a sign message. A signature is approved by the user every time, see the Deployment Profile,
  Section 7.1.1.
- An attribute value the requester asked for does not match the value the user has. A request that states that the user
  is `197705232382` is never answered with an authentication of somebody else.

### The policy

Everything else is an [`SsoPolicy`][SsoPolicy]. The default policy allows single sign-on for 60 minutes, which is the
Sweden Connect maximum, and only for the requester the authentication was made for. Two things are configurable:

- The time limit. `null` means single sign-on for as long as the user's session lives.
- Whether the same requester is required. It is, by default. "The same requester" means the same protocol and the same
  identity within it, so an organisation registered both as a SAML Service Provider and as an OpenID Connect client is
  two requesters.

What the policy never relaxes, beyond the rules above, is the authentication context: a previous authentication is
reused only when it was made under a context that is acceptable for the new request.

```java
SsoPolicy.defaultPolicy();      // 60 minutes, same requester
SsoPolicy.none();               // never
SsoPolicy.forSessionLifetime(); // as long as the session lives, any requester
```

The policy is set as a server default, a protocol may have a policy of its own, and a provider may override both. The
order is: provider, protocol, server default. For each request, the policy of the requester's protocol is used:

```java
provider.setServerSsoPolicy(SsoPolicy.none());                                     // set by the configuration
provider.setServerSsoPolicy(AuthenticationProtocol.SAML, SsoPolicy.defaultPolicy()); // set by the configuration
provider.setSsoPolicy(myOwnPolicy);                                                // this provider only
```

The server default and the protocol policies are set from the `authn-server.sso.*` and `authn-server.saml.sso.*`
properties, see [Configuration](configuration.html#single-sign-on).

### Voters

The decision is made by an ordered list of [`SsoVoter`][SsoVoter]s. One denial ends it, and at least one voter has to
allow it, so a request where every voter abstains gets no single sign-on. Three voters are installed: one applies the
policy, one requires the same authentication context, and one refuses when the requester asks for another set of
attributes than the original authentication was made for.

An application adds voters of its own to refuse single sign-on in cases the library knows nothing about:

```java
provider.getSsoVoters().add((previous, requirements, requester, contexts) ->
    previous.getAuthenticatedUser().getClientIpAddress().equals(currentIpAddress())
        ? SsoDecision.abstain()
        : SsoDecision.deny(SsoDenialReason.NOT_ALLOWED));
```

Voters that apply to every provider are better added to the server configuration, either to the shared list, for all
protocols, or to the list of one protocol. They are asked after the provider's own voters, see
[Producers, voters and processors](saml-identity-provider.html#producers-voters-and-processors).

A refusal always states its reason, an [`SsoDenialReason`][SsoDenialReason]. That matters for a passive request, see
below.

<a name="what-happens-to-the-session-authentication"></a>
### What happens to the session authentication

The session holds one authentication for the whole server, the one that a later request may reuse. What happens to it
depends on how a request ends:

- A successful authentication replaces it, provided that the new result may be reused. A result that may not be
  reused, such as one where a sign message was displayed, removes it.
- A redirect to the pages of a module leaves it in place. Starting a new authentication says nothing about the old one,
  so another request, for example in another browser tab, may still reuse it.
- An authentication that has started and ends in an error removes it. This covers every error a module reports,
  including `CANCEL`, `FRAUD` and `POSSIBLE_FRAUD`, and errors raised while the result is completed, such as
  `SIGN_MESSAGE_NOT_DISPLAYED`. After fraud, or after the user stopped, the earlier authentication must not let the next
  request through.
- A request that fails before any authentication started leaves it in place, since such a failure says nothing about
  the user. That is an invalid request, an unknown or rejected requester, `NO_AUTHN_CONTEXT` when no provider could
  take the request, and `PASSIVE_NOT_POSSIBLE` when the user was never asked.

### How use of the result is tracked

The library records every time a result is used, one record per use, in an
[`AuthenticationUsageTrack`][AuthenticationUsageTrack]. A record holds the protocol, the requester, the request
identifier where the protocol has one, the instant and the attributes that requester asked for. The first record is the
original authentication, and `isSsoApplied()` tells whether there were more.

A module does not write these records, and it should not read them either. They are what the voters decide from: how
long ago the user was authenticated, for which requester, and whether a different set of attributes is being asked for
the second time.

The requirements and the protocol data of the request are cleared from the result before it is saved, so a module must
not expect them to still be there when a result comes back from the session.

## Errors

A module reports a failure by throwing an [`AuthenticationErrorException`][AuthenticationErrorException] carrying an
[`AuthenticationError`][AuthenticationError]. The protocol module turns it into a SAML `Status` or an OpenID Connect
error response, so a module never writes protocol-specific error handling.

```java
throw new AuthenticationErrorException(AuthenticationError.CANCEL);
throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "The BankID server refused the order");
```

The second argument is a description for logs. In OpenID Connect it becomes the `error_description`, which the Swedish
OpenID Connect Profile, Section 2.3, asks to be something the Relying Party can put in its application logs. It is
never shown to the user, so write it for an operator, not for an end user.

These are the errors and how they reach the requester:

| Error | SAML status | OpenID Connect error |
| :--- | :--- | :--- |
| `AUTHN_FAILED` | `Responder` / `AuthnFailed` | `access_denied` |
| `CANCEL` | `Responder` / `.../status/1.0/cancel` | `access_denied` |
| `FRAUD` | `Responder` / `.../status/1.0/fraud` | `access_denied` |
| `POSSIBLE_FRAUD` | `Responder` / `.../status/1.0/possibleFraud` | `access_denied` |
| `SIGN_MESSAGE_NOT_DISPLAYED` | `Responder` / `AuthnFailed` | `access_denied` |
| `UNKNOWN_PRINCIPAL` | `Requester` / `UnknownPrincipal` | `access_denied` |
| `PASSIVE_NOT_POSSIBLE` | `Requester` / `NoPassive` | `login_required` or `interaction_required` |
| `NO_AUTHN_CONTEXT` | `Requester` / `NoAuthnContext` | `unmet_authentication_requirements` |
| `NOT_AUTHORIZED` | `Responder` / `RequestDenied` | `unauthorized_client` |

The three Sweden Connect status codes are `http://id.elegnamnden.se/status/1.0/` followed by `cancel`, `fraud` or
`possibleFraud`. They are second-level codes under `Responder`, as the Deployment Profile, Section 6.4, requires. A
server that detects fraud must not issue an assertion.

`CANCEL`, `FRAUD` and `POSSIBLE_FRAUD` are the errors a module raises that are not plain failures. Use `CANCEL` when
the user chose to stop, and the fraud codes when a security check alerted, not when the authentication merely failed.

The mappings live in the protocol modules, [`SamlErrorStatus`][SamlErrorStatus] and
[`OidcErrorMapping`][OidcErrorMapping], and a module does not call them.

### The passive case

`PASSIVE_NOT_POSSIBLE` is the one error whose OpenID Connect code depends on why it happened, so the exception carries
the `SsoDenialReason` that refused single sign-on. A request that could have been answered except that the requester
asks for another set of attributes gets `interaction_required`, as the OpenID Connect Profile for Sweden Connect,
Section 2.2.1, requires. Every other reason gets `login_required`. SAML has one code for all of them, `NoPassive`.

The base class raises this error, so a module does not.

### Errors that cannot be reported

Some failures make it impossible to send the user back to the requester at all, for instance when the request cannot be
tied to a session. The user is shown an error page instead. Those are an
[`UnrecoverableError`][UnrecoverableError], thrown as an `UnrecoverableErrorException`.

The core defines the two that do not depend on a protocol, in
[`CommonUnrecoverableError`][CommonUnrecoverableError]: an internal error and an invalid session. Each protocol module
adds its own as its request processing is built, which is why `UnrecoverableError` is an interface and not an enum.

## Modules with pages of their own

Most modules cannot authenticate the user inside the call to `authenticate`. They need to show a login screen, poll a
BankID server, or walk the user through a few steps. Such a module is sent the user instead: the server redirects to a
controller of the module's own, the controller authenticates the user, and the flow resumes afterwards.

The module writes two things, a provider and a controller, and neither of them has to know which protocol the requester
used. A SAML login and an OpenID Connect login reach the same controller and return to the same resume path.

### The provider

Extend [`AbstractUserRedirectAuthenticationProvider`][AbstractUserRedirectAuthenticationProvider] instead of
`AbstractUserAuthenticationProvider`. It takes the two paths, the one the user is sent to and the one the user comes
back to:

```java
public class MyAuthenticationProvider extends AbstractUserRedirectAuthenticationProvider {

  public MyAuthenticationProvider() {
    super("/authn/login", "/authn/resume");
  }

  @Override
  public boolean supportsUserAuthenticationToken(final @Nullable Authentication authentication) {
    return authentication instanceof UserAuthentication;
  }

  @Override
  protected @Nonnull UserAuthentication createUserAuthentication(final @Nonnull ResumedAuthenticationToken token) {
    return (UserAuthentication) token.getAuthnToken();
  }
}
```

Everything the base class does around an authentication still happens, and it happens before the user is sent
anywhere: the authentication contexts are filtered, single sign-on is decided, and a passive request that cannot be
answered fails. Only when the user really has to authenticate is a
[`RedirectForAuthenticationToken`][RedirectForAuthenticationToken] returned instead of a result. The server's filter
chain serves the two paths: the authentication path is open to everyone, and the resume path is where the flow
continues, in the protocol that the requester used. See
[The SAML Identity Provider](saml-identity-provider.html#modules-with-pages-of-their-own).

:raised_hand: Only these two exact paths are covered by the server's filter chain. Any other page of the module, such as
the one a login form posts to, is not, and the application must secure it in its own security configuration. For
example, permit the module's paths in the application's filter chain:

```java
@Bean
@Order(2)
SecurityFilterChain applicationSecurityFilterChain(final HttpSecurity http) throws Exception {
  http.authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/authn/**").permitAll()
      .anyRequest().denyAll());
  return http.build();
}
```

`createUserAuthentication` is the counterpart of `authenticate`. It is called when the user comes back, and it turns
what the controller delivered into the result. A controller that already delivers a `UserAuthentication` has nothing to
do but cast; one that delivers a token of its own builds the result from it. The result then runs through the same
post-authentication processing as a direct authentication, so a module does not do anything differently because the
authentication happened elsewhere.

`supportsUserAuthenticationToken` says whether the provider can use what the controller delivered. It is how the right
provider is found when several are installed.

### The identifier of the authentication

Each authentication gets an unguessable identifier when the redirect starts. It travels to the controller and back as
the `authnId` request parameter, and it is what makes several authentications in the same session independent of each
other: an OpenID Connect login in one browser tab and a SAML login in another do not disturb each other, and each
resumes with its own input and its own result.

An authentication is removed once it has been resumed, and one that is never resumed is removed when it is older than
the maximum age, 30 minutes by default. A request to the resume path that carries no identifier, or an identifier that
is unknown, expired or already resumed, is the invalid session error, and the user is shown an error page.

### The controller

Extend [`AbstractAuthenticationController`][AbstractAuthenticationController], which gives the controller what it needs
and takes care of getting the user back into the flow:

```java
@Controller
@RequestMapping("/authn")
public class MyAuthenticationController extends AbstractAuthenticationController<MyAuthenticationProvider> {

  private final MyAuthenticationProvider provider;

  public MyAuthenticationController(final MyAuthenticationProvider provider) {
    this.provider = provider;
  }

  @GetMapping("/login")
  public ModelAndView login(final HttpServletRequest request) {
    final RedirectForAuthenticationToken token = this.getInputToken(request);
    final ModelAndView view = new ModelAndView("login");
    view.addObject("authnId", token.getAuthnId());
    view.addObject("userMessage", token.getAuthnInputToken().getAuthnRequirements().getUserMessage());
    return view;
  }

  @PostMapping("/complete")
  public ModelAndView complete(final HttpServletRequest request) {
    ...
    return this.complete(request, new UserAuthentication(user));
  }

  @PostMapping("/cancel")
  public ModelAndView cancelled(final HttpServletRequest request) {
    return this.cancel(request);
  }

  @Override
  protected @Nonnull MyAuthenticationProvider getProvider() {
    return this.provider;
  }
}
```

`getInputToken` gives what this authentication was asked to do, the same `UserAuthenticationInputToken` the provider
was given, plus the authentication contexts that are left after filtering. There are three ways to finish, and all
three redirect the user to the resume path:

- `complete(request, authentication)` with what the module established.
- `complete(request, error)` with an `AuthenticationErrorException`, for an authentication that failed.
- `cancel(request)`, which is the same as completing with `AuthenticationError.CANCEL`.

A controller that spreads the authentication over several pages must carry the identifier along, as a hidden field or
in the link, so that every request lands on the right authentication. Losing it means the user cannot be brought back.

### Where the authentications are kept

The storage has two sides: [`RedirectFlowRepository`][RedirectFlowRepository], which the protocol flow uses to start an
authentication and pick up its outcome, and [`RedirectAuthenticatorRepository`][RedirectAuthenticatorRepository], which
is what the controller uses. They work on the same data, so one object,
[`RedirectAuthenticationRepository`][RedirectAuthenticationRepository], implements both.

[`SessionBasedRedirectAuthenticationRepository`][SessionBasedRedirectAuthenticationRepository] keeps them in the user's
session and is installed by default. Replace it to keep them somewhere else, and set the maximum age on it:

```java
final SessionBasedRedirectAuthenticationRepository repository = new SessionBasedRedirectAuthenticationRepository();
repository.setMaxAge(Duration.ofMinutes(10));
provider.setRepository(repository);
```

Whatever the storage, everything the module puts in it must survive Java serialization, including the token the
controller delivers.

## Post-authentication processing

A [`PostAuthenticationProcessor`][PostAuthenticationProcessor] runs on the result before it becomes an assertion or a
set of tokens, and asserts that the authentication delivered what the request needed. It may also change the result.

The processors of the server configuration run on every result. By default the shared list holds
`SwedenConnectPostAuthenticationProcessor`, which fails a result where a sign message had to be shown but was not. How
to add processors for all protocols or for one of them is described in
[Producers, voters and processors](saml-identity-provider.html#producers-voters-and-processors).

A provider may also have processors of its own, which run before those of the server configuration:

```java
provider.getPostAuthenticationProcessors().add(authentication -> {
  if (somethingIsWrong(authentication)) {
    throw new AuthenticationErrorException(AuthenticationError.NOT_AUTHORIZED, "why");
  }
});
```

[AbstractAuthenticationController]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/AbstractAuthenticationController.java
[AbstractUserAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/AbstractUserAuthenticationProvider.java
[AbstractUserRedirectAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/AbstractUserRedirectAuthenticationProvider.java
[AuthenticatedUser]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticatedUser.java
[AuthenticationError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/error/AuthenticationError.java
[AuthenticationErrorException]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/error/AuthenticationErrorException.java
[AuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticationRequirements.java
[AuthenticationUsageTrack]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/AuthenticationUsageTrack.java
[CommonUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/error/CommonUnrecoverableError.java
[GenericSignMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/GenericSignMessage.java
[GenericUserMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/GenericUserMessage.java
[LocalizedMessage]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/LocalizedMessage.java
[MessageMimeType]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/message/MessageMimeType.java
[OidcErrorMapping]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/error/OidcErrorMapping.java
[OriginalRequester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/OriginalRequester.java
[PostAuthenticationProcessor]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/PostAuthenticationProcessor.java
[RedirectAuthenticationRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/RedirectAuthenticationRepository.java
[RedirectAuthenticatorRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/RedirectAuthenticatorRepository.java
[RedirectFlowRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/RedirectFlowRepository.java
[RedirectForAuthenticationToken]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/RedirectForAuthenticationToken.java
[SamlAuthenticationRequirements]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/authentication/SamlAuthenticationRequirements.java
[SamlErrorStatus]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/error/SamlErrorStatus.java
[SessionBasedRedirectAuthenticationRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/redirect/SessionBasedRedirectAuthenticationRepository.java
[SsoDenialReason]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/sso/SsoDenialReason.java
[SsoPolicy]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/sso/SsoPolicy.java
[SsoVoter]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/sso/SsoVoter.java
[UnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/error/UnrecoverableError.java
[UserAuthentication]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/UserAuthentication.java
[UserAuthenticationInputToken]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/UserAuthenticationInputToken.java
[UserAuthenticationProvider]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/provider/UserAuthenticationProvider.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
