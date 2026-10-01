![Logo](images/sweden-connect.png)

# Auditing

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

The server records who asked for what, which user authenticated, and what was released to whom, as audit events. It
does so with [spring-audit-support][spring-audit-support]: the server publishes ordinary Spring application events,
transformers turn them into structured audit events, and the repositories that spring-audit-support sets up from the
`audit.*` properties store them.

This page documents the audit events of the server, how one authentication flow is followed across requests and
server instances, and how to change what an event holds. How spring-audit-support works, and how its repositories are
configured, is described in its own documentation.

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

- [Setting up auditing](#setting-up-auditing)
- [The common structure](#common-structure)
    - [The requester](#the-requester)
    - [The principal](#the-principal)
- [Following a flow: the correlation ID](#correlation-id)
- [Authentication events](#authentication-events)
    - [Authentication Request Received](#authn_request_received)
    - [Authentication Request Accepted](#authn_request_accepted)
    - [User Authenticated](#authn_user_authenticated)
    - [Authorization Response](#authn_authorization_response)
    - [Success Response](#authn_success_response)
    - [UserInfo Delivered](#authn_userinfo_delivered)
    - [Error Response](#authn_error_response)
    - [Unrecoverable Error](#authn_unrecoverable_error)
- [Operational events](#operational-events)
    - [Credential Test Error](#authn_credential_test_error)
    - [Credential Reload Success](#authn_credential_reload_success)
    - [Credential Reload Error](#authn_credential_reload_error)
    - [Trust mark alerts](#trust-mark-alerts)
- [Changing what an event holds](#replacing-a-transformer)

<a name="setting-up-auditing"></a>
## Setting up auditing

The starters include spring-audit-support and its auto-configuration, so the server produces audit events without any
code. Two things are left to the application:

- **The application name.** spring-audit-support puts the name of the application in every audit event and refuses to
  start without one. Set `spring.application.name`, see
  [The application name is required][audit-application-name].

- **Where the events go.** Configure one or more repositories under `audit.repository`. Without any, the events are
  kept in a bounded in-memory repository. See [Configuration][audit-configuration] and
  [Repositories][audit-repositories].

```yaml
spring:
  application:
    name: my-idp

audit:
  repository:
    file:
      log-file: /var/log/idp/audit.log
```

The server has no audit settings of its own.

> **Personal data.** The audit events hold the attributes of the users, including identity numbers. Protect the audit
> repositories accordingly, and use `audit.repository.exclude-events` or a
> [replaced transformer](#replacing-a-transformer) if an event holds more than the deployment may keep.

Without Spring Boot, the [`AuthnServerConfigurer`][AuthnServerConfigurer] publishes the events to the application
context of the `HttpSecurity` object, or to the publisher given with `eventPublisher(...)`. The transformers listed
under [Changing what an event holds](#replacing-a-transformer) are then registered with spring-audit-support's
`AuditApplicationListener` by the application.

<a name="common-structure"></a>
## The common structure

Every event has the common structure of spring-audit-support, see [The audit event][audit-event]: `type`,
`timestamp`, `application`, `correlation_id`, `trace_id`, `principal` and `data`. The server does not assign a trace
ID.

Every [authentication event](#authentication-events) has, as the first object of its `data`, the `requester`
described below. Most also have an object with the protocol-specific part of the event, holding what is needed to match
the entry to the SAML or OpenID Connect messages. Its members depend on the protocol, so the tables of those objects
are given per protocol.

<a name="the-requester"></a>
### The requester

**Audit data:** `requester`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `protocol` | `saml` or `oidc`. Absent when the protocol is not known, which only happens for an unrecoverable error on a path that serves both protocols, such as a resume path without an authentication in progress. | String |
| `id` | The SAML entityID of the Service Provider or the OpenID Connect `client_id`. Absent if the request names no requester. | String |
| `organization_number` | The organisation number of the requester exactly as the client registry holds it, with no conversion. A SAML Service Provider has it in whatever form its metadata gives, and an OpenID Connect client as a GLUE URI, see [The client registry](client-registry.html). Absent if the requester is not known or has none. | String |
| `verified` | Whether the server has established that the request comes from this requester. See below. | Boolean |

Until the requester is verified, `id` is only what the request claims. The requester is verified:

- for a SAML request, once the Service Provider is known, the assertion consumer service has been checked against its
  metadata, and the signature of the request has been checked,
- for an OpenID Connect authentication request, once the client is known and the `redirect_uri` is one it has
  registered, and the request object, if any, has been checked,
- at the token endpoint, once the client has been authenticated,
- at the UserInfo endpoint, once the access token has been found and its client is still known.

The [Authentication Request Received](#authn_request_received) event is always written before any check, so its
requester is never verified.

<a name="the-principal"></a>
### The principal

The principal of an authentication event is always the requester: the `id` above. When the request names no
requester, such as a SAML request without an `Issuer` that could be read, the principal is `unknown`.

The operational events have spring-audit-support's system principal, `system`.

<a name="correlation-id"></a>
## Following a flow: the correlation ID

All events of one authentication flow have the same `correlation_id`. The server generates it when an authentication
request arrives, for both protocols. The ID of the SAML `AuthnRequest` is not used; it is found in the
`authn_request` object.

A flow usually spans several requests: the authentication request, the pages of an authentication module, the return
to the resume path, and for OpenID Connect the client's calls to the token and UserInfo endpoints. The correlation ID
follows the flow like this:

| Request | Where the correlation ID comes from |
| :--- | :--- |
| Authentication request | Generated. A new request always starts a new flow, also when single sign-on is used. |
| The pages of an authentication module | The authentication in progress, kept in the session, for a request on the module's authentication path that carries the `authnId` parameter. |
| The resume path | The authentication in progress, kept in the session. |
| The token endpoint | The authorization code, which is bound to the flow. |
| The UserInfo endpoint | The access token, which is bound to the flow. |

Since the correlation ID is kept with the data of the flow, the session, the authorization codes and the access
tokens, it is the same whichever server instance handles a request, also when that data is kept in Redis, see
[Running several nodes](configuration.html#running-several-nodes).

A request that cannot be tied to a flow gets a correlation ID of its own, for example a token request with an unknown
code, or a request on the resume path without an authentication in progress.

The correlation ID is kept by spring-audit-support's `CorrelationIDHolder` while the request is processed, and is
cleared when the request ends, whatever the outcome. See [Correlation ID and Trace ID][audit-tracing].

> **Events from authentication modules.** An event that an authentication module publishes while the flow is in
> progress, from its provider or from its pages on the authentication path, is audited under the correlation ID of the
> flow without the module doing anything. spring-audit-support picks the ID up when the event is transformed.

<a name="authentication-events"></a>
## Authentication events

The events are given in the order they occur in a flow. A SAML flow produces
[Authentication Request Received](#authn_request_received), [Authentication Request Accepted](#authn_request_accepted),
[User Authenticated](#authn_user_authenticated) and [Success Response](#authn_success_response). An OpenID Connect
flow produces the same events, with an [Authorization Response](#authn_authorization_response) after the user
authenticated, the [Success Response](#authn_success_response) when the client redeems the code, and
[UserInfo Delivered](#authn_userinfo_delivered) when the client calls the UserInfo endpoint.

An error ends the flow with an [Error Response](#authn_error_response) or an
[Unrecoverable Error](#authn_unrecoverable_error).

<a name="authn_request_received"></a>
### Authentication Request Received

**Type:** `authn_request_received`

**Description:** An authentication request has arrived. No check has been made yet, so the requester is not verified.
For SAML, the event is written once the message has been decoded; a message that cannot be decoded only gives an
[Unrecoverable Error](#authn_unrecoverable_error). For OpenID Connect, the request object of a request that has one
has not yet been read.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `authn_request`, SAML

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the `AuthnRequest`. | String |
| `issuer` | The `Issuer` of the request. Absent if there is none. | String |
| `destination` | The `Destination` of the request. Absent if there is none. | String |
| `binding` | The binding the request was received with, the URI of the redirect or the POST binding. | String |
| `assertion_consumer_service_url` | The `AssertionConsumerServiceURL` of the request. Absent if the request gives none. | String |
| `authn_context_class_refs` | The requested authentication contexts. Absent if none were requested. | List of strings |
| `force_authn` | The `ForceAuthn` attribute. | Boolean |
| `is_passive` | The `IsPassive` attribute. | Boolean |
| `relay_state` | The `RelayState`. Absent if there is none. | String |
| `signed` | Whether the request was signed, with an XML signature or, for the redirect binding, in the query string. | Boolean |
| `holder_of_key` | Whether the request was received on a Holder-of-key endpoint. | Boolean |

**Audit data:** `authn_request`, OpenID Connect

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `client_id` | The `client_id` parameter. | String |
| `redirect_uri` | The `redirect_uri` parameter. | String |
| `response_type` | The `response_type` parameter. | String |
| `response_mode` | The `response_mode` parameter. | String |
| `scope` | The requested scopes. | List of strings |
| `acr_values` | The requested authentication contexts. | List of strings |
| `prompt` | The `prompt` values. | List of strings |
| `state` | The `state` parameter. | String |
| `code_challenge_method` | The PKCE code challenge method. | String |
| `request_object` | Whether a request object was given, with `request` or `request_uri`. | Boolean |

Every member except `request_object` is absent when the request does not have it.

<a name="authn_request_accepted"></a>
### Authentication Request Accepted

**Type:** `authn_request_accepted`

**Description:** The request has passed all checks, the requester is verified, and the user authentication starts.
Any error from here on is answered to the requester.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `authn_request`, with the members of
[Authentication Request Received](#authn_request_received), with these differences:

- SAML: `assertion_consumer_service_url` is the assertion consumer service that the response is sent to.
- OpenID Connect: the values include those of the request object, and `response_mode` is the response mode that is
  used, `query` or `form_post`.

<a name="authn_user_authenticated"></a>
### User Authenticated

**Type:** `authn_user_authenticated`

**Description:** The user has been authenticated, or an earlier authentication from the session was reused for single
sign-on. The event holds every attribute the authentication module delivered, whether or not it is released to the
requester. Which attributes were released is found in the [Success Response](#authn_success_response) and
[UserInfo Delivered](#authn_userinfo_delivered) events.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `authn_request`, as in [Authentication Request Accepted](#authn_request_accepted).

**Audit data:** `user_authentication`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `authn_instant` | When the user authenticated. For single sign-on, the instant of the original authentication. | Instant |
| `acr` | The authentication context under which the user was authenticated, the SAML `AuthnContextClassRef` and the OpenID Connect `acr`. | String |
| `authenticating_authority` | The service that authenticated the user, when the server proxies the authentication. Absent otherwise. | String |
| `client_ip_address` | The IP address of the client the user authenticated from. | String |
| `sign_message_displayed` | Whether a sign message was displayed for the user. | Boolean |
| `allowed_to_reuse` | Whether the authentication may be reused for single sign-on. | Boolean |
| `sso` | Whether an earlier authentication was reused for single sign-on. | Boolean |
| `sso_information.original_protocol` | The protocol of the request that the user originally authenticated for, `saml` or `oidc`. Present only when `sso` is `true`. | String |
| `sso_information.original_requester` | The requester that the user originally authenticated for. Present only when `sso` is `true`. | String |
| `sso_information.original_request_id` | The ID of the SAML `AuthnRequest` that the user originally authenticated for. Absent when `sso` is `false`, and when the original request was an OpenID Connect request. | String |

**Audit data:** `attributes`

A list of the attributes that the authentication module delivered, by their protocol-neutral names, such as
`attribute.personal-identity-number`, see [Attributes](attributes.html). Each element has:

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `name` | The name of the attribute. | String |
| `values` | The values of the attribute, as strings. | List of strings |

<a name="authn_authorization_response"></a>
### Authorization Response

**Type:** `authn_authorization_response`

**Description:** OpenID Connect only. The authorization code has been issued, and the authorization response holding
it is sent to the client. The code itself is not recorded.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `authorization_response`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `redirect_uri` | Where the response is sent. | String |
| `response_mode` | The response mode, `query` or `form_post`. | String |
| `state` | The `state` of the request. Absent if there is none. | String |

<a name="authn_success_response"></a>
### Success Response

**Type:** `authn_success_response`

**Description:** For SAML, a `Response` holding the assertion has been built and is sent to the Service Provider. For
OpenID Connect, the client has redeemed the authorization code at the token endpoint and the ID token has been issued.
There is no separate event for the tokens. The event holds the attributes that were released, by their protocol names.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `response`, SAML

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id` | The ID of the `Response`. | String |
| `in_response_to` | The ID of the `AuthnRequest`. | String |
| `destination` | The assertion consumer service the response is posted to. | String |
| `issued_at` | The `IssueInstant` of the response. | Instant |
| `signed` | Whether the response is signed. | Boolean |
| `relay_state` | The `RelayState`. Absent if there is none. | String |
| `assertion.id` | The ID of the assertion. | String |
| `assertion.signed` | Whether the assertion is signed. | Boolean |
| `assertion.encrypted` | Whether the assertion is encrypted in the response. | Boolean |
| `assertion.subject_id` | The `NameID` of the subject. | String |
| `assertion.subject_id_format` | The format of the `NameID`. | String |
| `assertion.authn_instant` | The `AuthnInstant` of the authentication statement. | Instant |
| `assertion.authn_context_class_ref` | The `AuthnContextClassRef` of the authentication statement. | String |
| `assertion.authenticating_authorities` | The `AuthenticatingAuthority` elements. Absent if there are none. | List of strings |

**Audit data:** `response`, OpenID Connect

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `sub` | The `sub` of the user for the client. | String |
| `acr` | The `acr` of the ID token. | String |
| `auth_time` | The `auth_time` of the ID token. | Instant |
| `scope` | The scopes that the tokens were issued for. | List of strings |
| `redirect_uri` | The redirect URI of the authentication request. | String |
| `id_token_signed` | Whether the ID token is signed. Always `true`. | Boolean |
| `id_token_encrypted` | Whether the ID token is encrypted. | Boolean |

**Audit data:** `released_attributes`

A list of the released attributes, by their protocol names: the SAML attribute names of the assertion, or the claims of
the ID token. Each element has `name` and `values`, as the `attributes` of
[User Authenticated](#authn_user_authenticated). The list is empty if nothing was released.

<a name="authn_userinfo_delivered"></a>
### UserInfo Delivered

**Type:** `authn_userinfo_delivered`

**Description:** OpenID Connect only. A UserInfo response holding the claims has been produced and is sent to the
client.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `response`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `sub` | The `sub` of the user for the client. | String |
| `signed` | Whether the response is a signed JWT. | Boolean |
| `encrypted` | Whether the response is encrypted. | Boolean |

**Audit data:** `released_attributes`, the claims of the response other than `sub`, as in
[Success Response](#authn_success_response).

<a name="authn_error_response"></a>
### Error Response

**Type:** `authn_error_response`

**Description:** An error is sent to the requester: a SAML error response, an OpenID Connect authorization error sent
to the redirect URI, an error from the token endpoint or an error from the UserInfo endpoint. This includes a user who
cancels the authentication. The event is written just before the response is sent.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `stage`, a string telling where the error came from:

| Value | Description |
| :--- | :--- |
| `authn_request` | The processing of the authentication request, before the user authentication started. |
| `user_authentication` | The user authentication, including the return from the pages of an authentication module. |
| `response` | The completion of the response after the user was authenticated, such as the release of attributes. |
| `token` | The token endpoint. |
| `userinfo` | The UserInfo endpoint. |

**Audit data:** `error`, the `error` object of spring-audit-support, with these members:

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `code` | The error code of the protocol. For SAML the subordinate status code, such as `http://id.elegnamnden.se/status/1.0/cancel`. For OpenID Connect the error code, such as `access_denied` or `invalid_grant`. A UserInfo request without an access token gets no error code (RFC 6750, Section 3.1), and is recorded as `missing_token`. | String |
| `message` | The description of the error. Absent if there is none. | String |

**Audit data:** `response`, SAML

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `id`, `in_response_to`, `destination`, `issued_at`, `signed`, `relay_state` | As in [Success Response](#authn_success_response). | |
| `status_code` | The status code. | String |
| `subordinate_status_code` | The subordinate status code. | String |
| `status_message` | The status message. Absent if there is none. | String |

**Audit data:** `response`, OpenID Connect authorization error

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `redirect_uri` | Where the error is sent. | String |
| `response_mode` | The response mode, `query` or `form_post`. | String |
| `state` | The `state` of the request. Absent if there is none. | String |

**Audit data:** `response`, OpenID Connect token and UserInfo error

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `http_status` | The HTTP status of the response. | Integer |

<a name="authn_unrecoverable_error"></a>
### Unrecoverable Error

**Type:** `authn_unrecoverable_error`

**Description:** An error occurred that cannot be answered to the requester, because it is not known who the requester
is or where to send a response. The error is shown to the user instead. Examples are a SAML message that cannot be
decoded, an unknown Service Provider or client, a `redirect_uri` that the client has not registered, and a return to
the resume path without an authentication in progress. The principal and `verified` follow
[The principal](#the-principal), so an unknown requester is recorded as the requester the request names.

**Audit data:** `requester`, see [The requester](#the-requester).

**Audit data:** `stage`, as in [Error Response](#authn_error_response). Absent when the stage is not known, such as
for an error on the pages of an authentication module that do not belong to an authentication in progress.

**Audit data:** `error`

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `code` | The message code of the error, such as `authn-server.error.unrecoverable.session`. The errors are listed in [`CommonUnrecoverableError`][CommonUnrecoverableError], [`SamlUnrecoverableError`][SamlUnrecoverableError] and [`OidcUnrecoverableError`][OidcUnrecoverableError]. | String |
| `message` | A description of what went wrong. | String |

<a name="operational-events"></a>
## Operational events

These events are not tied to an authentication flow. Their principal is the system principal, `system`.

<a name="authn_credential_test_error"></a>
### Credential Test Error

**Type:** `authn_credential_test_error`

**Description:** A monitored credential failed its test. Written for credentials-support's
`FailedCredentialTestEvent`. What credential monitoring is, and when the events occur, is described under
[Monitoring][credentials-monitoring] in the credentials-support documentation.

**Audit data:**

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `credential_name` | The name of the credential. | String |
| `error.message` | The error reported by the test. | String |
| `error.exception_class` | The class of the exception from the test. Absent if there was none. | String |

<a name="authn_credential_reload_success"></a>
### Credential Reload Success

**Type:** `authn_credential_reload_success`

**Description:** A monitored credential that failed its test has been reloaded. Written for credentials-support's
`SuccessfulCredentialReloadEvent`.

**Audit data:**

| Parameter | Description | Type |
| :--- | :--- | :--- |
| `credential_name` | The name of the credential. | String |

<a name="authn_credential_reload_error"></a>
### Credential Reload Error

**Type:** `authn_credential_reload_error`

**Description:** A monitored credential that failed its test could not be reloaded, and cannot be used. Written for
credentials-support's `FailedCredentialReloadEvent`.

**Audit data:** as [Credential Test Error](#authn_credential_test_error), with the error of the reload.

<a name="trust-mark-alerts"></a>
### Trust mark alerts

Two conditions of OpenID Federation are published as spring-audit-support's `SystemAlertEvent`, and audited as
[System Alert][audit-system-alert] events:

- The OpenID Provider fails to fetch or renew one of its own trust marks, see
  [The trust marks of the OpenID Provider](openid-provider.html#the-trust-marks-of-the-openid-provider).
- A trust mark of a client is reported withdrawn, or anything but active, at a trust mark status check, see
  [Trust mark status checks](client-registry.html#trust-mark-status-checks).

The trust marks of the OpenID Provider are wired to publish the alerts. A
[`TrustMarkStatusChecker`][TrustMarkStatusChecker] is created by the application, which gives it the application
context with `setEventPublisher(...)`.

<a name="replacing-a-transformer"></a>
## Changing what an event holds

Each event type has a transformer, registered as a bean by the auto-configuration:

| Type | Transformer |
| :--- | :--- |
| `authn_request_received` | `AuthnRequestReceivedEventTransformer` |
| `authn_request_accepted` | `AuthnRequestAcceptedEventTransformer` |
| `authn_user_authenticated` | `AuthnUserAuthenticatedEventTransformer` |
| `authn_authorization_response` | `AuthnAuthorizationResponseEventTransformer` |
| `authn_success_response` | `AuthnSuccessResponseEventTransformer` |
| `authn_userinfo_delivered` | `AuthnUserInfoDeliveredEventTransformer` |
| `authn_error_response` | `AuthnErrorResponseEventTransformer` |
| `authn_unrecoverable_error` | `AuthnUnrecoverableErrorEventTransformer` |
| `authn_credential_test_error` | `CredentialTestErrorEventTransformer` |
| `authn_credential_reload_success` | `CredentialReloadSuccessEventTransformer` |
| `authn_credential_reload_error` | `CredentialReloadErrorEventTransformer` |

They are found in the
[`se.swedenconnect.spring.authnserver.audit.transform`][transform-package] package. A transformer is only created if the
application has not declared a bean of the same type, so an application replaces one by declaring its own bean of that
type. The usual way is to extend the transformer and override `getDataFields`, which returns the data of the event in
the order it is written. This one leaves the attributes out of the [User Authenticated](#authn_user_authenticated)
event:

```java
@Bean
AuthnUserAuthenticatedEventTransformer authnUserAuthenticatedEventTransformer() {
  return new AuthnUserAuthenticatedEventTransformer() {
    @Override
    protected List<AuditValue<? extends Serializable>> getDataFields(final AuthnUserAuthenticatedEvent event) {
      final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
      fields.removeIf(f -> ATTRIBUTES.equals(f.getName()));
      return fields;
    }
  };
}
```

The events themselves, in the [`se.swedenconnect.spring.authnserver.audit.events`][events-package] package, carry
the requester, the protocol-specific part as a
[`ProtocolAuditData`][ProtocolAuditData], and what else the event is about, so a replaced transformer can write any of
it. Document a changed event in the same way as on this page, see
[Documenting Audit Events][audit-documentation-guide].

To leave an event type out of the audit log altogether, use `audit.repository.exclude-events`, see
[Configuration][audit-configuration].

[spring-audit-support]: https://docs.swedenconnect.se/spring-audit-support
[audit-event]: https://docs.swedenconnect.se/spring-audit-support/usage.html#the-audit-event
[audit-tracing]: https://docs.swedenconnect.se/spring-audit-support/tracing.html
[audit-configuration]: https://docs.swedenconnect.se/spring-audit-support/configuration.html
[audit-application-name]: https://docs.swedenconnect.se/spring-audit-support/configuration.html#application-name-is-required
[audit-repositories]: https://docs.swedenconnect.se/spring-audit-support/repositories.html
[audit-system-alert]: https://docs.swedenconnect.se/spring-audit-support/audit-events.html#system_alert
[audit-documentation-guide]: https://docs.swedenconnect.se/spring-audit-support/documentation-guide.html
[credentials-monitoring]: https://docs.swedenconnect.se/credentials-support/#monitoring
[AuthnServerConfigurer]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/config/AuthnServerConfigurer.java
[CommonUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/error/CommonUnrecoverableError.java
[SamlUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/error/SamlUnrecoverableError.java
[OidcUnrecoverableError]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/error/OidcUnrecoverableError.java
[TrustMarkStatusChecker]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/TrustMarkStatusChecker.java
[ProtocolAuditData]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/audit/ProtocolAuditData.java
[transform-package]: https://github.com/swedenconnect/spring-authentication-server/tree/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/audit/transform
[events-package]: https://github.com/swedenconnect/spring-authentication-server/tree/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/audit/events

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
