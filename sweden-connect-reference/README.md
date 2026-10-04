![Logo](../docs/images/sweden-connect.png)

# Sweden Connect Reference Authentication Server

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

The Sweden Connect reference authentication server is a SAML Identity Provider and an OpenID Provider in one service,
built on the [Spring Authentication Server](https://docs.swedenconnect.se/spring-authentication-server/). It is the
successor of the [Sweden Connect reference IdP](https://github.com/swedenconnect/swedish-eid-idp).

The user authentication is simulated: the user picks a person from a list instead of authenticating. Everything around
the authentication is real. The service processes SAML authentication requests according to the
[Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/) and OpenID Connect requests according to
the [Swedish OpenID Connect specifications](https://www.oidc.se/specifications/), and issues assertions and tokens just
like a production service does. That makes it useful for anyone who tests a Service Provider or a Relying Party
against Sweden Connect.

The simulated authentication is implemented once, as an authentication module, and serves both protocols. The service
also shows how a real deployment of the Spring Authentication Server is put together: a module with pages of its own,
the configuration of both protocols, the security of the pages, the response pages, the error pages and the Actuator.

- [Building](#building)
- [Running the service](#running-the-service)
- [Settings that a deployment must add](#settings-that-a-deployment-must-add)
- [Optional settings](#optional-settings)
- [The simulated users](#the-simulated-users)
- [Settings of the simulated authentication](#settings-of-the-simulated-authentication)

<a name="building"></a>
## Building

The service is a module of the Spring Authentication Server build, and is built and tested by `mvn clean verify` from
the root of the repository. It is never published to Maven Central.

The container image is built with [Jib](https://github.com/GoogleContainerTools/jib), from the `amazoncorretto:25.0.1`
base image. Neither build runs as part of the normal build. Build and install the project first, with
`mvn clean install` from the root, then, from the `sweden-connect-reference` directory:

```bash
# Builds local/sweden-connect-reference-authn-server:<version> into the local Docker daemon
mvn jib:dockerBuild@local

# Builds the image for linux/amd64 and linux/arm64, and pushes it to
# ghcr.io/swedenconnect/sweden-connect-reference-authn-server:<version>
mvn jib:build
```

The image exposes port 8443 for the service and port 8444 for the Actuator.

<a name="running-the-service"></a>
## Running the service

The [default configuration](src/main/resources/application.yml) holds defaults only. It ships no base URL, entity ID,
issuer, metadata, keys or key stores, so the service does not start until the deployment supplies them. When something
is missing, startup fails with a list of the settings to add. The OpenID Connect clients are not on that list. The
OpenID Provider takes its clients from `authn-server.oidc.clients`, from an OpenID Federation, or from both, see
[OpenID Connect clients](#openid-connect-clients); with neither, the server itself stops startup with a message that
names what to add:

```
The Sweden Connect reference authentication server has no defaults for these settings, and the deployment has not
supplied them:

    - authn-server.base-url: the base URL of the server, protocol, host, port and context path, ...
    - spring.ssl.bundle.(jks|pem).tls.keystore: the TLS key store of the server, given as a Spring Boot SSL bundle
    ...
```

A deployment supplies the settings the way Spring Boot reads configuration: in an `application.yml` of its own, given
with `spring.config.additional-location`, in a profile, or as environment variables. For example, with the
configuration and keys in `/opt/reference`:

```bash
docker run -d --name reference -p 8443:8443 -p 8444:8444 \
  -v /opt/reference:/opt/reference \
  -e SPRING_CONFIG_ADDITIONAL_LOCATION=/opt/reference/ \
  local/sweden-connect-reference-authn-server:1.0.0-SNAPSHOT
```

The tests of the module start the service with a complete configuration,
[application-complete.yml](src/test/resources/application-complete.yml), which is a working example of everything a
deployment adds. It is part of the test resources only, and never ends up in the service or the image.

<a name="settings-that-a-deployment-must-add"></a>
## Settings that a deployment must add

These are the settings marked `DEPLOYMENT MUST ADD` in the default configuration. The settings of a protocol are only
required when the protocol is enabled; both are enabled by default.

| Setting | Description |
| :--- | :--- |
| `authn-server.base-url` | The base URL of the server: protocol, host, port and context path, for example `https://idp.example.com`. Every URL of the server is built from it, see [URL layout](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#url-layout). |
| `spring.ssl.bundle.*.tls` | The TLS key store of the server, as a Spring Boot [SSL bundle](https://docs.spring.io/spring-boot/reference/features/ssl.html) named `tls`, the bundle that `server.ssl.bundle` names. A JKS or PKCS#12 key store under `spring.ssl.bundle.jks.tls`, or PEM files under `spring.ssl.bundle.pem.tls`. |
| `authn-server.saml.entity-id` | The SAML entity ID of the Identity Provider. |
| `authn-server.saml.credentials.*` | The SAML signing key (`sign`) and encryption key (`encrypt`), or one key for both (`default-credential`). A metadata signing key (`metadata-sign`) is recommended. See [Credentials](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#credentials). |
| `authn-server.saml.metadata-providers[]` | The sources of the SAML Service Provider metadata, for example the metadata of the Sweden Connect federation. See [Service Provider metadata](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#sp-metadata). |
| `authn-server.oidc.issuer` | The issuer identifier of the OpenID Provider. It is also its OpenID Federation entity identifier. It must be the base URL, or begin with it. |
| `authn-server.oidc.keys.signing[]` | The signing keys of the OpenID Provider. See [Keys](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#oidc-keys). |
| `authn-server.oidc.clients[]` | The OpenID Connect clients, in JSON files or inline, unless every client is resolved through an OpenID Federation, see [OpenID Connect clients](#openid-connect-clients). |

The keys are configured through [credentials-support](https://docs.swedenconnect.se/credentials-support/), preferably as
credential bundles that the settings refer to. A complete example:

```yaml
spring:
  ssl:
    bundle:
      jks:
        tls:
          key:
            alias: tls
            password: ${TLS_KEY_PASSWORD}
          keystore:
            location: file:/opt/reference/tls.p12
            password: ${TLS_KEYSTORE_PASSWORD}
            type: PKCS12

credential:
  bundles:
    keystore:
      reference-keys:
        location: file:/opt/reference/keys.p12
        password: ${KEYSTORE_PASSWORD}
        type: PKCS12
    jks:
      saml-sign:
        store-reference: reference-keys
        key:
          alias: saml-sign
          key-password: ${KEYSTORE_PASSWORD}
      saml-encrypt:
        store-reference: reference-keys
        key:
          alias: saml-encrypt
          key-password: ${KEYSTORE_PASSWORD}
      oidc-sign:
        store-reference: reference-keys
        key:
          alias: oidc-sign
          key-password: ${KEYSTORE_PASSWORD}

authn-server:
  base-url: https://idp.example.com
  saml:
    entity-id: https://idp.example.com/saml
    credentials:
      sign:
        bundle: saml-sign
      encrypt:
        bundle: saml-encrypt
      metadata-sign:
        bundle: saml-sign
    metadata-providers:
      - location: https://md.swedenconnect.se/role/sp.xml
        validation-certificate: file:/opt/reference/metadata-signing.crt
        backup-location: /var/reference/sp-metadata-backup.xml
  oidc:
    issuer: https://idp.example.com
    keys:
      signing:
        - credential:
            bundle: oidc-sign
    clients:
      - location: file:/opt/reference/oidc-clients.json
```

<a name="openid-connect-clients"></a>
### OpenID Connect clients

The OpenID Connect clients are given with `authn-server.oidc.clients`, see
[Clients](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#oidc-clients). Each entry is
either the `location` of a JSON file, holding one client object or an array of them, or one client given inline with
`client-id`, `metadata` as a JSON string, and optionally `client-secret` and `trust-mark-types`. A client object in a
file has `client_id`, `metadata` as a nested object, and optionally `client_secret` and `trust_mark_types`. The
`metadata` is exactly the client's registered metadata, and never holds the client secret:

```json
[
  {
    "client_id": "https://rp.example.com",
    "metadata": {
      "client_name#sv": "Exempeltjänsten",
      "client_name#en": "The Example Service",
      "logo_uri": "https://rp.example.com/logo.svg",
      "redirect_uris": [ "https://rp.example.com/callback" ],
      "response_types": [ "code" ],
      "grant_types": [ "authorization_code" ],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks_uri": "https://rp.example.com/jwks"
    }
  }
]
```

The same client inline:

```yaml
authn-server:
  oidc:
    clients:
      - client-id: https://rp.example.com
        metadata: >
          {"client_name#sv": "Exempeltjänsten", "client_name#en": "The Example Service",
           "logo_uri": "https://rp.example.com/logo.svg", "redirect_uris": ["https://rp.example.com/callback"],
           "token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://rp.example.com/jwks"}
```

The trust mark types of a client are assigned by the operator and are not verified. They give a locally configured
client the same treatment as a federation client that holds a trust mark of that type, for example under
`authn-server.oidc.requester-acceptance.required-marks`.

The clients are read at startup only, so a changed file takes effect when the service is restarted. They become the
`properties` source of the [client registry](https://docs.swedenconnect.se/spring-authentication-server/client-registry.html#openid-connect-three-backends).

A deployment that joins an OpenID Federation also, or instead, accepts clients resolved through the federation, with
`authn-server.oidc.federation.clients` and the trust anchor, see
[Clients from OpenID Federation](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#oidc-federation-clients).
The configured clients are asked first, so a configured client wins over what the federation says about the same
`client_id`.
The `client_name` and `logo_uri` of a client are shown on the pages, in the language of the page where the metadata
gives one. Only `private_key_jwt` is enabled at the token endpoint by default, see
[The token endpoint and tokens](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#oidc-token-endpoint)
for how to enable the others.

<a name="optional-settings"></a>
## Optional settings

Everything the Spring Authentication Server offers is configured as described in
[Configuration](https://docs.swedenconnect.se/spring-authentication-server/configuration.html). These are the
settings that a deployment of the reference is most likely to change.

**The subject identifier secret.** The SAML `NameID` and the OpenID Connect `sub` are computed with a secret. Setting
`authn-server.subject-identifier.secret` is strongly recommended, see
[Subject identifiers](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#subject-identifiers).

**Context path.** The service has no context path. A deployment may add one with `server.servlet.context-path`, for
example `/idp`. The context path is then part of the base URL, and so of the OpenID Connect issuer and of every
endpoint, and `authn-server.base-url` and `authn-server.oidc.issuer` must include it. The cookies of the pages follow
the context path.

```yaml
server:
  servlet:
    context-path: /idp
authn-server:
  base-url: https://example.com/idp
  oidc:
    issuer: https://example.com/idp
```

**Display names and description.** The descriptive information is given under `authn-server.entity-information` and
published by both protocols. The reference gives its display names per protocol, "Sweden Connect Reference IdP" in
the SAML metadata under `authn-server.saml.metadata.ui-info.display-names` and "Sweden Connect Reference OP" for the
OpenID Provider under `authn-server.oidc.entity-information.ui-info.display-names`, only because this service shows
both protocols side by side. A normal deployment gives one shared display name under
`authn-server.entity-information.ui-info.display-names`. The description, "Sweden Connect Reference Authentication
Service", is shared. See
[Entity information](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#entity-information).

**AJP.** The Tomcat AJP connector is off. A deployment behind a web server that speaks AJP turns it on:

| Setting | Description | Default value |
| :--- | :--- | :--- |
| `tomcat.ajp.enabled` | Whether the AJP connector is started. | `false` |
| `tomcat.ajp.port` | The port of the AJP connector. | `8009` |
| `tomcat.ajp.secret-required` | Whether the AJP secret is required. | `false` |
| `tomcat.ajp.secret` | The AJP secret. | - |

**Several instances and Redis.** The HTTP session, single sign-on and the stores of both protocols are kept in memory.
A deployment that runs several instances keeps them in Redis instead, by setting `authn-server.storage.type` to
`redis` and configuring the Redis connection under `spring.data.redis`. The Redis libraries are part of the service, so
no other change is needed. The Redis health check of the Actuator is off by default, and is turned on with
`management.health.redis.enabled`. See
[Running several nodes](https://docs.swedenconnect.se/spring-authentication-server/configuration.html#running-several-nodes).

```yaml
authn-server:
  storage:
    type: redis
spring:
  data:
    redis:
      host: redis.example.com
      port: 6379
      password: ${REDIS_PASSWORD}
management:
  health:
    redis:
      enabled: true
```

**Audit.** The audit events are kept in the in-memory repository of
[spring-audit-support](https://github.com/swedenconnect/spring-audit-support). Other repositories are added under
`audit.repository`: `file`, `jdbc`, `mongo`, `redis` and `syslog`. The JDBC, MongoDB and syslog repositories need
libraries that the service does not include; the file, in-memory and Redis repositories work as they are. See
[Auditing](https://docs.swedenconnect.se/spring-authentication-server/audit.html).

```yaml
audit:
  repository:
    file:
      log-file: /var/log/reference/audit.log
```

**Actuator.** The Actuator answers on port 8444 only, `management.server.port`. The `health`, `info` and `clients`
endpoints are exposed, and `clients` is read-only. Exposing more endpoints, or allowing the update operations of the
`clients` endpoint, is done with Spring Boot's settings, see
[Monitoring and managing the server](https://docs.swedenconnect.se/spring-authentication-server/management.html).

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health, info, clients, auditevents
  endpoint:
    clients:
      access: unrestricted
```

<a name="the-simulated-users"></a>
## The simulated users

The user picker shows the requester, by the name and logotype from its SAML metadata or OpenID Connect client
metadata, and a list of persons to authenticate as. The user picks a person and, when the requester accepts several
levels of assurance, one of them.

- **The fixed users.** The persons of the list are read from [users.yml](src/main/resources/users.yml). Each has a
  `personal-number`, a `given-name` and a `surname`, and may have a `display-name` and a `date-of-birth`. When they are
  not given, the display name is the given name followed by the surname, and the date of birth is taken from the
  personal identity number. To use other users, put a `users.yml` of the same form in a directory and set the
  environment variable `IDP_CONFIG_DIR` to that directory.

- **Users that the tester adds.** Under "Advanced", the tester enters a personal identity number and a name. The user
  is saved in a cookie of the tester's browser, and is offered in the list the next time. At most 40 users are kept;
  when more are added, the oldest is dropped.

- **The last selection.** The last selected person and level of assurance are remembered in a cookie and selected the
  next time.

- **A requested person.** When the requester asks for a specific personal identity number, in a SAML
  `PrincipalSelection` or as a requested value of the personal identity number claim in OpenID Connect, that person
  is selected and the selection is locked. This only applies when the person is in the list.

- **Signatures.** For a signature service, a SAML Service Provider with the signature service entity category, or an
  OpenID Connect client that asks for the `https://id.oidc.se/scope/sign` or `https://id.oidc.se/scope/signApproval`
  scope, the page asks the user to sign, and shows the sign message. Plain text, Markdown and, for SAML, HTML are
  turned into HTML that is safe to show; a sign message that cannot be shown fails the request.

- **User messages.** A user message from the requester is shown in the language of the page, when there is no sign
  message.

- **Simulated errors.** Under "Simulate Error", the tester sends an error back to the requester instead of
  authenticating: `AUTHN_FAILED`, `CANCEL`, `FRAUD`, `POSSIBLE_FRAUD`, `UNKNOWN_PRINCIPAL`, `NO_AUTHN_CONTEXT`,
  `NOT_AUTHORIZED` or `SIGN_MESSAGE_NOT_DISPLAYED`, with a message of the tester's choice. Each is turned into the
  SAML status or OpenID Connect error of its protocol, see
  [Errors](https://docs.swedenconnect.se/spring-authentication-server/authentication-module.html#errors).

The pages are in Swedish and English.

<a name="settings-of-the-simulated-authentication"></a>
## Settings of the simulated authentication

The settings of the reference itself are placed under `authn-server-reference`. The default configuration gives these
values, and a deployment rarely changes them.

| Setting | Description |
| :--- | :--- |
| `authn-server-reference.authn.provider-name` | The name of the authentication provider. |
| `authn-server-reference.authn.authn-path` | The path of the user picker, `/extauth`. |
| `authn-server-reference.authn.resume-path` | The path that the user is sent back to after the authentication, `/resume`. |
| `authn-server-reference.authn.supported-loas[]` | The levels of assurance that the service offers. |
| `authn-server-reference.authn.entity-categories[]` | The SAML entity categories that the service declares in its metadata. |
| `authn-server-reference.ui.languages[]` | The languages of the pages, each with a `tag` and the `text` of its button. |
| `authn-server-reference.users-location` | Where `users.yml` is read from, `${IDP_CONFIG_DIR:classpath:}`. |

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
