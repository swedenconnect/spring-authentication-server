![Logo](images/sweden-connect.png)

# Monitoring and managing the server

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

This page is for those who run a server built on the Spring Authentication Server. It describes what the server adds
to [Spring Boot Actuator](https://docs.spring.io/spring-boot/reference/actuator/index.html): an endpoint that shows
and updates the clients that the server knows, what the server adds to the `info` endpoint, its health indicators,
the state that the server keeps between restarts, and the audit events that tell when a client appears or
disappears.

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

- [Setting up the Actuator](#setting-up-the-actuator)
- [The clients endpoint](#the-clients-endpoint)
    - [Allowing the update operations](#allowing-the-update-operations)
- [The info endpoint](#the-info-endpoint)
- [The health endpoint](#the-health-endpoint)
    - [The WARNING status](#the-warning-status)
    - [SAML metadata](#saml-metadata-health)
    - [The trust marks of the OpenID Provider](#oidc-trust-marks-health)
    - [Federation services](#oidc-federation-health)
- [State that survives a restart](#state-that-survives-a-restart)
- [Clients added and removed](#clients-added-and-removed)

<a name="setting-up-the-actuator"></a>
## Setting up the Actuator

The Actuator support is active when Spring Boot Actuator is on the classpath. The starters do not bring it, so add it
to the application:

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

Without it the server works as before; only the endpoint, the info contributions and the health indicators are
missing.

Which endpoints are exposed, on which port, and who may call them is decided by the deployment, as for any Actuator
endpoint. See [Endpoints](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html) in the Spring Boot
documentation. For example:

```yaml
management:
  server:
    port: 8444
  endpoints:
    web:
      exposure:
        include: health, info, clients, auditevents
  endpoint:
    health:
      show-details: always
```

The examples on this page assume that the endpoints are found under `/actuator`.

<a name="the-clients-endpoint"></a>
## The clients endpoint

**Path:** `/actuator/clients`

The `clients` endpoint shows the clients that the [client registry](client-registry.html) holds, for both protocols,
and updates their data on request. The identity of a client is given as the query parameter `id`, since identities
are usually URLs.

| Operation | Description |
| :--- | :--- |
| `GET /actuator/clients` | Lists every client that the server holds now. |
| `GET /actuator/clients/saml?id=...` | Shows one SAML Service Provider. |
| `GET /actuator/clients/oidc?id=...` | Shows one OpenID Connect client. |
| `GET /actuator/clients/saml/metadata?id=...` | Gives the `EntityDescriptor` of a Service Provider as XML, exactly as held. |
| `GET /actuator/clients/oidc/metadata?id=...` | Gives the metadata of an OpenID Connect client as JSON, exactly as held, except that a client secret is left out. |
| `POST /actuator/clients/saml` | Updates the SAML metadata. No source is named; every metadata source that can be updated is downloaded or read again. |
| `POST /actuator/clients/oidc?id=...` | Drops an OpenID Federation client from the cache and resolves it again. |

An unknown protocol or an unknown client gives 404.

The list holds, for each client, its protocol, its identity, its organisation number as the registry holds it, where
it came from (the SAML metadata source, or the OpenID Connect backend: `configuration`, `repository` or `federation`),
and when its data expires. A client with no expiry, such as a configured OpenID Connect client, has none:

```json
{
  "clients" : [ {
    "protocol" : "saml",
    "id" : "https://sp.example.com",
    "organization-number" : "5566778899",
    "source" : "https://md.swedenconnect.se/role/sp.xml",
    "expires-at" : "2026-10-08T12:00:00Z"
  }, {
    "protocol" : "oidc",
    "id" : "https://rp.example.com",
    "organization-number" : "urn:glue:iso6523:0007:5566778899",
    "source" : "federation",
    "expires-at" : "2026-10-02T09:14:31Z"
  } ]
}
```

The list shows what the server holds now. For an OpenID Federation client that is the clients in the federation
cache, and for an MDQ source the Service Providers that have been asked for.

One client is shown with its marks, which are entity categories for SAML and trust mark types for OpenID Connect,
and the path of its metadata:

```json
{
  "protocol" : "oidc",
  "id" : "https://rp.example.com",
  "organization-number" : "urn:glue:iso6523:0007:5566778899",
  "marks" : [ "https://id.swedenconnect.se/contract/sc/eid-authorization-system" ],
  "source" : "federation",
  "expires-at" : "2026-10-02T09:14:31Z",
  "metadata" : "/actuator/clients/oidc/metadata?id=https%3A%2F%2Frp.example.com"
}
```

The answer of an update tells what happened in `outcome`, with a description in `message`:

| Outcome | Description |
| :--- | :--- |
| `updated` | The data was fetched again. |
| `removed` | The OpenID Federation resolver reports the client as not found. It is removed, see [Clients added and removed](#clients-added-and-removed). |
| `nothing-to-update` | The data does not come from a source that can be updated: a configured OpenID Connect client, a client in a repository, or SAML metadata that is read once from a resource. |
| `failed` | The update failed, and the answer has HTTP status 502. The data held before is kept. |

```json
{
  "protocol" : "oidc",
  "id" : "https://rp.example.com",
  "outcome" : "updated",
  "message" : "Resolved 'https://rp.example.com' again, valid until 2026-10-02T11:02:10Z"
}
```

A SAML metadata source is updated in the same way as when the scheduled download runs, so the Service Providers that
it adds or removes are reported as [added and removed](#clients-added-and-removed).

<a name="allowing-the-update-operations"></a>
### Allowing the update operations

The update operations change what the server holds and make calls to other services, so the default access of the
endpoint is read-only. Until the deployment grants more, a `POST` is refused. Grant it with:

```yaml
management:
  endpoint:
    clients:
      access: unrestricted
```

As for every Actuator write operation, the request is sent with the content type `application/json`:

```bash
curl -X POST -H 'Content-Type: application/json' \
  'https://idp.example.com:8444/actuator/clients/oidc?id=https%3A%2F%2Frp.example.com'
```

<a name="the-info-endpoint"></a>
## The info endpoint

**Path:** `/actuator/info`

**Reference:** [Info endpoint](https://docs.spring.io/spring-boot/api/rest/actuator/info.html)

The server adds two entries.

**`authn-server`** sums up how the server is set up: the enabled protocols, the SAML entityID, the OpenID Connect
issuer, and the authentication providers with the `acr` values, the authentication context URIs, that each supports.
With OpenID Federation enabled, it also gives the authority hints and the OpenID Provider's own trust marks with their
expiry. The issuer is given once, since it is also the federation entity identifier.

```json
"authn-server" : {
  "protocols" : [ "saml", "oidc" ],
  "saml" : {
    "entity-id" : "https://idp.example.com/auth"
  },
  "oidc" : {
    "issuer" : "https://idp.example.com/auth",
    "federation" : {
      "authority-hints" : [ "https://fed.swedenconnect.se/intermediate" ],
      "trust-marks" : [ {
        "type" : "https://id.swedenconnect.se/loa/loa3",
        "published" : true,
        "expires-at" : "2026-12-31T00:00:00Z"
      } ]
    }
  },
  "authentication-providers" : [ {
    "name" : "bankid",
    "acr-values" : [ "http://id.elegnamnden.se/loa/1.0/loa3" ]
  } ]
}
```

**`client-registry`** lists the sources of the client registry: each SAML metadata source and each OpenID Connect
backend, with the number of clients it holds and the time of its last update. For a SAML source the last update is
when its metadata last changed; for the federation backend it is when this server instance last resolved a client.
A source that cannot tell how many clients it has, such as an MDQ source, gives no number.

```json
"client-registry" : {
  "sources" : [ {
    "protocol" : "saml",
    "backend" : "saml-metadata",
    "name" : "https://md.swedenconnect.se/role/sp.xml",
    "clients" : 412,
    "last-update" : "2026-10-01T06:00:12Z"
  }, {
    "protocol" : "oidc",
    "backend" : "federation",
    "name" : "federation",
    "clients" : 37,
    "last-update" : "2026-10-01T09:14:31Z"
  } ]
}
```

<a name="the-health-endpoint"></a>
## The health endpoint

**Path:** `/actuator/health`

**Reference:** [Health endpoint](https://docs.spring.io/spring-boot/api/rest/actuator/health.html)

The server adds the health indicators below, each for an enabled protocol. Spring Boot's own indicators, such as the
one for Redis, and the indicator of credentials-support for monitored credentials, see
[Credential monitoring health endpoint](https://docs.swedenconnect.se/credentials-support/#credential-monitoring-health-endpoint),
are not duplicated. An indicator is turned off with `management.health.<key>.enabled: false`.

<a name="the-warning-status"></a>
### The WARNING status

The server adds the status `WARNING` for a failure where the server still works, for example a metadata download that
failed while the metadata already held is used.

By default `WARNING` gives HTTP 200, and it is placed between `UP` and the failing statuses in the status order, so
that a `WARNING` from one indicator gives `WARNING` overall unless another one is `DOWN` or `OUT_OF_SERVICE`. Both are
Spring Boot settings that the deployment may change:

```yaml
management:
  endpoint:
    health:
      status:
        order: DOWN, OUT_OF_SERVICE, WARNING, UP, UNKNOWN
        http-mapping:
          down: 503
          out-of-service: 503
          warning: 503
```

The order above is the default that the server sets. A deployment that sets `http-mapping` replaces all of Spring
Boot's default mappings, so it gives the codes for `DOWN` and `OUT_OF_SERVICE` too, as in the example. Without them,
those statuses would give HTTP 200.

<a name="saml-metadata-health"></a>
### SAML metadata

**Key:** `saml-metadata`

Each SAML metadata source reports whether its latest download succeeded and how old its metadata is.

| Status | When |
| :--- | :--- |
| `UP` | Every source holds metadata and its latest download succeeded. |
| `WARNING` | The latest download of a source failed. The server keeps using the metadata it has, or the backup file, so it still works, but the metadata gets older. |
| `OUT_OF_SERVICE` | No source holds a single Service Provider. The server cannot serve any request. |

A download counts as failed also when the server falls back to the metadata it holds or to the backup file. An MDQ
source cannot tell how many Service Providers it has, and does not count as empty.

```json
"saml-metadata" : {
  "status" : "WARNING",
  "details" : {
    "sources" : [ {
      "name" : "https://md.swedenconnect.se/role/sp.xml",
      "last-download" : "2026-10-01T10:00:03Z",
      "last-download-successful" : false,
      "loaded-at" : "2026-10-01T06:00:12Z",
      "age" : "PT3H59M51S",
      "service-providers" : 412,
      "error" : "HTTP status 503"
    } ]
  }
}
```

`loaded-at` is when the metadata was last downloaded or read successfully, and `age` is the time since then.

<a name="oidc-trust-marks-health"></a>
### The trust marks of the OpenID Provider

**Key:** `oidc-trust-marks`

Present when OpenID Federation is enabled. Each of the OpenID Provider's own trust mark types, see
[The trust marks of the OpenID Provider](openid-provider.html#the-trust-marks-of-the-openid-provider), reports
whether a valid trust mark is published, when it expires, when it was last fetched, and, while fetching fails, the
number of failed attempts and the latest error.

| Status | When |
| :--- | :--- |
| `UP` | A valid trust mark is published for every type, and the latest fetch or renewal of each succeeded. |
| `WARNING` | The fetch or renewal of a type failed, or a type has no valid trust mark. |

When the trust marks are kept in Redis, every server instance reports the same.

<a name="oidc-federation-health"></a>
### Federation services

**Key:** `oidc-federation`

The OpenID Federation services that the server calls: the resolver, and each trust mark issuer, whether it is called
for the OpenID Provider's own trust marks, for a trust mark that a client is asked to hold, or for a trust mark status
check.

The health is built from the calls that the server makes, never from calls made by the health check. A resolver
answer that a client is not found is a successful call; any other error answer counts as a failure. Each service
reports the outcome of its latest call and when it was made, its most recent failure with its time, its kind
(`error-response` or `unreachable`) and the error, and the number of failed calls since the latest successful one. A
failure is therefore still shown after a later call has succeeded.

| Status | When |
| :--- | :--- |
| `UP` | The latest call to every service succeeded, or no call has been made. |
| `WARNING` | The latest call to a service failed. |

```json
"oidc-federation" : {
  "status" : "UP",
  "details" : {
    "services" : [ {
      "type" : "resolver",
      "id" : "https://fed.swedenconnect.se/resolve",
      "latest-outcome" : "success",
      "latest-call" : "2026-10-01T10:02:44Z",
      "failures-since-success" : 0,
      "last-failure" : {
        "time" : "2026-10-01T09:58:12Z",
        "kind" : "unreachable",
        "error" : "Failed to make resolve request to https://fed.swedenconnect.se/resolve - Connection refused"
      }
    } ]
  }
}
```

A resolver is identified by its endpoint and a trust mark issuer by its entity identifier. When the federation cache
is kept in Redis, so is this state, and every server instance reports the same.

The calls are recorded by the `HttpFederationClient` bean that the auto-configuration declares. An application that
sets up the federation backend of the client registry builds it with that bean, see
[The client registry](client-registry.html#the-federation-backend); calls made through a client that the application
creates itself are not seen.

<a name="state-that-survives-a-restart"></a>
## State that survives a restart

When the server keeps its state in memory, some of it is worth keeping when the server restarts. Give a cache
directory:

```yaml
authn-server:
  cache-directory: /var/authn-server/cache
```

| Property | Description | Default value |
| :--- | :--- | :--- |
| `authn-server.cache-directory` | A directory where the server keeps state that should survive a restart when it keeps its state in memory. | Nothing is kept |

Without a cache directory nothing is kept, and every start behaves as a first start. The server decides how the
directory is organized:

| Path | What it holds |
| :--- | :--- |
| `known-clients.json` | The record of the clients that the server knows, which the server compares with at startup, see [Clients added and removed](#clients-added-and-removed). Written when a client is added or removed. |
| `oidc/federation-cache.json` | The cache of clients resolved through OpenID Federation. Written a few seconds after a change, and when the server stops. At startup, entries that have expired are dropped. |
| `oidc/trust-marks/` | The OpenID Provider's own trust marks, one file per trust mark type. A stored trust mark is used at startup if it is still valid. |

`authn-server.oidc.federation.trust-mark-cache-directory`, when set, overrides where the trust marks of the OpenID
Provider are kept.

When state is kept in Redis, see [Running several nodes](configuration.html#running-several-nodes), it survives a
restart there and the cache directory is not used for it. The record of known clients follows
`authn-server.storage.type`, the federation cache `authn-server.oidc.storage.federation-cache` and the trust marks
`authn-server.oidc.storage.trust-marks`.

<a name="clients-added-and-removed"></a>
## Clients added and removed

The server publishes an audit event when a client appears in or disappears from the client registry:
[`client_added`](audit.html#client_added) and [`client_removed`](audit.html#client_removed). There is one event per
client. Both are system operations, so their principal is the system principal.

A client is added when:

- a SAML metadata source that is downloaded or read again holds a Service Provider that it did not hold before, or
- an OpenID Federation client is resolved and was not known before.

A client is removed when:

- a SAML metadata source that is downloaded or read again no longer holds a Service Provider that it had, unless
  another metadata source holds it, or
- the OpenID Federation resolver reports a client that was known as not found, at a request, at a refresh of the
  cache, or at an update through the [clients endpoint](#the-clients-endpoint).

A federation client whose cache entry expires and that is resolved again is neither added nor removed.

**At startup** the clients that the server loads are compared with the record of known clients from before the
restart, which is kept in the [cache directory](#state-that-survives-a-restart) or in Redis. Every Service Provider of
the SAML metadata, every configured OpenID Connect client, and every client of a repository that can list its clients
that was not known gives `client_added`, and every such client that was known and is no longer there gives
`client_removed`. The federation clients in the cache that were not known give `client_added`. A known federation
client that is not in the cache is not removed, since it is only resolved again when it is asked for. Without a
previous record, every client gives `client_added` once.

**With Redis** the record of known clients is shared, and each change gives its event once for the whole deployment,
not once per server instance.

An MDQ source is queried one Service Provider at a time, so its Service Providers are neither added nor removed.

A deployment that does not want these events in its audit log excludes them in the configuration of its audit
repositories, with spring-audit-support's `audit.repository.exclude-events`, or leaves them out of
`audit.repository.include-events`, see
[Configuration](https://docs.swedenconnect.se/spring-audit-support/configuration.html):

```yaml
audit:
  repository:
    file:
      log-file: /var/log/idp/audit.log
    exclude-events:
      - client_added
      - client_removed
```

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
