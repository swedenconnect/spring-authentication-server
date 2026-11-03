![Logo](images/sweden-connect.png)

# The client registry

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

Every request comes from a requester: a SAML Service Provider known by its entityID, or an OpenID Connect client
known by its `client_id`. Before the server can process a request it needs to know who the requester is. That is what
the client registry is for.

The registry is one interface for both protocols. Code that does not care about the protocol, such as the login page
or a check that the requester holds a certain mark, works against the protocol-neutral part of what the registry
answers. The SAML and OpenID Connect layers reach for the protocol metadata inside it.

Source links in this guide point to the `main` branch of the
[spring-authentication-server](https://github.com/swedenconnect/spring-authentication-server) repository.

## Table of Contents

1. [**Looking up a requester**](#looking-up-a-requester)

2. [**The record**](#the-record)

    2.1. [Marks](#marks)

    2.2. [The organisation number](#the-organisation-number)

3. [**Backends**](#backends)

4. [**SAML: metadata sources**](#saml-metadata-sources)

5. [**OpenID Connect: three backends**](#openid-connect-three-backends)

    5.1. [Validation of configured and repository clients](#static-client-validation)

6. [**The federation backend**](#the-federation-backend)

    6.1. [The cache](#the-cache)

    6.2. [Filling the cache from the federation](#filling-the-cache)

    6.3. [Trust marks on demand](#trust-marks-on-demand)

    6.4. [Checking the status of trust marks](#trust-mark-status-checks)

    6.5. [Several nodes](#several-nodes)

    6.6. [Invalid clients](#invalid-clients)

    6.7. [Pairwise clients](#pairwise-clients)

    6.8. [Keys of federation clients](#client-keys)

7. [**Deciding which requesters may use the server**](#requester-acceptance)

<a name="looking-up-a-requester"></a>
## 1. Looking up a requester

[`ClientRegistry`][ClientRegistry] has one lookup, by protocol and requester identity:

```java
RequesterRecord record = clientRegistry.lookup(AuthenticationProtocol.OIDC, clientId);
if (record == null) {
  // The registry does not know this client.
}
```

A requester that the registry does not know gives `null`. That is a normal outcome, and it is not the same thing as a
backend that fails. A metadata source that cannot be read, or a resolver service that cannot be reached, throws a
[`ClientRegistryException`][ClientRegistryException]. A failure is never reported as an unknown requester, so a
temporary problem behind the registry never turns into "no such client".

<a name="the-record"></a>
## 2. The record

A [`RequesterRecord`][RequesterRecord] holds a protocol-neutral part and the protocol metadata.

The protocol-neutral part is:

- The [`Requester`][Requester], that is, the protocol and the requester identity.
- The display names, one per language. A name without a language may appear, and at most one does.
- The logotypes, with a language where the metadata gives one, and a size where the metadata gives one.
- The marks that the requester holds.
- The organisation number of the requester, when its metadata gives one, see
  [Section 2.2, "The organisation number"](#the-organisation-number).

Picking a name or a logotype for the user's language is done by the record:

```java
String name = record.getDisplayName("sv");
Logo logo = record.getLogo("sv");
```

The name for the exact language tag is used if there is one, otherwise a name for a language with the same primary
subtag, so that `sv-SE` in the metadata answers a request for `sv`, and otherwise the name that is not tied to a
language.

The protocol metadata is carried as it is and the core never looks at it. Ask for it in its own type:

```java
EntityDescriptor spMetadata = record.getProtocolMetadata(EntityDescriptor.class);
OIDCClientMetadata clientMetadata = record.getProtocolMetadata(OIDCClientMetadata.class);
```

<a name="marks"></a>
### 2.1. Marks

Marks are one set of identifiers for both protocols:

- For SAML they are the entity category URIs that the Service Provider declares in its metadata.
- For OpenID Connect they are trust mark types.

Consumers see identifiers and nothing else. That a trust mark is valid is the backend's business, checked before the
type is put in the set, so `record.hasMark(mark)` means that the requester holds the mark:

```java
if (!record.hasMark("http://id.elegnamnden.se/sprop/1.0/mobile-auth")) {
  ...
}
```

A mark that the operator has set on a configured client, or on a client held in a repository, is there because the
operator vouches for it. Those are not verified.

<a name="the-organisation-number"></a>
### 2.2. The organisation number

`record.organizationNumber()` tells which organisation the requester belongs to, so that code such as login page
support, audit and checks for accepting a requester does not have to read SAML or OpenID Connect metadata:

- For SAML it is the `mdorgext:OrganizationNumber` extension of the Service Provider's `md:Organization`, see the
  [schema](https://docs.swedenconnect.se/schemas/authn/1.0/OrganizationNumber-1.0.xsd).
- For OpenID Connect it is `organization_identifier` in the client metadata, see
  [OpenID Federation Organization Identifier Metadata Parameter 1.0](https://www.oidc.se/specifications/openid-federation-organization-identifier-1_0.html)
  and Section 3 of
  [Sweden Connect - OpenID Connect Metadata Requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html).

The value is held exactly as the metadata publishes it, and it is not validated. The two protocols use different
forms. A SAML value may be `556677-8899`, `5566778899` or anything else, since the schema does not restrict it, while
an OpenID Connect value is a GLUE URI such as `urn:glue:iso6523:0007:5566778899`. Code that compares requesters across
protocols handles both forms itself.

The organisation number is optional. A requester whose metadata gives none has `null` in its record.

<a name="backends"></a>
## 3. Backends

The registry itself holds no data. It asks its backends, and each backend answers for one protocol. Several backends
may serve the same protocol, in which case they are asked in the order they were given and the first one that knows
the requester wins. [`ClientRegistryBackend`][ClientRegistryBackend] is the interface, and
[`DefaultClientRegistry`][DefaultClientRegistry] is the registry that asks them.

<a name="saml-metadata-sources"></a>
## 4. SAML: metadata sources

Service Provider metadata is read through one or more [`MetadataSource`][MetadataSource] objects, and
[`MetadataProviderFactory`][MetadataProviderFactory] turns them into the OpenSAML provider that
[`SamlMetadataBackend`][SamlMetadataBackend] serves. The location of a source decides how it is read:

| Location | How it is read |
|----------|----------------|
| An HTTP or HTTPS URL | Downloaded as a federation metadata document |
| An HTTP or HTTPS URL with `mdq` set | Queried entity by entity with the [MDQ protocol](https://www.ietf.org/id/draft-young-md-query-17.html) |
| A file | Read from the file system and reloaded when it changes |
| Anything else, such as a classpath resource | Read once and held in memory |

```java
MetadataSource source = MetadataSource.builder(new UrlResource("https://md.swedenconnect.se/role/sp.xml"))
    .validationCertificate(certificate)
    .backupLocation(new File("/var/authn-server/metadata-backup.xml"))
    .build();

SamlMetadataBackend backend =
    new SamlMetadataBackend(MetadataProviderFactory.createMetadataResolver(List.of(source), sslBundles));
```

Give several sources and they are combined into one, searched in the order they were given. That is how a federation
metadata source and a locally kept Service Provider can live side by side.

For a downloading source:

- **Assign a validation certificate.** It is what makes the downloaded metadata trustworthy. Without one the server
  starts, but it logs a warning and the metadata cannot be trusted.
- **Assign a backup location.** Downloaded metadata is stored there so that the server can start even when the
  source cannot be reached. It is a file for a federation metadata source and a directory for an MDQ source. Without
  one the server logs a warning.
- TLS trust comes from the Java default unless the source names a
  [Spring SSL bundle](https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl). Hostname
  verification can be turned off, which is meant for testing only.
- An HTTP proxy is configured per source.

The display names of a record are taken from the `mdui:UIInfo` extension, then from
`Organization/OrganizationDisplayName` and finally from `Organization/OrganizationName`. For every language the first
name found is the one used. Logotypes come from `mdui:UIInfo`. The marks are the entity categories that the Service
Provider declares. The organisation number comes from the `mdorgext:OrganizationNumber` extension of
`md:Organization`; a Service Provider without `md:Organization`, or without the extension, has none.

The SAML configurer creates this backend from the metadata sources it is given, and with Spring Boot the sources are
set with the `authn-server.saml.metadata-providers` properties, see [Section 5.4, "Service Provider metadata"](configuration.html#sp-metadata) of [Configuration](configuration.html).

<a name="openid-connect-three-backends"></a>
## 5. OpenID Connect: three backends

The OpenID Connect side has three backends. They are asked in a configured order, and the default order is
configuration, repository, federation.

- **Configuration** ([`ConfigurationClientBackend`][ConfigurationClientBackend]): the clients that the deployment
  gives the server directly. With Spring Boot, they are given with `authn-server.oidc.clients`, in JSON files or
  inline, see [Section 6.2, "Clients"](configuration.html#oidc-clients) of [Configuration](configuration.html), and that source is named `properties`. Configured clients
  added in code get the name `configuration`. The clients are read with
  [`OidcClientReader`][OidcClientReader], which may also be used without Spring Boot.
- **Repository** ([`RepositoryClientBackend`][RepositoryClientBackend]): the clients of a
  [`ClientRepository`][ClientRepository]. The library ships [`InMemoryClientRepository`][InMemoryClientRepository];
  implementations backed by a database are added later. A repository that can list its clients implements
  `findAll()`, so that its clients can be listed and compared with those known before a restart, see
  [Section 6, "Clients added and removed"](management.html#clients-added-and-removed) of [Monitoring and managing the server](management.html).
- **Federation** ([`FederationClientBackend`][FederationClientBackend]): clients resolved through OpenID Federation.

Every client source has a name, which the [Actuator](management.html) and the [audit events](audit.html) use to tell
the sources apart. The names must be unique among the client sources of a protocol, and the application does not
start if two sources of the same protocol have the same name. The `properties` source is asked before any OpenID
Connect client source added in code.

The first two work from an [`OidcClientRecord`][OidcClientRecord], which is a `client_id`, the client metadata as
Nimbus models it, and the trust mark types that the operator has set:

```java
OIDCClientMetadata metadata = new OIDCClientMetadata();
metadata.setName("Tjänsten", LangTag.parse("sv"));
metadata.setName("The Service", LangTag.parse("en"));
metadata.setLogoURI(URI.create("https://client.example.com/logo.svg"));

ClientRegistryBackend backend = new ConfigurationClientBackend(
    List.of(new OidcClientRecord("https://client.example.com", metadata, Set.of(trustMarkType))));
```

The display names of a record come from `client_name` and the logotypes from `logo_uri`, both in every language that
the metadata gives them in. The Sweden Connect profile requires `client_name` in Swedish and English, so a client that
follows the profile gives the login page a name in both languages. The organisation number comes from
`organization_identifier` in the client metadata, for all three backends. A federation client gets it from the
resolved metadata, where the Sweden Connect registration intermediate sets it. For a configured client, or a client in
a repository, the operator puts it in the client metadata:

```java
metadata.setCustomField("organization_identifier", "urn:glue:iso6523:0007:5566778899");
```

A configured client, or a client in a repository, that authenticates with a client secret at the token endpoint has
the secret in the `client_secret` field of its metadata, see
[Section 6.3, "Client authentication"](openid-provider.html#client-authentication) of [The OpenID Provider](openid-provider.html).

<a name="static-client-validation"></a>
### 5.1. Validation of configured and repository clients

The clients of the configuration and of a client repository are checked with the same rules as federation clients,
by the [`ClientMetadataValidator`][ClientMetadataValidator], so that a client with an error is found at once and not
when a request hits it, which can be after the user has logged in. The rules are listed in
[Section 6.6, "Invalid clients"](#invalid-clients).

The OpenID Provider sets this up when it starts: it gives each `ConfigurationClientBackend` and
`RepositoryClientBackend` added to the client registry a [`ClientValidation`][ClientValidation], which holds the
validator and knows the algorithms and client authentication methods that the OpenID Provider supports. The
application adds the backend as before and supplies nothing more, and the author of a `ClientRepository` does nothing
for it. A backend that the OpenID Provider has not set up, for example one in a client registry that the application
assigns itself, marks every client as invalid.

A client is validated:

- at startup, for every configured client, and for every client of a repository whose `findAll()` lists them,
- at its first lookup, for a client of a repository that cannot list its clients,
- when the metadata of a repository client differs from what was validated,
- when a temporary mark has run out, see below.

A lookup makes no network call unless the metadata has changed or a temporary mark has run out. A repository that
cannot be read at startup does not stop the server. The failure is logged, and its clients are validated when they are
looked up. An error in a client never stops the server from starting.

A client with an error is blocked in the same way as a federation client. It stays in the client registry and in the
[clients endpoint](management.html#the-clients-endpoint), shown as invalid with the reason, is never authenticated, and
gets `invalid_client` at its redirect URI and at the token endpoint. A client without a registered redirect URI ends at
the error page for a client that is not correctly registered. Every error is logged at error level, since it is an
error in the setup of the server, and gives a [`client_invalid`](audit.html#client_invalid) audit event.

The rules differ from those for federation clients in these ways:

- **Client secrets.** A `token_endpoint_auth_method` that needs a client secret, including the default
  `client_secret_basic`, is accepted if the client has a secret and is an error if it does not. The method must still
  be enabled by the OpenID Provider.
- **Pairwise clients.** A pairwise client with redirect URIs on more than one host and no `sector_identifier_uri` has an
  error. The document at the `sector_identifier_uri` is never fetched, whatever
  `authn-server.oidc.federation.clients.check-sector-identifier-uri` says. The operator is expected to give correct
  values. A repository whose clients register themselves must check the document when a client registers, since the
  server does not.
- **`signed_jwks_uri`.** A client with only a `signed_jwks_uri` has an error, since there is no trust chain to give its
  Federation Entity Keys. A client that also has `jwks` or `jwks_uri` uses those, and its `signed_jwks_uri` is
  ignored.
- **Metadata that cannot be parsed** is not a case, since these clients are parsed when they are created.

**Keys.** The keys at the `jwks_uri` of a client are read when it is validated, and held together with the URI, as for a
federation client, see [Section 6.8, "Keys of federation clients"](#client-keys). A request does not cause a fetch for a
key that is held. A client with `jwks` uses those keys. The keys are read again:

- when a JWT names a key that is not held, at most once a minute for each client,
- by a background job, the [`ClientKeysRefresher`][ClientKeysRefresher], every
  `authn-server.oidc.client-keys-refresh-interval`, 1 hour by default. It covers every configured client and every
  client of a repository that can list them, and the repository clients that have been validated otherwise. Without
  it, the OpenID Provider would keep encrypting to an old key, since encryption has no trigger like the unknown key.
  The job also validates again a client whose temporary mark has run out.

| Situation | Result |
| :--- | :--- |
| The keys at `jwks_uri` cannot be read at the first check | Invalid for `authn-server.oidc.federation.clients.cache.not-found-time-to-live`, then validated again at the next lookup or by the job |
| A later read fails, or gives keys that cannot be used | The held keys are kept and the client stays valid. A failed read is logged and shows in the [health of the federation services](management.html#oidc-federation-health) |
| The `jwks_uri` of a repository client has changed | The keys of the old URI are not kept |
| Any other error | Invalid until the metadata changes, which for a configured client means until a restart |

Reads have the same limits as for federation clients and use the same fetcher. With Spring Boot, the outcomes and the
held keys are kept in memory or in Redis according to `authn-server.storage.type`. With Redis, all nodes share them,
and the background job runs on one node at a time. In memory, each node holds its own. In code, the store is assigned
with `authnRequestProcessor(c -> c.clientValidationStore(...))` on the `OidcProviderConfigurer`, and the job's interval
and the time of a temporary mark with `clientKeysRefreshInterval(...)` and `clientKeysFailureTimeToLive(...)`.

The keys of a client of a backend of the application's own, which holds no keys, are found by the configured
`ClientKeyResolver`.

<a name="the-federation-backend"></a>
## 6. The federation backend

The federation backend resolves a client through OpenID Federation, where the `client_id` of the client is its entity
identifier.

With Spring Boot, it is set up from properties: the trust anchor under `authn-server.oidc.federation.trust-anchor` and
the source under `authn-server.oidc.federation.clients`, with the resolver, the trust mark issuers and the cache, see
[Section 6.11, "Clients from OpenID Federation"](configuration.html#oidc-federation-clients) of [Configuration](configuration.html). The source is named `federation`, and it
is on whenever the OpenID Provider is a member of a federation, unless it is turned off. Endpoints that are not
configured are found in the entity configurations of the resolver and the issuers, by
[`EntityConfigurationEndpoints`][EntityConfigurationEndpoints].

The OpenID Connect sources are asked in this order: the configured clients of `authn-server.oidc.clients`
(`properties`), then the sources added in an adapter, and the federation source last. A client known to both the
configured clients and the federation is therefore served from the configured clients.

The rest of this section describes the parts, for an application that replaces some of them, for example with a
resolver of its own. A `FederationClientBackend` that an adapter adds replaces the one of the properties, which is
then not set up. The backend is put together from a [`FederationResolver`][FederationResolver], a
[`TrustMarkRequester`][TrustMarkRequester], a [`FederationCache`][FederationCache] and
[`FederationCacheSettings`][FederationCacheSettings]:

```java
FederationSettings federation = new FederationSettings(
    new FederationSettings.TrustAnchor(trustAnchorEntityId, trustAnchorKeys),
    new FederationSettings.Resolver(resolverEntityId, resolveEndpoint, resolverKeys),
    Map.of(trustMarkType, new FederationSettings.TrustMarkIssuer(issuerEntityId, trustMarkEndpoint, issuerKeys,
        trustMarkStatusEndpoint)));

FederationClientBackend backend = new FederationClientBackend(
    new HttpFederationResolver(federation),
    new HttpTrustMarkRequester(federation),
    new InMemoryFederationCache(),
    FederationCacheSettings.defaults());
```

[`HttpFederationResolver`][HttpFederationResolver] calls the resolve endpoint of an external resolver service. The
resolve response is a signed JWT, and it is verified with the trust anchor's keys when the resolver runs at the trust
anchor, that is, when it has the same entity identifier, and with the resolver's own keys otherwise. The keys of a
resolver that is not the trust anchor are configured together with it. A resolver given without an endpoint, `null`,
is called at the `federation_resolve_endpoint` that it publishes in its entity configuration, and the same holds for
the trust mark endpoint and the status endpoint of an issuer. The record holds the client metadata
of the response, after the metadata policies of the trust chain have been applied by the resolver, and the trust mark
types of the response.

Resolving inside the OpenID Provider itself is a later addition. It arrives as another implementation of
`FederationResolver`, and nothing else changes.

<a name="the-cache"></a>
### 6.1. The cache

Resolved clients are cached, because reaching the resolver on every request is not an option.

- An entry lives until the expiry that the resolve response gives, or until an optional maximum age if that comes
  first. No maximum age is set by default.
- The store is pluggable, so that the nodes of a deployment can share it. The default is
  [`InMemoryFederationCache`][InMemoryFederationCache], which is what a single node needs.
  [`RedisFederationCache`][RedisFederationCache] keeps the entries in Redis, shared by all nodes.
- A client that the resolver does not know is cached as such for a short time, five minutes by default, so that
  repeated requests with the same unknown `client_id` do not each reach the resolver. A resolver that fails is never
  cached.

<a name="filling-the-cache"></a>
### 6.2. Filling the cache from the federation

[`FederationClientCollector`][FederationClientCollector] is a background job that walks the federation and puts every
client it finds in the cache, so that an authorization request does not have to wait for the resolver. With Spring
Boot it runs whenever the federation source is set up from the properties: on by default, every 30 minutes, with the
first run shortly after startup. It is turned off, or given another interval, under
`authn-server.oidc.federation.clients.collector`, see [Section 6.11, "Clients from OpenID Federation"](configuration.html#oidc-federation-clients) of [Configuration](configuration.html).

A client that the job has not found yet, for example one that joined the federation after the latest run, is still
resolved at its first request, as before.

**The walk.** A run starts at the trust anchor. Each entity is resolved through the resolver, asking for both its
relying party and its federation entity metadata, so the answers are signed and verified in the same way as for
clients, and no other keys are needed. An entity that publishes a `federation_list_endpoint` is asked for its
subordinates (OpenID Federation 1.0, Section 8.2), and each of them is resolved in the same way:

- an entity with relying party metadata is a client, and is put in the cache,
- an entity with a `federation_list_endpoint` is walked into, and an entity can be both,
- an entity with neither, such as an OpenID Provider or a trust mark issuer, is only remembered.

The listings are not filtered, so that any federation entity answers them. Each entity is visited once per run, so a
loop in the listings does no harm. What the resolver answers about each entity is kept in a
[`FederationEntityStore`][FederationEntityStore], separate from the cache, and is not asked for again until the
resolve response expires, or the maximum age of the cache has passed. An answer that the resolver does not know an
entity is kept as long as for a client. A failure is never kept.

**Where to start.** In a large federation, a walk from the trust anchor resolves every entity of the federation, which
costs one resolve request per entity after each start and memory for every answer. When the clients that matter are
below one or a few intermediates, give them as `authn-server.oidc.federation.clients.collector.intermediates`, and
the walk starts there instead of at the trust anchor. A client below another intermediate is resolved at its first
request, as before.

**Renewing.** A run resolves again every cached client whose entry expires before the next run, whether the job found
it or a request did, and keeps the trust marks that have been [asked for on demand](#trust-marks-on-demand). A client
whose resolve response lives shorter than the interval of the job can still expire between two runs, and is then
resolved at its next request.

**Clients that are no longer listed.** A listing is not signed, and a call can fail, so a run only counts as evidence
that a client is gone when every listing call and every resolution of the walk succeeded. A cached client that such a
run did not find is resolved again; a client that still resolves stays, also one that was found through a request
outside the configured intermediates. When the resolver answers that it does not know the client, at this point or
when the client is renewed:

- by default, the client is kept until its cache entry expires, never longer, which is what OpenID Federation 1.0,
  Section 12.3, allows. A client that dropped out of the resolver by mistake then has time to fix it without its users
  noticing. Each such client is logged at `WARN` and shown in the
  [health of the federation services](management.html#oidc-federation-health). Once the entry has expired, the next
  answer that the client is not known reports it as [removed](management.html#clients-added-and-removed).
- with `keep-until-expiry` set to `false`, the client is dropped and reported as removed at once.

The job cannot tell a client that the federation has removed from one that has a broken configuration. With the
default, **a removed client therefore keeps working until its cache entry expires**. Turn the setting off when a
removal must take effect at once, and the resolver is reliable enough that a client is never missing by mistake.

A resolver or listing endpoint that fails never removes anything. The failure is logged, shows in the
[health of the federation services](management.html#oidc-federation-health), and the entity is tried again at the
next run. The rest of the run goes on.

An application that builds the backend in code starts the job itself:

```java
FederationClientCollector collector = new FederationClientCollector(backend, new InMemoryFederationEntityStore(),
    httpFederationClient, federation, FederationCollectorSettings.defaults());
collector.start();
```

<a name="trust-marks-on-demand"></a>
### 6.3. Trust marks on demand

A resolve response carries the trust marks that the resolver knows about. A trust mark that it does not carry can be
asked for from its issuer:

```java
RequesterRecord record = clientRegistry.requestMark(requester, trustMarkType);
if (record != null && record.hasMark(trustMarkType)) {
  ...
}
```

- The issuer to ask for each trust mark type is configured. A type with no configured issuer is never asked for.
- The issuer's keys are configured together with it, unless the issuer is the trust anchor, in which case the trust
  anchor keys are used.
- A trust mark that is received is verified before its type is added: its signature, that it was issued to the
  client, that it is of the type that was asked for, and that it has not expired.
- A trust mark obtained this way is added to the client's cached record and kept until the earlier of the trust
  mark's expiry and the record's expiry. Later requests from the same client need no call to the issuer, and a
  renewal of the record carries the trust mark over while it is still valid.
- A trust mark without `exp`, or with a long one, stays trusted after the issuer has withdrawn it, unless its status is
  checked, see [Section 6.4, "Checking the status of trust marks"](#trust-mark-status-checks).

For SAML, asking for a mark never finds anything. It gives the requester's record unchanged.

<a name="trust-mark-status-checks"></a>
### 6.4. Checking the status of trust marks

[`TrustMarkStatusChecker`][TrustMarkStatusChecker] is a background job that asks the issuer whether the trust marks
obtained on demand are still valid, at the issuer's trust mark status endpoint (OpenID Federation 1.0, Section 8.4).
It runs at a configurable interval, one hour by default:

```java
TrustMarkStatusChecker checker = new TrustMarkStatusChecker(cache, federation, httpFederationClient,
    Duration.ofHours(1), Clock.systemUTC());
checker.setEventPublisher(applicationContext);
checker.start();
```

With Spring Boot, `httpFederationClient` is the [`HttpFederationClient`][HttpFederationClient] bean, so that the
status checks count toward the [health of the trust mark issuers](management.html#oidc-federation-health).

- A trust mark is checked when it has no `exp`, or when its `exp` is later than the next check. A trust mark that
  expires before the next check is not checked; it expires as before.
- The status endpoint of an issuer is configured together with the issuer, as `statusEndpoint` of
  `FederationSettings.TrustMarkIssuer`. A checker built with an
  [`EntityConfigurationEndpoints`][EntityConfigurationEndpoints] checks an issuer without a configured status endpoint
  at the `federation_trust_mark_status_endpoint` that it publishes, as the one set up from the properties does. The
  trust marks of an issuer without a status endpoint are not checked.
- The status response is verified with the keys of the issuer, and must be about the trust mark that was sent.
- A trust mark that the issuer reports as anything but `active`, such as `revoked` or `expired`, is removed from the
  client's cached record. A client that needs it for the [required marks](#requester-acceptance) is then treated as not
  holding it on its next request: the trust mark is asked for again, and when the issuer no longer issues it, the
  client is rejected with the same error response as any client that lacks a required mark. The removal is also
  published as a system alert for the audit log, when the checker has been given an event publisher, see
  [Section 5.4, "Trust mark alerts"](audit.html#trust-mark-alerts) of [Auditing](audit.html).
- A status endpoint that cannot be reached, or a response that does not verify, leaves the trust mark in place. It is
  logged at `WARN`, and the trust mark is checked again at the next run.

The trust marks of the resolve response are not checked by the job. The resolver has checked them, and they are held
no longer than the resolve response is valid.

<a name="several-nodes"></a>
### 6.5. Several nodes

The background jobs ask the cache for the lock that decides which node runs a round. With a `RedisFederationCache`,
each run of the [job that fills the cache](#filling-the-cache) and each round of the
[trust mark status checks](#trust-mark-status-checks) takes place on one node. A node that stops while it holds the
lock of a job blocks the job for at most one round. [`RedisFederationEntityStore`][RedisFederationEntityStore] keeps
the answers about the federation entities in Redis too, so that all nodes share them.

With Spring Boot, a `FederationCache` bean and a `FederationEntityStore` bean are declared according to
`authn-server.storage.type`, or `authn-server.oidc.storage.federation-cache`, see
[Section 7, "Running several nodes"](configuration.html#running-several-nodes) of [Configuration](configuration.html). The source set up from the properties uses them,
together with the jobs. An application that builds the backend in code
builds it and the jobs from the same bean, and from the [`HttpFederationClient`][HttpFederationClient] bean that the
auto-configuration declares. That client publishes the outcome of every call it makes, which is what the
[health of the federation services](management.html#oidc-federation-health) is built from:

```java
@Bean
FederationClientBackend federationBackend(final FederationCache cache, final HttpFederationClient client) {
  return new FederationClientBackend(new HttpFederationResolver(federation, client),
      new HttpTrustMarkRequester(federation, client), cache, settings);
}
```

The backend is added to the client registry with an `AuthnServerConfigurerAdapter`, which calls
`configurer.clientRegistryBackend(backend)`. The clients that the backend adds and removes are then reported, see
[Section 6, "Clients added and removed"](management.html#clients-added-and-removed) of [Monitoring and managing the server](management.html), and the clients it holds can be listed and
updated through the [clients endpoint](management.html#the-clients-endpoint).

<a name="invalid-clients"></a>
### 6.6. Invalid clients

A client resolved through OpenID Federation is marked as invalid when it is resolved and its registration has an
error. Its metadata is checked by the [`ClientMetadataValidator`][ClientMetadataValidator] each time it is
resolved: at a request, by the [job that fills the cache](#filling-the-cache) or through the operator's re-resolve.
Only what the OpenID Provider needs to serve the client is checked. Stricter rules of a federation, such as a required
`client_name` or `contacts`, are left to the Federation Operator's policy. The same rules apply to clients from the
configuration and from a client repository, with the differences listed in
[Section 5.1, "Validation of configured and repository clients"](#static-client-validation).

A parameter that is absent has the default value of OpenID Connect Dynamic Client Registration 1.0, Section 2. The
exception is ID token signing, where no algorithm is assumed, as for any client. A client has an error when:

- its metadata cannot be parsed, or it has no `redirect_uris`,
- its `response_types` do not include `code`, or its `grant_types` do not include `authorization_code`,
- its `token_endpoint_auth_method` is `none`, is not supported and enabled by the OpenID Provider, or needs a client
  secret. A federation client never has a client secret, so `client_secret_basic`, `client_secret_post` and
  `client_secret_jwt` are errors, and so is an absent `token_endpoint_auth_method`, since it defaults to
  `client_secret_basic`. In practice, a federation client authenticates with `private_key_jwt`,
- a signing or encryption algorithm that it declares is not supported by the OpenID Provider, as its discovery
  document tells,
- `jwks_uri` or `signed_jwks_uri` does not use `https`,
- it needs keys and has none, or its keys hold no usable key for an algorithm that it declares. Keys are needed for
  `private_key_jwt`, for a `request_object_signing_alg`, and for encryption of ID tokens or UserInfo responses, see
  [Section 6.8, "Keys of federation clients"](#client-keys),
- its keys at a `signed_jwks_uri` cannot be verified,
- it is a pairwise client whose registration has an error, see
  [Section 6.7, "Pairwise clients"](#pairwise-clients).

| Situation | Result |
| :--- | :--- |
| The keys at `jwks_uri` or `signed_jwks_uri` cannot be fetched or read, and the client holds no keys from the same URI | Invalid for `clients.cache.not-found-time-to-live` |
| The pairwise document cannot be fetched, see [Section 6.7](#pairwise-clients) | Invalid for `clients.cache.not-found-time-to-live` |
| Any other error, including keys that were fetched but cannot be used | Invalid until the client is next resolved |

A client marked as invalid stays in the client registry and in the cache, and is shown in the
[clients endpoint](management.html#the-clients-endpoint) as invalid, with the reason. It is never authenticated. Its
authorization requests get `invalid_client` at its redirect URI, with an `error_description` saying what is wrong, and
the user is not shown an error page. A token request from it gets `invalid_client` too. The redirect is deliberate:
the registered `redirect_uri` is still trusted, and the relying party is the one that can fix its registration. OpenID
Federation 1.0, Section 12.1.3, can be read as forbidding a redirect when the RP metadata is invalid.

A client with no registered redirect URI, which is the case for metadata that cannot be parsed and for a missing
`redirect_uris`, cannot be answered. Its authorization requests end at the error page for a client that is not
correctly registered. A resolve response whose relying party metadata cannot be parsed is not a failure of the
resolver, and it shows neither in the health of the federation services nor as an incomplete run of the job that
fills the cache. An entity with such metadata that publishes a `federation_list_endpoint` is still walked into.

Every case is logged, and marking a client as invalid gives a [`client_invalid`](audit.html#client_invalid) audit
event, where the `reason` tells what is wrong. A client whose registration has been fixed is valid again the next time
it is resolved; `POST /actuator/clients/oidc` resolves it at once.

<a name="pairwise-clients"></a>
### 6.7. Pairwise clients

A client with `subject_type` set to `pairwise` gets a `sub` computed from its sector identifier, the host of its
`sector_identifier_uri`, see [Section 5.3, "OpenID Connect"](attributes.html#openid-connect-1) of
[Attributes](attributes.html). If the server took the URI on trust, a client could name another organization's host,
get the same `sub` values as that organization's clients, and correlate their users. So each time a federation client
is resolved, the [`PairwiseClientCheck`][PairwiseClientCheck] checks its registration, and a client with an error is
marked as invalid, see [Section 6.6, "Invalid clients"](#invalid-clients). An authorization request for a cached client
never causes a fetch.

| Situation | Result |
| :--- | :--- |
| There is no `sector_identifier_uri`, and `redirect_uris` have more than one host | Invalid until the client is next resolved |
| The document at `sector_identifier_uri` does not list all `redirect_uris` | Invalid until the client is next resolved |
| First check of the client, and the document cannot be fetched | Invalid for `clients.cache.not-found-time-to-live` |
| `sector_identifier_uri` has changed, and the document cannot be fetched | Invalid for `clients.cache.not-found-time-to-live` |

If only `redirect_uris` have changed and the document cannot be fetched, the client stays valid and the new metadata is
used. The first row needs no fetch and applies also when the check of the document is turned off.

The `sector_identifier_uri` must use `https` and return a JSON array holding all the client's `redirect_uris`. A URI
without `https`, or a successful answer that is not such an array, counts as a document that does not list the
`redirect_uris`. A host that cannot be reached, an answer other than 2xx, a redirect, which is not followed, or a body
that is not JSON means that the document cannot be fetched. A call has a time limit and the answer a size limit, since
the URI comes from client metadata.

A successful check is remembered with the client's cache entry, per combination of `sector_identifier_uri` and
`redirect_uris`, also across re-resolves and, with Redis, across nodes. The document is fetched again only when the
combination changes. A client whose entry has expired and gone is checked as for the first time. When a temporary mark
has run out, the client is checked again the next time it is resolved or found by the job, even if the job holds a
valid resolve result for it.

The check of the document is turned off with `authn-server.oidc.federation.clients.check-sector-identifier-uri: false`,
or by giving the backend a `PairwiseClientCheck` without a fetcher. Do this only where someone else has done the check,
such as the Federation Operator in the Sweden Connect federation. For clients from the configuration and from a client
repository, the first row applies, but the document is never fetched, see
[Section 5.1, "Validation of configured and repository clients"](#static-client-validation).

<a name="client-keys"></a>
### 6.8. Keys of federation clients

A federation client gives its keys in one of three ways (OpenID Federation 1.0, Section 5.2.1): by value in `jwks`, as
a signed JWK Set at `signed_jwks_uri`, or as a JWK Set at `jwks_uri`. When a client gives more than one, `jwks` is used
first, then `signed_jwks_uri`, then `jwks_uri`.

Keys at a URI are fetched each time the client is resolved, and held with the client's cache entry, together with the
URI they came from. With Redis, all nodes share them. Verifying the signature of a client assertion or a request
object, and encrypting an ID token or a UserInfo response, uses the held keys, so a request does not cause a fetch for
a key that is held.

- **Rollover.** When a JWT names a key, by its `kid`, that the held keys do not hold, the keys are fetched again, so
  that a client can roll over its keys without waiting to be resolved again. The new keys replace the held ones if
  they pass the same checks as when the client is resolved. This happens at most once a minute for each client, so
  that requests naming made-up keys cannot cause a fetch each time, and never for a client marked as invalid.
- **A fetch that fails.** A client that already holds keys from the same URI keeps them, and stays valid, when a later
  fetch fails. The failure is logged, and shows in the
  [health of the federation services](management.html#oidc-federation-health). The keys are kept for as long as the
  client stays in the cache. A client that holds no keys from the URI is marked as invalid for a while, see
  [Section 6.6, "Invalid clients"](#invalid-clients).
- **Limits.** A fetch has a time limit and the answer a size limit, and redirects are not followed, since the URI comes
  from client metadata. Each fetch shows in the health of the federation services as a call to the URI.

**`signed_jwks_uri`** is supported. The JWT at the URI must have the type `jwk-set+jwt`, a `kid`, the client as its
issuer, and be signed with one of the client's Federation Entity Keys. These keys are taken from the client's entity
configuration, which comes first in the `trust_chain` of the resolve response, and which the resolver has verified.
They are kept with the cache entry, so that a later fetch, such as at a rollover, can be verified. A resolve response
without a usable `trust_chain` means that the keys cannot be verified, and the client is marked as invalid until it is
next resolved.

The keys are fetched by an [`HttpClientKeysFetcher`][HttpClientKeysFetcher]. With Spring Boot, the federation source
set up from the properties gives it the event publisher, so that its fetches are seen by the health check. An
application that builds the backend in code does the same:

```java
HttpClientKeysFetcher keysFetcher = new HttpClientKeysFetcher();
keysFetcher.setApplicationEventPublisher(applicationContext);
backend.setValidator(new ClientMetadataValidator(
    new PairwiseClientCheck(new HttpSectorIdentifierFetcher()), keysFetcher));
```

The OpenID Provider gives the backends added to the client registry its discovery document, which the validator checks
the algorithms and methods against, and takes the held keys through a
[`HeldKeysClientKeyResolver`][HeldKeysClientKeyResolver]. Clients from the configuration and from a client
repository hold their keys in the same way, see
[Section 5.1, "Validation of configured and repository clients"](#static-client-validation).

<a name="requester-acceptance"></a>
## 7. Deciding which requesters may use the server

Knowing a requester is not the same as accepting it. Once the requester has been found in the registry and its
request has been verified, a [`RequesterAcceptance`][RequesterAcceptance] check decides whether it may use the server.
A requester that is not accepted gets the error `NOT_AUTHORIZED`, answered to the requester as an error response. For
SAML that is the status `Responder` / `RequestDenied`, and for OpenID Connect the error `unauthorized_client`.

The check sees the requester's record: the protocol-neutral part and the protocol metadata. Two implementations are
supplied:

- **Accept all**, `RequesterAcceptance.acceptAll()`. It is the default when nothing is configured.
- **Configurable**, [`ConfigurableRequesterAcceptance`][ConfigurableRequesterAcceptance], which holds a set of
  [`RequesterPredicate`][RequesterPredicate]s.

Every predicate belongs to one protocol, and only the predicates of the requester's protocol are evaluated, so a rule
for SAML Service Providers never affects an OpenID Connect client. Per protocol, the predicates are combined in one of
two modes: `ALL`, the default, where every predicate must accept the requester, or `ANY`, where one accepting predicate
is enough. A protocol with no predicates accepts every requester.

Two predicates are built in:

- [`WhitelistRequesterPredicate`][WhitelistRequesterPredicate] accepts the requesters of a list of identities: SAML
  entityIDs or OpenID Connect `client_id`s.
- [`RequiredMarksRequesterPredicate`][RequiredMarksRequesterPredicate] requires marks, given as groups. Every group must
  be satisfied, and a group is satisfied by any one of its marks, so `[[A, B], [C]]` means "A or B, and C". When a
  group is not satisfied by the record, the predicate asks the registry for the missing marks, see
  [Section 6.3, "Trust marks on demand"](#trust-marks-on-demand), and evaluates the updated record before rejecting. For SAML nothing
  is obtained this way, so the Service Provider metadata decides.

With Spring Boot, the configurable check is set up from properties under each protocol's prefix, for SAML
`authn-server.saml.requester-acceptance.*`, see [Section 5.7, "Requester acceptance"](configuration.html#requester-acceptance) of [Configuration](configuration.html), and for
OpenID Connect `authn-server.oidc.requester-acceptance.*`, see
[Section 6.5, "Requester acceptance"](configuration.html#oidc-requester-acceptance) of [Configuration](configuration.html).

A predicate of your own is added with an adapter. A predicate that reads protocol metadata gets it from the record in
its own type:

```java
@Bean
AuthnServerConfigurerAdapter onlySwedishOrganisations() {
  return (http, configurer) -> configurer.configurableRequesterAcceptance().addPredicate(new RequesterPredicate() {

    @Override
    public AuthenticationProtocol getProtocol() {
      return AuthenticationProtocol.SAML;
    }

    @Override
    public boolean test(final RequesterRecord record, final ClientRegistry registry) {
      return record.organizationNumber() != null;
    }
  });
}
```

To replace the check altogether, assign another implementation with `configurer.requesterAcceptance(...)`.

[ClientRegistry]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/ClientRegistry.java
[ClientRegistryBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/ClientRegistryBackend.java
[ClientRegistryException]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/ClientRegistryException.java
[PairwiseClientCheck]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/PairwiseClientCheck.java
[ClientKeysRefresher]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ClientKeysRefresher.java
[ClientValidation]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ClientValidation.java
[ClientRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ClientRepository.java
[ConfigurableRequesterAcceptance]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/ConfigurableRequesterAcceptance.java
[ConfigurationClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ConfigurationClientBackend.java
[DefaultClientRegistry]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/DefaultClientRegistry.java
[EntityConfigurationEndpoints]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/EntityConfigurationEndpoints.java
[FederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationCache.java
[HeldKeysClientKeyResolver]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/HeldKeysClientKeyResolver.java
[ClientMetadataValidator]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ClientMetadataValidator.java
[FederationClientCollector]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationClientCollector.java
[FederationEntityStore]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationEntityStore.java
[FederationCacheSettings]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationCacheSettings.java
[FederationClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationClientBackend.java
[FederationResolver]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationResolver.java
[HttpClientKeysFetcher]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/HttpClientKeysFetcher.java
[HttpFederationClient]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/HttpFederationClient.java
[HttpFederationResolver]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/HttpFederationResolver.java
[InMemoryClientRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/InMemoryClientRepository.java
[InMemoryFederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/InMemoryFederationCache.java
[MetadataProviderFactory]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/MetadataProviderFactory.java
[MetadataSource]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/MetadataSource.java
[OidcClientReader]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/OidcClientReader.java
[OidcClientRecord]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/OidcClientRecord.java
[Requester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/Requester.java
[RequesterAcceptance]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequesterAcceptance.java
[RequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequesterPredicate.java
[RequiredMarksRequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequiredMarksRequesterPredicate.java
[RequesterRecord]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/RequesterRecord.java
[RedisFederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/RedisFederationCache.java
[RedisFederationEntityStore]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/RedisFederationEntityStore.java
[RepositoryClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/RepositoryClientBackend.java
[SamlMetadataBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/SamlMetadataBackend.java
[TrustMarkRequester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/TrustMarkRequester.java
[TrustMarkStatusChecker]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/TrustMarkStatusChecker.java
[WhitelistRequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/WhitelistRequesterPredicate.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
