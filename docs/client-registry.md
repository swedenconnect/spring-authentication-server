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

## Looking up a requester

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

## The record

A [`RequesterRecord`][RequesterRecord] holds a protocol-neutral part and the protocol metadata.

The protocol-neutral part is:

- The [`Requester`][Requester], that is, the protocol and the requester identity.
- The display names, one per language. A name without a language may appear, and at most one does.
- The logotypes, with a language where the metadata gives one, and a size where the metadata gives one.
- The marks that the requester holds.
- The organisation number of the requester, when its metadata gives one, see
  [The organisation number](#the-organisation-number).

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

### Marks

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
### The organisation number

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

## Backends

The registry itself holds no data. It asks its backends, and each backend answers for one protocol. Several backends
may serve the same protocol, in which case they are asked in the order they were given and the first one that knows
the requester wins. [`ClientRegistryBackend`][ClientRegistryBackend] is the interface, and
[`DefaultClientRegistry`][DefaultClientRegistry] is the registry that asks them.

## SAML: metadata sources

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
set with the `authn-server.saml.metadata-providers` properties, see [Configuration](configuration.html#sp-metadata).

## OpenID Connect: three backends

The OpenID Connect side has three backends. They are asked in a configured order, and the default order is
configuration, repository, federation.

- **Configuration** ([`ConfigurationClientBackend`][ConfigurationClientBackend]): the clients that the deployment
  gives the server directly.
- **Repository** ([`RepositoryClientBackend`][RepositoryClientBackend]): the clients of a
  [`ClientRepository`][ClientRepository]. The library ships [`InMemoryClientRepository`][InMemoryClientRepository];
  implementations backed by a database are added later.
- **Federation** ([`FederationClientBackend`][FederationClientBackend]): clients resolved through OpenID Federation.

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
[Client authentication](openid-provider.html#client-authentication).

## The federation backend

The federation backend resolves a client through OpenID Federation, where the `client_id` of the client is its entity
identifier. It is put together from a [`FederationResolver`][FederationResolver], a
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
resolver that is not the trust anchor are configured together with its endpoint. The record holds the client metadata
of the response, after the metadata policies of the trust chain have been applied by the resolver, and the trust mark
types of the response.

Resolving inside the OpenID Provider itself is a later addition. It arrives as another implementation of
`FederationResolver`, and nothing else changes.

### The cache

Resolved clients are cached, because reaching the resolver on every request is not an option.

- An entry lives until the expiry that the resolve response gives, or until an optional maximum age if that comes
  first. No maximum age is set by default.
- The store is pluggable, so that the nodes of a deployment can share it. The default is
  [`InMemoryFederationCache`][InMemoryFederationCache], which is what a single node needs.
  [`RedisFederationCache`][RedisFederationCache] keeps the entries in Redis, shared by all nodes.
- A client that the resolver does not know is cached as such for a short time, one minute by default, so that
  repeated requests with the same unknown `client_id` do not each reach the resolver. A resolver that fails is never
  cached.

### Keeping frequently used clients fresh

[`FederationCacheRefresher`][FederationCacheRefresher] is a background job that resolves a cached client again
shortly before its entry expires, so that a request from a client that is used often never waits for the resolver.
The job is off by default.

Only clients that are worth it are refreshed. A client qualifies once it has been looked up a configured number of
times within a configured period, and one run never refreshes more clients than a configured maximum. Clients that are
used rarely are left alone; they are resolved again the next time they are asked for after their entry has expired.
The count of lookups is bounded too: at most a configured number of clients are counted, and the client that has not
been asked for in the longest time is dropped when a new one arrives.

```java
FederationCacheSettings settings = new FederationCacheSettings(
    Duration.ofHours(12),
    Duration.ofMinutes(1),
    FederationCacheSettings.RefreshSettings.enabled(true));

FederationCacheRefresher refresher = new FederationCacheRefresher(cache, resolver, backend.getLookupTracker(),
    settings);
refresher.start();
```

### Trust marks on demand

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
  refresh of the record carries the trust mark over while it is still valid.
- A trust mark without `exp`, or with a long one, stays trusted after the issuer has withdrawn it, unless its status is
  checked, see [Checking the status of trust marks](#trust-mark-status-checks).

For SAML, asking for a mark never finds anything. It gives the requester's record unchanged.

<a name="trust-mark-status-checks"></a>
### Checking the status of trust marks

[`TrustMarkStatusChecker`][TrustMarkStatusChecker] is a background job that asks the issuer whether the trust marks
obtained on demand are still valid, at the issuer's trust mark status endpoint (OpenID Federation 1.0, Section 8.4).
It runs at a configurable interval, one hour by default:

```java
TrustMarkStatusChecker checker = new TrustMarkStatusChecker(cache, federation, new HttpFederationClient(),
    Duration.ofHours(1), Clock.systemUTC());
checker.setEventPublisher(applicationContext);
checker.start();
```

- A trust mark is checked when it has no `exp`, or when its `exp` is later than the next check. A trust mark that
  expires before the next check is not checked; it expires as before.
- The status endpoint of an issuer is configured together with the issuer, as `statusEndpoint` of
  `FederationSettings.TrustMarkIssuer`. The trust marks of an issuer without a status endpoint are not checked.
- The status response is verified with the keys of the issuer, and must be about the trust mark that was sent.
- A trust mark that the issuer reports as anything but `active`, such as `revoked` or `expired`, is removed from the
  client's cached record. A client that needs it for the [required marks](#requester-acceptance) is then treated as not
  holding it on its next request: the trust mark is asked for again, and when the issuer no longer issues it, the
  client is rejected with the same error response as any client that lacks a required mark. The removal is also
  published as a system alert for the audit log, when the checker has been given an event publisher, see
  [Auditing](audit.html#trust-mark-alerts).
- A status endpoint that cannot be reached, or a response that does not verify, leaves the trust mark in place. It is
  logged at `WARN`, and the trust mark is checked again at the next run.

The trust marks of the resolve response are not checked by the job. The resolver has checked them, and they are held
no longer than the resolve response is valid.

### Several nodes

The cache is also where the background jobs keep their shared state. The backend asks the cache for the object that
counts lookups, and the jobs ask it for the lock that decides which node runs a round. With a
`RedisFederationCache`:

- the lookup counts are kept in Redis, so that the threshold of the refresh applies to the traffic of all nodes, and
- each round of the refresh and of the [trust mark status checks](#trust-mark-status-checks) runs on one node. A node
  that stops while it holds the lock of a job blocks the job for at most one round.

With Spring Boot, a `FederationCache` bean is declared according to `authn-server.storage.type`, or
`authn-server.oidc.storage.federation-cache`, see [Running several nodes](configuration.html#running-several-nodes).
Build the backend and the jobs from it:

```java
@Bean
FederationClientBackend federationBackend(final FederationCache cache) {
  return new FederationClientBackend(new HttpFederationResolver(federation), new HttpTrustMarkRequester(federation),
      cache, settings);
}
```

<a name="requester-acceptance"></a>
## Deciding which requesters may use the server

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
  [Trust marks on demand](#trust-marks-on-demand), and evaluates the updated record before rejecting. For SAML nothing
  is obtained this way, so the Service Provider metadata decides.

With Spring Boot, the configurable check is set up from properties under each protocol's prefix, for SAML
`authn-server.saml.requester-acceptance.*`, see [Configuration](configuration.html#requester-acceptance), and for
OpenID Connect `authn-server.oidc.requester-acceptance.*`, see
[Configuration](configuration.html#oidc-requester-acceptance).

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
[ClientRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ClientRepository.java
[ConfigurableRequesterAcceptance]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/ConfigurableRequesterAcceptance.java
[ConfigurationClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/ConfigurationClientBackend.java
[DefaultClientRegistry]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/DefaultClientRegistry.java
[FederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationCache.java
[FederationCacheRefresher]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationCacheRefresher.java
[FederationCacheSettings]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationCacheSettings.java
[FederationClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationClientBackend.java
[FederationResolver]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/FederationResolver.java
[HttpFederationResolver]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/HttpFederationResolver.java
[InMemoryClientRepository]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/InMemoryClientRepository.java
[InMemoryFederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/InMemoryFederationCache.java
[MetadataProviderFactory]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/MetadataProviderFactory.java
[MetadataSource]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/MetadataSource.java
[OidcClientRecord]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/OidcClientRecord.java
[Requester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/authentication/Requester.java
[RequesterAcceptance]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequesterAcceptance.java
[RequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequesterPredicate.java
[RequiredMarksRequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/RequiredMarksRequesterPredicate.java
[RequesterRecord]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/RequesterRecord.java
[RedisFederationCache]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/RedisFederationCache.java
[RepositoryClientBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/RepositoryClientBackend.java
[SamlMetadataBackend]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-saml/src/main/java/se/swedenconnect/spring/authnserver/saml/metadata/SamlMetadataBackend.java
[TrustMarkRequester]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/TrustMarkRequester.java
[TrustMarkStatusChecker]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-oidc/src/main/java/se/swedenconnect/spring/authnserver/oidc/client/federation/TrustMarkStatusChecker.java
[WhitelistRequesterPredicate]: https://github.com/swedenconnect/spring-authentication-server/blob/main/authn-server-core/src/main/java/se/swedenconnect/spring/authnserver/registry/acceptance/WhitelistRequesterPredicate.java

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
