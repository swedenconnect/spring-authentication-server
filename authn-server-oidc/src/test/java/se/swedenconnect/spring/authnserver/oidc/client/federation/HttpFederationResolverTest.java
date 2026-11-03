/*
 * Copyright 2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link HttpFederationResolver}.
 *
 * @author Martin Lindström
 */
class HttpFederationResolverTest extends FederationTestSupport {

  private static final URI RESOLVE_ENDPOINT = URI.create("https://resolver.example.com/resolve");

  @Test
  void aResponseSignedByTheTrustAnchorIsAccepted() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);
    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID,
        clientMetadata("The Client"), Set.of(MARK_ONE, MARK_TWO), expiresAt);

    final ResolvedClient resolved = new HttpFederationResolver(settings, client).resolve(CLIENT_ID);

    assertThat(resolved).isNotNull();
    assertThat(resolved.clientId()).isEqualTo(CLIENT_ID);
    assertThat(resolved.metadata().getName()).isEqualTo("The Client");
    assertThat(resolved.trustMarkTypes()).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);
    assertThat(resolved.expiresAt()).isEqualTo(expiresAt);
    assertThat(client.lastResolveRequest.subject()).isEqualTo(CLIENT_ID);
    assertThat(client.lastResolveRequest.trustAnchor()).isEqualTo(TRUST_ANCHOR);
    assertThat(client.lastResolveRequest.types()).containsExactly("openid_relying_party");
  }

  @Test
  void theOrganisationIdentifierOfTheResolvedMetadataReachesTheRecord() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final OIDCClientMetadata metadata = clientMetadata("The Client");
    metadata.setCustomField(OidcClientRecord.ORGANIZATION_IDENTIFIER, "urn:glue:iso6523:0007:5566778899");
    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID, metadata, Set.of(),
        Instant.now().plus(1, ChronoUnit.HOURS));
    final HttpFederationResolver resolver = new HttpFederationResolver(settings, client);

    final FederationClientBackend backend = new FederationClientBackend(resolver, (id, type) -> null,
        new InMemoryFederationCache(), FederationCacheSettings.defaults());
    assertThat(backend.lookup(CLIENT_ID).organizationNumber()).isEqualTo("urn:glue:iso6523:0007:5566778899");
    // From the cache
    assertThat(backend.lookup(CLIENT_ID).organizationNumber()).isEqualTo("urn:glue:iso6523:0007:5566778899");

    client.resolveResponse = resolveResponse(trustAnchorKey, TRUST_ANCHOR, "https://other.example.com",
        clientMetadata("Other"), Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));
    assertThat(backend.lookup("https://other.example.com").organizationNumber()).isNull();
  }

  @Test
  void aResponseSignedBySeparatelyConfiguredResolverKeysIsAccepted() {
    final ECKey trustAnchorKey = key("ta");
    final ECKey resolverKey = key("resolver");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(RESOLVER, RESOLVE_ENDPOINT, publicKeys(resolverKey)));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(resolverKey, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));

    assertThat(new HttpFederationResolver(settings, client).resolve(CLIENT_ID)).isNotNull();
  }

  @Test
  void aResponseWithABadSignatureIsRejected() {
    final ECKey trustAnchorKey = key("ta");
    final ECKey otherKey = key("other");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(otherKey, TRUST_ANCHOR, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));

    assertThatThrownBy(() -> new HttpFederationResolver(settings, client).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aResponseSignedByTheResolverIsRejectedWhenTheTrustAnchorKeysAreExpected() {
    final ECKey trustAnchorKey = key("ta");
    final ECKey resolverKey = key("resolver");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(RESOLVER, RESOLVE_ENDPOINT, publicKeys(resolverKey)));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(trustAnchorKey, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));

    assertThatThrownBy(() -> new HttpFederationResolver(settings, client).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aResponseForAnotherSubjectOrIssuerIsRejected() {
    final ECKey key = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));
    final Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);

    final StubFederationClient wrongSubject = new StubFederationClient();
    wrongSubject.resolveResponse = resolveResponse(key, TRUST_ANCHOR, "https://other.example.com",
        clientMetadata("Other"), Set.of(), expiresAt);
    assertThatThrownBy(() -> new HttpFederationResolver(settings, wrongSubject).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);

    final StubFederationClient wrongIssuer = new StubFederationClient();
    wrongIssuer.resolveResponse = resolveResponse(key, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), expiresAt);
    assertThatThrownBy(() -> new HttpFederationResolver(settings, wrongIssuer).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aResponseThatHasExpiredIsRejected() {
    final ECKey key = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(key, TRUST_ANCHOR, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().minus(1, ChronoUnit.HOURS));

    assertThatThrownBy(() -> new HttpFederationResolver(settings, client).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aResponseWithAnotherExplicitTypeIsRejected() {
    final ECKey key = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = sign(key, "entity-statement+jwt", new JWTClaimsSet.Builder()
        .issuer(TRUST_ANCHOR)
        .subject(CLIENT_ID)
        .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
        .claim("metadata", Map.of("openid_relying_party", new OIDCClientMetadata().toJSONObject()))
        .build());

    assertThatThrownBy(() -> new HttpFederationResolver(settings, client).resolve(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aClientThatTheResolverDoesNotKnowIsNotAnError() {
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    assertThat(new HttpFederationResolver(settings, new StubFederationClient()).resolve(CLIENT_ID)).isNull();
  }

  @Test
  void anEntityThatIsNotARelyingPartyIsNotAClient() {
    final ECKey key = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));

    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(key, TRUST_ANCHOR, CLIENT_ID, null, Set.of(),
        Instant.now().plus(1, ChronoUnit.HOURS));

    assertThat(new HttpFederationResolver(settings, client).resolve(CLIENT_ID)).isNull();
  }

  @Test
  void anEntityIsResolvedAskingForBothEntityTypes() {
    final ECKey trustAnchorKey = key("ta");
    final StubFederationClient client = new StubFederationClient();
    final HttpFederationResolver resolver = new HttpFederationResolver(this.trustAnchorSettings(trustAnchorKey),
        client);
    final Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);

    // An intermediate that is also a client
    client.resolveResponse = this.entityResponse(trustAnchorKey, CLIENT_ID, Map.of(
        EntityType.OPENID_RELYING_PARTY.getValue(), clientMetadata("The Client").toJSONObject(),
        EntityType.FEDERATION_ENTITY.getValue(), Map.of("federation_list_endpoint", "https://client.example.com/list")),
        expiresAt);
    final ResolvedEntity entity = resolver.resolveEntity(CLIENT_ID);
    assertThat(client.lastResolveRequest.types()).containsExactly("openid_relying_party", "federation_entity");
    assertThat(client.lastResolveRequest.trustAnchor()).isEqualTo(TRUST_ANCHOR);
    assertThat(entity).isNotNull();
    assertThat(entity.clientMetadata().getName()).isEqualTo("The Client");
    assertThat(entity.listEndpoint()).isEqualTo("https://client.example.com/list");
    assertThat(entity.expiresAt()).isEqualTo(expiresAt);
    assertThat(entity.toClient()).isNotNull();

    // A federation entity without a list endpoint, such as a trust mark issuer
    client.resolveResponse = this.entityResponse(trustAnchorKey, CLIENT_ID, Map.of(
        EntityType.FEDERATION_ENTITY.getValue(), Map.of("federation_trust_mark_endpoint", "https://x/tm")),
        expiresAt);
    assertThat(resolver.resolveEntity(CLIENT_ID)).isNotNull()
        .satisfies(e -> assertThat(e.clientMetadata()).isNull())
        .satisfies(e -> assertThat(e.listEndpoint()).isNull())
        .satisfies(e -> assertThat(e.toClient()).isNull());

    // An entity with none of the types asked for is the same as not found
    client.resolveResponse = this.entityResponse(trustAnchorKey, CLIENT_ID, Map.of(
        EntityType.OPENID_PROVIDER.getValue(), Map.of("issuer", CLIENT_ID)), expiresAt);
    assertThat(resolver.resolveEntity(CLIENT_ID)).isNull();

    client.resolveResponse = null;
    assertThat(resolver.resolveEntity(CLIENT_ID)).isNull();
  }

  @Test
  void aResolvedEntityIsVerifiedAsAClientIs() {
    final ECKey trustAnchorKey = key("ta");
    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = this.entityResponse(key("other"), CLIENT_ID, Map.of(
        EntityType.FEDERATION_ENTITY.getValue(), Map.of("federation_list_endpoint", "https://x/list")),
        Instant.now().plus(1, ChronoUnit.HOURS));

    assertThatThrownBy(() -> new HttpFederationResolver(this.trustAnchorSettings(trustAnchorKey), client)
        .resolveEntity(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void theDefaultResolutionOfAnEntityResolvesItAsAClient() {
    final ResolvedClient resolved =
        new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(MARK_ONE), Instant.now());
    final FederationResolver resolver = clientId -> CLIENT_ID.equals(clientId) ? resolved : null;

    assertThat(resolver.resolveEntity(CLIENT_ID)).isNotNull().satisfies(e -> {
      assertThat(e.listEndpoint()).isNull();
      assertThat(e.toClient()).isEqualTo(resolved);
    });
    assertThat(resolver.resolveEntity("https://other.example.com")).isNull();
  }

  private FederationSettings trustAnchorSettings(final ECKey trustAnchorKey) {
    return FederationSettings.of(new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));
  }

  private SignedJWT entityResponse(final ECKey key, final String subject, final Map<String, Object> metadata,
      final Instant expiresAt) {
    return sign(key, HttpFederationResolver.RESOLVE_RESPONSE_TYPE, new JWTClaimsSet.Builder()
        .issuer(TRUST_ANCHOR)
        .subject(subject)
        .issueTime(new Date())
        .expirationTime(Date.from(expiresAt))
        .claim("metadata", metadata)
        .build());
  }

  @Test
  void keysAreRequiredForAResolverThatIsNotTheTrustAnchor() {
    assertThatThrownBy(() -> FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(RESOLVER, RESOLVE_ENDPOINT, null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(RESOLVER);
  }

  @Test
  void aConfiguredResolveEndpointIsUsedWithoutFetchingAnything() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));
    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = resolveResponse(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));

    assertThat(new HttpFederationResolver(settings, client).resolve(CLIENT_ID)).isNotNull();
    assertThat(client.lastResolveEndpoint).isEqualTo(RESOLVE_ENDPOINT.toString());
    assertThat(client.entityConfigurationRequests).isEmpty();
  }

  @Test
  void aResolverAtTheTrustAnchorWithoutAnEndpointUsesThePublishedOne() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, null, null));
    final StubFederationClient client = new StubFederationClient();
    client.entityConfigurations.put(TRUST_ANCHOR, entityConfiguration(trustAnchorKey, TRUST_ANCHOR,
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "https://ta.example.com/published-resolve"),
        Instant.now().plus(1, ChronoUnit.HOURS)));
    client.resolveResponse = resolveResponse(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));
    final HttpFederationResolver resolver = new HttpFederationResolver(settings, client);

    assertThat(resolver.resolve(CLIENT_ID)).isNotNull();
    assertThat(resolver.resolve(CLIENT_ID)).isNotNull();
    assertThat(client.lastResolveEndpoint).isEqualTo("https://ta.example.com/published-resolve");
    assertThat(client.entityConfigurationRequests).containsExactly(TRUST_ANCHOR);
  }

  @Test
  void aStandaloneResolverWithoutAnEndpointIsVerifiedWithItsOwnKeys() {
    final ECKey trustAnchorKey = key("ta");
    final ECKey resolverKey = key("resolver");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(RESOLVER, null, publicKeys(resolverKey)));
    final StubFederationClient client = new StubFederationClient();
    client.entityConfigurations.put(RESOLVER, entityConfiguration(resolverKey, RESOLVER,
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "https://resolver.example.com/published"),
        Instant.now().plus(1, ChronoUnit.HOURS)));
    client.resolveResponse = resolveResponse(resolverKey, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));

    assertThat(new HttpFederationResolver(settings, client).resolve(CLIENT_ID)).isNotNull();
    assertThat(client.lastResolveEndpoint).isEqualTo("https://resolver.example.com/published");
  }

  @Test
  void aResolverThatCannotBeFoundFailsTheResolutionWithoutCachingIt() {
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, null, null));
    final StubFederationClient client = new StubFederationClient();
    final FederationClientBackend backend = new FederationClientBackend(new HttpFederationResolver(settings, client),
        (id, type) -> null, new InMemoryFederationCache(), FederationCacheSettings.defaults());

    assertThatThrownBy(() -> backend.lookup(CLIENT_ID)).isInstanceOf(ClientRegistryException.class);
    assertThatThrownBy(() -> backend.lookup(CLIENT_ID)).isInstanceOf(ClientRegistryException.class);
    assertThat(client.resolveCalls).isZero();
    assertThat(client.entityConfigurationRequests).containsExactly(TRUST_ANCHOR, TRUST_ANCHOR);
  }

  @Test
  void relyingPartyMetadataThatCannotBeParsedGivesAClientWithTheReason() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));
    final StubFederationClient client = new StubFederationClient();
    client.resolveResponse = sign(trustAnchorKey, HttpFederationResolver.RESOLVE_RESPONSE_TYPE,
        resolveClaims(CLIENT_ID, Map.of(
            EntityType.OPENID_RELYING_PARTY.getValue(), Map.of("redirect_uris", "not a list"),
            EntityType.FEDERATION_ENTITY.getValue(), Map.of("federation_list_endpoint", CLIENT_ID + "/list")))
            .build());
    final HttpFederationResolver resolver = new HttpFederationResolver(settings, client);

    final ResolvedClient resolved = resolver.resolve(CLIENT_ID);
    assertThat(resolved).isNotNull();
    assertThat(resolved.metadataError()).contains("redirect_uris");
    assertThat(resolved.metadata().toJSONObject()).isEmpty();

    // An entity with such metadata is still walked into
    final ResolvedEntity entity = resolver.resolveEntity(CLIENT_ID);
    assertThat(entity).isNotNull();
    assertThat(entity.listEndpoint()).isEqualTo(CLIENT_ID + "/list");
    assertThat(entity.toClient()).isNotNull().satisfies(c -> assertThat(c.metadataError()).contains("redirect_uris"));

    // Relying party metadata that is not an object
    client.resolveResponse = sign(trustAnchorKey, HttpFederationResolver.RESOLVE_RESPONSE_TYPE,
        resolveClaims(CLIENT_ID, Map.of(EntityType.OPENID_RELYING_PARTY.getValue(), "not an object")).build());
    assertThat(resolver.resolve(CLIENT_ID).metadataError()).isEqualTo(
        "the openid_relying_party metadata is not a JSON object");

    // At the backend, the client is marked as invalid and the lookup does not fail
    final FederationClientBackend backend = new FederationClientBackend(resolver, (id, type) -> null,
        new InMemoryFederationCache(), FederationCacheSettings.defaults());
    assertThat(backend.lookup(CLIENT_ID).invalidReason()).startsWith("the metadata cannot be parsed");
  }

  @Test
  void theFederationEntityKeysAreTakenFromTheTrustChain() {
    final ECKey trustAnchorKey = key("ta");
    final ECKey entityKey = key("entity");
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null));
    final StubFederationClient client = new StubFederationClient();
    final HttpFederationResolver resolver = new HttpFederationResolver(settings, client);
    final Map<String, Object> metadata =
        Map.of(EntityType.OPENID_RELYING_PARTY.getValue(), clientMetadata("RP").toJSONObject());
    final String configuration = this.entityStatement(entityKey, CLIENT_ID, CLIENT_ID);
    final String subordinate = this.entityStatement(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID);

    client.resolveResponse = sign(trustAnchorKey, HttpFederationResolver.RESOLVE_RESPONSE_TYPE,
        resolveClaims(CLIENT_ID, metadata).claim("trust_chain", List.of(configuration, subordinate)).build());
    assertThat(resolver.resolve(CLIENT_ID).entityKeys()).isNotNull()
        .satisfies(k -> assertThat(k.getKeyByKeyId(entityKey.getKeyID())).isNotNull());
    assertThat(resolver.resolveEntity(CLIENT_ID).entityKeys()).isNotNull();

    // No trust_chain, one that does not start with the entity configuration, and one that cannot be read
    for (final Object chain : Arrays.asList(null, List.of(subordinate), List.of("not a JWT"), List.of())) {
      final JWTClaimsSet.Builder claims = resolveClaims(CLIENT_ID, metadata);
      if (chain != null) {
        claims.claim("trust_chain", chain);
      }
      client.resolveResponse = sign(trustAnchorKey, HttpFederationResolver.RESOLVE_RESPONSE_TYPE, claims.build());
      assertThat(resolver.resolve(CLIENT_ID).entityKeys()).as(String.valueOf(chain)).isNull();
    }
  }

  private static JWTClaimsSet.Builder resolveClaims(final String subject, final Map<String, Object> metadata) {
    return new JWTClaimsSet.Builder()
        .issuer(TRUST_ANCHOR)
        .subject(subject)
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
        .claim("metadata", metadata);
  }

  private String entityStatement(final ECKey key, final String issuer, final String subject) {
    return sign(key, "entity-statement+jwt", new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
        .claim("jwks", publicKeys(key).toJSONObject())
        .build()).serialize();
  }

}
