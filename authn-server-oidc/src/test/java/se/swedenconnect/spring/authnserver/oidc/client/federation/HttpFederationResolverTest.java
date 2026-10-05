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
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
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

}
