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

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.events.ClientInvalidEvent;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;

/**
 * Tests for the validation of federation clients, and the keys that they hold, when a {@link FederationClientBackend}
 * resolves them at a request or at the operator's re-resolve. The {@link FederationClientCollector} is tested in
 * {@link FederationClientCollectorTest}.
 *
 * @author Martin Lindström
 */
class FederationClientMetadataTest extends FederationTestSupport {

  private static final String JWKS_URI = "https://client.example.com/jwks";

  private static final Duration TEMPORARY = Duration.ofMinutes(5);

  private static final Duration VALIDITY = Duration.ofHours(1);

  private static final ECKey ROLLED_KEY = key("rolled-key");

  private final StubClientKeysFetcher fetcher = new StubClientKeysFetcher();

  private final List<ApplicationEvent> events = new ArrayList<>();

  private FederationClientBackendTest.Fixture fixture;

  @BeforeEach
  void setUp() {
    this.events.clear();
    this.fetcher.calls.clear();
    this.fixture = new FederationClientBackendTest.Fixture(new FederationCacheSettings(null, TEMPORARY));
    this.fixture.backend.setValidator(new FederationClientValidator(new PairwiseClientCheck(null), this.fetcher));
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.start();
    this.fixture.backend.setClientChangeTracker(tracker);
  }

  // Faults

  @Test
  void eachFaultMarksTheClientUntilItIsResolvedAgainAtARequestAndAtTheOperatorsReResolve() {
    for (final Map.Entry<String, Supplier<ResolvedClient>> fault : this.faults().entrySet()) {
      this.setUp();
      this.fixture.resolver.answer = fault.getValue().get();

      // At a request
      final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);
      assertThat(record).as(fault.getKey()).isNotNull();
      assertThat(record.isValid()).as(fault.getKey()).isFalse();
      assertThat(record.invalidReason()).as(fault.getKey()).contains(fault.getKey());
      assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt()).as(fault.getKey())
          .isEqualTo(this.fixture.clock.instant().plus(VALIDITY));
      assertThat(this.invalidEvents()).as(fault.getKey()).containsExactly(record.invalidReason());

      // Shown in the list of clients with its reason
      final RegisteredClient registered = this.fixture.backend.getClient(CLIENT_ID);
      assertThat(registered).as(fault.getKey()).isNotNull();
      assertThat(registered.invalidReason()).as(fault.getKey()).isEqualTo(record.invalidReason());

      // At the operator's re-resolve
      assertThat(this.fixture.backend.update(CLIENT_ID).message()).as(fault.getKey()).contains("marked as invalid");
      assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).as(fault.getKey()).isFalse();
      assertThat(this.invalidEvents()).as(fault.getKey()).hasSize(2);
    }
  }

  @Test
  void aClientWhoseMetadataCannotBeParsedIsShownWithItsClientIdAndReason() {
    this.fixture.resolver.answer = this.unparsable();

    final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);

    assertThat(record.isValid()).isFalse();
    assertThat(record.getProtocolMetadata(OIDCClientMetadata.class).getRedirectionURIs()).isNull();
    assertThat(this.fixture.backend.getClients()).singleElement().satisfies(c -> {
      assertThat(c.requester().identifier()).isEqualTo(CLIENT_ID);
      assertThat(c.invalidReason()).startsWith("the metadata cannot be parsed");
    });
    assertThat(this.fixture.backend.getMetadata(CLIENT_ID)).isNull();
  }

  @Test
  void aFixedClientIsValidWhenItIsResolvedAgain() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setTokenEndpointAuthMethod(null);
    this.fixture.resolver.answer = this.resolved(metadata);
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();

    this.fixture.resolver.answer = this.resolved(clientMetadata("RP"));
    assertThat(this.fixture.backend.update(CLIENT_ID).outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isTrue();
  }

  // How long a mark lasts

  @Test
  void keysThatCannotBeFetchedMarkTheClientForTheNotFoundTime() {
    this.fixture.resolver.answer = this.resolved(jwksUriClient());

    assertThat(this.fixture.backend.lookup(CLIENT_ID).invalidReason())
        .isEqualTo("the keys at the jwks_uri cannot be fetched - HTTP status 503");
    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(this.fixture.clock.instant().plus(TEMPORARY));

    // Within the time, the client stays invalid and nothing is fetched
    this.fixture.clock.advance(TEMPORARY.minusSeconds(1));
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fetcher.calls).hasSize(1);

    // Then it is resolved and checked again at its next request
    this.fixture.clock.advance(Duration.ofSeconds(2));
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fixture.resolver.calls).isEqualTo(2);
    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void heldKeysAreKeptWhenALaterFetchFails() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    this.fixture.backend.lookup(CLIENT_ID);

    this.fetcher.jwks.clear();
    this.fixture.backend.update(CLIENT_ID);

    final CachedClientRecord entry = this.fixture.cache.get(CLIENT_ID);
    assertThat(entry.isValid()).isTrue();
    assertThat(entry.heldKeys().keys().getKeyByKeyId(CLIENT_KEY.getKeyID())).isNotNull();
    assertThat(entry.expiresAt()).isEqualTo(this.fixture.clock.instant().plus(VALIDITY));
    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void unusableKeysAreALastingFault() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    final OIDCClientMetadata metadata = jwksUriClient();
    metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.RS256);
    this.fixture.resolver.answer = this.resolved(metadata);

    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(this.fixture.clock.instant().plus(VALIDITY));
  }

  // Held keys

  @Test
  void theHeldKeysAreUsedWithoutAFetch() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    final OIDCClientMetadata metadata = this.lookupMetadata();
    assertThat(this.fetcher.calls).hasSize(1);

    for (int i = 0; i < 3; i++) {
      assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher(CLIENT_KEY.getKeyID())))
          .singleElement().satisfies(k -> assertThat(k.getKeyID()).isEqualTo(CLIENT_KEY.getKeyID()));
    }
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void aJwtNamingAnUnknownKeyMakesTheClientsKeysBeFetchedAgain() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    final OIDCClientMetadata metadata = this.lookupMetadata();

    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY, ROLLED_KEY));
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher(ROLLED_KEY.getKeyID())))
        .singleElement().satisfies(k -> assertThat(k.getKeyID()).isEqualTo(ROLLED_KEY.getKeyID()));
    assertThat(this.fetcher.calls).hasSize(2);

    // The new keys are held
    assertThat(this.fixture.cache.get(CLIENT_ID).heldKeys().keys().getKeyByKeyId(ROLLED_KEY.getKeyID())).isNotNull();
    this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher(ROLLED_KEY.getKeyID()));
    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void theKeysOfAClientAreFetchedAgainAtMostOncePerMinute() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    final OIDCClientMetadata metadata = this.lookupMetadata();

    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher("made-up-1"))).isEmpty();
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher("made-up-2"))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(2);

    this.fixture.clock.advance(FederationClientBackend.KEY_REFRESH_INTERVAL.minusSeconds(1));
    this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher("made-up-3"));
    assertThat(this.fetcher.calls).hasSize(2);

    this.fixture.clock.advance(Duration.ofSeconds(1));
    this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher("made-up-4"));
    assertThat(this.fetcher.calls).hasSize(3);

    // Without a key identifier, nothing is fetched
    this.fixture.clock.advance(Duration.ofMinutes(2));
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata,
        new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build())).isEmpty();
    assertThat(this.fetcher.calls).hasSize(3);
  }

  @Test
  void keysFetchedAgainThatDoNotPassTheChecksAreNotUsed() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    final OIDCClientMetadata es256 = jwksUriClient();
    es256.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256);
    this.fixture.resolver.answer = this.resolved(es256);
    final OIDCClientMetadata metadata = this.lookupMetadata();

    // A P-384 key cannot be used for ES256
    final ECKey p384 = ecKey384("p384-key");
    this.fetcher.jwks.put(JWKS_URI, new JWKSet(p384.toPublicJWK()));
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, metadata, matcher(p384.getKeyID()))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(2);
    assertThat(this.fixture.cache.get(CLIENT_ID).heldKeys().keys().getKeys()).singleElement()
        .satisfies(k -> assertThat(k.getKeyID()).isEqualTo(CLIENT_KEY.getKeyID()));
  }

  @Test
  void theKeysOfAClientMarkedAsInvalidAreNotFetchedAgain() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    final OIDCClientMetadata pairwise = pairwiseMetadata("RP", null, "https://a.example.com/cb",
        "https://b.example.com/cb");
    pairwise.setJWKSet(null);
    pairwise.setJWKSetURI(URI.create(JWKS_URI));
    this.fixture.resolver.answer = this.resolved(pairwise);

    final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);
    assertThat(record.isValid()).isFalse();
    final OIDCClientMetadata held = record.getProtocolMetadata(OIDCClientMetadata.class);

    // The held keys are given, so that a request object can still be read, but no new fetch is made
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, held, matcher(CLIENT_KEY.getKeyID()))).hasSize(1);
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, held, matcher("made-up"))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void onlyACachedClientWhoseKeysComeFromTheSameUriIsServed() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    this.fixture.backend.lookup(CLIENT_ID);

    final OIDCClientMetadata other = jwksUriClient();
    other.setJWKSetURI(URI.create("https://other.example.com/jwks"));
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, other, matcher(CLIENT_KEY.getKeyID()))).isNull();
    assertThat(this.fixture.backend.resolveKeys(CLIENT_ID, clientMetadata("RP"), matcher(CLIENT_KEY.getKeyID())))
        .isNull();
    assertThat(this.fixture.backend.resolveKeys("https://unknown.example.com", jwksUriClient(),
        matcher(CLIENT_KEY.getKeyID()))).isNull();
  }

  @Test
  void theKeyResolverGivesHeldKeysAndAsksTheDelegateForOtherClients() throws Exception {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    this.fixture.resolver.answer = this.resolved(jwksUriClient());
    final OIDCClientMetadata metadata = this.lookupMetadata();
    final List<String> delegated = new ArrayList<>();
    final ClientKeyResolver delegate = (clientId, m, matcher) -> {
      delegated.add(clientId);
      return List.of();
    };
    final FederationClientKeyResolver resolver =
        new FederationClientKeyResolver(List.of(this.fixture.backend), delegate);

    final List<JWK> keys = resolver.resolve(CLIENT_ID, metadata,
        new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(CLIENT_KEY.getKeyID()).build());
    assertThat(keys).hasSize(1);
    assertThat(delegated).isEmpty();

    resolver.resolve("https://configured.example.com", clientMetadata("RP"), matcher(CLIENT_KEY.getKeyID()));
    assertThat(delegated).containsExactly("https://configured.example.com");
    assertThat(resolver.getDelegate()).isSameAs(delegate);
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void theHeldKeysSurviveTheStoredForm() throws Exception {
    final HeldKeys held = new HeldKeys(JWKS_URI, true, publicKeys(CLIENT_KEY), publicKeys(ROLLED_KEY));
    final CachedClientRecord record = new CachedClientRecord(CLIENT_ID, jwksUriClient(), Set.of(), Map.of(),
        this.fixture.clock.instant(), null, null, held);

    final CachedClientRecord read = StoredClientRecord.of(record).toRecord();

    assertThat(read.heldKeys().uri()).isEqualTo(JWKS_URI);
    assertThat(read.heldKeys().signed()).isTrue();
    assertThat(read.heldKeys().keys().toJSONObject()).isEqualTo(held.keys().toJSONObject());
    assertThat(read.heldKeys().entityKeys().toJSONObject()).isEqualTo(held.entityKeys().toJSONObject());
    assertThat(read.withTrustMark(MARK_ONE, null).heldKeys()).isEqualTo(read.heldKeys());

    // An entry without keys
    assertThat(StoredClientRecord.of(record.withHeldKeys(null)).toRecord().heldKeys()).isNull();
  }

  @Test
  void theParseErrorAndTheFederationEntityKeysSurviveTheStoredEntityForm() throws Exception {
    final FederationEntityRecord record = FederationEntityRecord.found(new ResolvedEntity(CLIENT_ID,
        new OIDCClientMetadata(), CLIENT_ID + "/list", Set.of(), this.fixture.clock.instant().plus(VALIDITY),
        "Unexpected type of redirect_uris", publicKeys(ROLLED_KEY)), this.fixture.clock.instant(), null);

    final ResolvedClient client = StoredEntityRecord.of(record).toRecord().toClient();

    assertThat(client).isNotNull();
    assertThat(client.metadataError()).isEqualTo("Unexpected type of redirect_uris");
    assertThat(client.entityKeys().getKeyByKeyId(ROLLED_KEY.getKeyID())).isNotNull();
  }

  private Map<String, Supplier<ResolvedClient>> faults() {
    final Map<String, Supplier<ResolvedClient>> faults = new LinkedHashMap<>();
    faults.put("the metadata cannot be parsed", this::unparsable);
    faults.put("no redirect_uris", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setRedirectionURIs(null);
      return this.resolved(m);
    });
    faults.put("the default client_secret_basic needs a client secret", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setTokenEndpointAuthMethod(null);
      return this.resolved(m);
    });
    faults.put("token_endpoint_auth_method is none", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
      return this.resolved(m);
    });
    faults.put("the request_object_signing_alg HS256 is not supported", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setRequestObjectJWSAlg(JWSAlgorithm.HS256);
      return this.resolved(m);
    });
    faults.put("keys are needed for private_key_jwt", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setJWKSet(null);
      return this.resolved(m);
    });
    faults.put("the jwks_uri does not use https", () -> {
      final OIDCClientMetadata m = jwksUriClient();
      m.setJWKSetURI(URI.create("http://client.example.com/jwks"));
      return this.resolved(m);
    });
    faults.put("hold no usable key for private_key_jwt", () -> {
      final OIDCClientMetadata m = clientMetadata("RP");
      m.setTokenEndpointAuthJWSAlg(JWSAlgorithm.RS256);
      return this.resolved(m);
    });
    faults.put("no usable trust_chain", () -> {
      final OIDCClientMetadata m = jwksUriClient();
      m.setJWKSetURI(null);
      m.setSignedJWKSetURI(URI.create("https://client.example.com/signed-jwks"));
      return this.resolved(m);
    });
    return faults;
  }

  private ResolvedClient unparsable() {
    return new ResolvedClient(CLIENT_ID, new OIDCClientMetadata(), Set.of(),
        this.fixture.clock.instant().plus(VALIDITY), "Unexpected type of redirect_uris", null);
  }

  private ResolvedClient resolved(final OIDCClientMetadata metadata) {
    return new ResolvedClient(CLIENT_ID, metadata, Set.of(), this.fixture.clock.instant().plus(VALIDITY));
  }

  private OIDCClientMetadata lookupMetadata() {
    final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);
    assertThat(record.isValid()).isTrue();
    return record.getProtocolMetadata(OIDCClientMetadata.class);
  }

  private List<String> invalidEvents() {
    return this.events.stream()
        .filter(ClientInvalidEvent.class::isInstance)
        .map(e -> ((ClientInvalidEvent) e).getReason())
        .toList();
  }

  private static OIDCClientMetadata jwksUriClient() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setJWKSet(null);
    metadata.setJWKSetURI(URI.create(JWKS_URI));
    return metadata;
  }

  private static JWKMatcher matcher(final String keyId) {
    return JWKMatcher.forJWSHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build());
  }

  private static ECKey ecKey384(final String keyId) {
    try {
      return new ECKeyGenerator(Curve.P_384).keyID(keyId).generate();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
