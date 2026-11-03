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
package se.swedenconnect.spring.authnserver.oidc.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.ApplicationEvent;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.events.ClientInvalidEvent;
import se.swedenconnect.spring.authnserver.job.JobLock;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;

/**
 * Tests for the validation of the clients of {@link ConfigurationClientBackend} and {@link RepositoryClientBackend},
 * see {@link ClientValidation}, and for the {@link ClientKeysRefresher}.
 *
 * @author Martin Lindström
 */
class ClientValidationTest extends ClientTestSupport {

  private static final Duration TEMPORARY = Duration.ofMinutes(5);

  private final StubKeysFetcher fetcher = new StubKeysFetcher();

  private final TestClock clock = new TestClock();

  private final InMemoryClientValidationStore store = new InMemoryClientValidationStore();

  private final List<ApplicationEvent> events = new ArrayList<>();

  private ClientChangeTracker tracker;

  @BeforeEach
  void setup() {
    this.tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    this.tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    this.tracker.start();
  }

  private ClientValidation validation(final String source) {
    return new ClientValidation(source, new ClientMetadataValidator(new PairwiseClientCheck(null), this.fetcher),
        this.store, TEMPORARY, this.clock);
  }

  // The faults, for both backends

  static Stream<Arguments> faults() {
    final Map<String, Consumer<OIDCClientMetadata>> faults = Map.ofEntries(
        Map.entry("the metadata has no redirect_uris", m -> m.setRedirectionURIs(null)),
        Map.entry("the response_types do not include code", m -> m.setResponseTypes(
            new HashSet<>(List.of(ResponseType.IDTOKEN)))),
        Map.entry("the grant_types do not include authorization_code",
            m -> m.setGrantTypes(new HashSet<>(List.of(GrantType.CLIENT_CREDENTIALS)))),
        Map.entry("the token_endpoint_auth_method is none, which is not supported",
            m -> m.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE)),
        Map.entry("client_secret_post needs a client secret, which the client does not have",
            m -> m.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)),
        Map.entry("the request_object_signing_alg HS256 is not supported",
            m -> m.setRequestObjectJWSAlg(JWSAlgorithm.HS256)),
        Map.entry("the id_token_encrypted_response_alg RSA1_5 is not supported",
            m -> m.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5)),
        Map.entry("the jwks_uri does not use https", m -> m.setJWKSetURI(URI.create("http://client.example.com/jwks"))),
        Map.entry("there is no jwks or jwks_uri, and keys are needed for private_key_jwt", m -> m.setJWKSetURI(null)),
        Map.entry("there is only a signed_jwks_uri", m -> {
          m.setJWKSetURI(null);
          m.setSignedJWKSetURI(URI.create(CLIENT_ID + "/signed-jwks"));
        }),
        Map.entry("the keys of the jwks_uri hold no usable key for private_key_jwt",
            m -> m.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256)),
        Map.entry("the redirect_uris have 2 different hosts and there is no sector_identifier_uri", m -> {
          m.setSubjectType(SubjectType.PAIRWISE);
          m.setRedirectionURIs(Set.of(URI.create(REDIRECT_URI), URI.create("https://other.example.com/cb")));
        }));
    return faults.entrySet().stream()
        .flatMap(e -> Stream.of(Arguments.of("configuration", e.getKey(), e.getValue()),
            Arguments.of("repository", e.getKey(), e.getValue())));
  }

  @ParameterizedTest(name = "{0}: {1}")
  @MethodSource("faults")
  void eachFaultMarksTheClientAsInvalidAtStartupAndGivesAnAuditEvent(final String kind, final String reason,
      final Consumer<OIDCClientMetadata> fault) {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final OIDCClientMetadata metadata = jwksUriMetadata();
    fault.accept(metadata);
    final OidcClientRecord client = OidcClientRecord.of(CLIENT_ID, metadata);
    final ValidatingClientBackend backend = "configuration".equals(kind)
        ? new ConfigurationClientBackend(List.of(client))
        : new RepositoryClientBackend(new InMemoryClientRepository(List.of(client)));

    // As at startup: the validation is assigned before the tracker
    backend.setClientValidation(this.validation(backend.getName()));
    backend.setClientChangeTracker(this.tracker);

    final RequesterRecord record = backend.lookup(CLIENT_ID);
    assertThat(record).isNotNull();
    assertThat(record.isValid()).isFalse();
    assertThat(record.invalidReason()).contains(reason);
    assertThat(backend.getClients()).singleElement()
        .satisfies(c -> assertThat(c.invalidReason()).contains(reason));
    assertThat(this.events).filteredOn(ClientInvalidEvent.class::isInstance).singleElement()
        .satisfies(e -> {
          assertThat(((ClientInvalidEvent) e).getClient().identifier()).isEqualTo(CLIENT_ID);
          assertThat(((ClientInvalidEvent) e).getClient().source()).isEqualTo(backend.getName());
          assertThat(((ClientInvalidEvent) e).getReason()).contains(reason);
        });
  }

  @Test
  void aValidClientIsServedAndGivesNoEvent() {
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    backend.setClientValidation(this.validation(backend.getName()));
    backend.setClientChangeTracker(this.tracker);

    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(backend.getClients()).extracting(RegisteredClient::invalidReason).containsOnlyNulls();
    assertThat(this.events).noneMatch(ClientInvalidEvent.class::isInstance);
  }

  @Test
  void withoutAValidationEveryClientIsInvalid() {
    final ConfigurationClientBackend configuration =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    final RepositoryClientBackend repository = new RepositoryClientBackend(
        new InMemoryClientRepository(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()))));
    for (final ValidatingClientBackend backend : List.<ValidatingClientBackend> of(configuration, repository)) {
      assertThat(backend.lookup(CLIENT_ID).invalidReason()).isEqualTo(ValidatingClientBackend.NOT_VALIDATED_REASON);
      assertThat(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), new JWKMatcher.Builder().build())).isEmpty();
      assertThat(backend.resolveKeys("https://other.example.com", jwksUriMetadata(),
          new JWKMatcher.Builder().build())).isNull();
    }
    assertThat(this.fetcher.calls).isEmpty();
  }

  // Configured clients

  @Test
  void configuredClientsAreValidatedAtStartupAndALookupMakesNoFetch() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(this.fetcher.calls).containsExactly(JWKS_URI);

    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(keyIds(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("key")))).containsExactly("key");
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void aConfiguredClientWithJwksUsesThoseKeys() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSet(keys(KEY, "inline"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, metadata)));
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(keyIds(backend.resolveKeys(CLIENT_ID, metadata, matcher("inline")))).containsExactly("inline");
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void aTemporaryMarkRunsOutAtTheNextLookup() {
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(backend.lookup(CLIENT_ID).invalidReason()).contains("cannot be fetched");
    assertThat(this.fetcher.calls).hasSize(1);

    // Within the time, nothing is fetched
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    this.clock.advance(TEMPORARY.minusSeconds(1));
    assertThat(backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fetcher.calls).hasSize(1);

    this.clock.advance(Duration.ofSeconds(1));
    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void aTemporaryMarkOfAConfiguredClientRunsOutByTheSchedule() {
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));
    final ClientKeysRefresher refresher =
        new ClientKeysRefresher(List.of(backend), JobLock.LOCAL, Duration.ofHours(1));

    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    // The mark has not run out, and nothing is fetched
    assertThat(refresher.refresh()).isTrue();
    assertThat(this.fetcher.calls).hasSize(1);

    this.clock.advance(TEMPORARY);
    refresher.refresh();
    assertThat(this.fetcher.calls).hasSize(2);
    assertThat(this.store.get(backend.getName(), CLIENT_ID).isValid()).isTrue();
  }

  // Held keys

  @Test
  void anUnknownKeyReadsTheKeysAgainAtMostOncePerMinute() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));

    this.fetcher.jwks.put(JWKS_URI, keys(NEW_KEY, "new-key"));
    assertThat(keyIds(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("new-key"))))
        .containsExactly("new-key");
    assertThat(this.fetcher.calls).hasSize(2);

    // A made-up key makes no fetch within a minute
    assertThat(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("made-up"))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(2);
    this.clock.advance(ClientValidation.KEY_REFRESH_INTERVAL.minusSeconds(1));
    assertThat(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("made-up"))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(2);

    this.clock.advance(Duration.ofSeconds(1));
    assertThat(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("made-up"))).isEmpty();
    assertThat(this.fetcher.calls).hasSize(3);

    // A request with a known key makes no fetch
    assertThat(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("new-key"))).hasSize(1);
    assertThat(this.fetcher.calls).hasSize(3);
  }

  @Test
  void anUnknownKeyMakesNoFetchForAnInvalidClient() {
    final OIDCClientMetadata metadata = jwksUriMetadata();
    metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, metadata)));
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(backend.resolveKeys(CLIENT_ID, metadata, matcher("made-up"))).isEmpty();
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void theScheduleReadsTheKeysAgainAndKeepsTheOldKeysWhenTheReadFails() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));
    final ClientKeysRefresher refresher =
        new ClientKeysRefresher(List.of(backend), JobLock.LOCAL, Duration.ofHours(1));

    // New keys are read and held, so that encryption uses them
    this.fetcher.jwks.put(JWKS_URI, keys(NEW_KEY, "new-key"));
    refresher.refresh();
    assertThat(this.fetcher.calls).hasSize(2);
    assertThat(keyIds(this.store.get(backend.getName(), CLIENT_ID).heldKeys().keys().getKeys()))
        .containsExactly("new-key");

    // A read that fails keeps the held keys, and the client stays valid
    this.fetcher.jwks.remove(JWKS_URI);
    refresher.refresh();
    assertThat(this.fetcher.calls).hasSize(3);
    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(keyIds(this.store.get(backend.getName(), CLIENT_ID).heldKeys().keys().getKeys()))
        .containsExactly("new-key");

    // New keys that cannot be used are not used
    this.fetcher.jwks.put(JWKS_URI, new JWKSet());
    refresher.refresh();
    assertThat(this.fetcher.calls).hasSize(4);
    assertThat(keyIds(this.store.get(backend.getName(), CLIENT_ID).heldKeys().keys().getKeys()))
        .containsExactly("new-key");
  }

  @Test
  void theScheduleRunsOnOneNodeAtATime() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backend.setClientValidation(this.validation(backend.getName()));
    final List<String> asked = new ArrayList<>();
    final ClientKeysRefresher refresher = new ClientKeysRefresher(List.of(backend), (job, lease) -> {
      asked.add(job + "/" + lease);
      return false;
    }, Duration.ofMinutes(30));

    assertThat(refresher.refresh()).isFalse();
    assertThat(asked).containsExactly(ClientKeysRefresher.JOB_NAME + "/PT30M");
    assertThat(this.fetcher.calls).hasSize(1);
  }

  // Repository clients

  @Test
  void aRepositoryThatCannotListItsClientsIsValidatedOnLookup() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ListingRepository repository = new ListingRepository(false);
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);
    backend.setClientValidation(this.validation(backend.getName()));
    backend.setClientChangeTracker(this.tracker);
    assertThat(this.fetcher.calls).isEmpty();

    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fetcher.calls).hasSize(1);
    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fetcher.calls).hasSize(1);

    // The schedule covers the client that has been validated
    this.fetcher.jwks.put(JWKS_URI, keys(NEW_KEY, "new-key"));
    new ClientKeysRefresher(List.of(backend), JobLock.LOCAL, Duration.ofHours(1)).refresh();
    assertThat(this.fetcher.calls).hasSize(2);
    assertThat(keyIds(backend.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("new-key"))))
        .containsExactly("new-key");

    // A client that the repository no longer holds is forgotten
    repository.clients.clear();
    assertThat(backend.lookup(CLIENT_ID)).isNull();
    assertThat(this.store.get(backend.getName(), CLIENT_ID)).isNull();
  }

  @Test
  void aRepositoryThatCannotBeReadAtStartupDoesNotStopTheServer() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ListingRepository repository = new ListingRepository(true);
    repository.failing = true;
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);

    assertThatNoException().isThrownBy(() -> {
      backend.setClientValidation(this.validation(backend.getName()));
      backend.setClientChangeTracker(this.tracker);
    });
    assertThat(this.fetcher.calls).isEmpty();

    repository.failing = false;
    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void aRepositoryThatCanListItsClientsIsValidatedAtStartup() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ListingRepository repository = new ListingRepository(true);
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(this.fetcher.calls).hasSize(1);

    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fetcher.calls).hasSize(1);
  }

  @Test
  void aChangedRepositoryClientIsValidatedAgain() {
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ListingRepository repository = new ListingRepository(true);
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);
    backend.setClientValidation(this.validation(backend.getName()));
    backend.setClientChangeTracker(this.tracker);

    // A change that gives a fault
    final OIDCClientMetadata faulty = jwksUriMetadata();
    faulty.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, faulty));
    assertThat(backend.lookup(CLIENT_ID).invalidReason()).contains("RSA1_5");
    assertThat(this.events).filteredOn(ClientInvalidEvent.class::isInstance).hasSize(1);
    // ... is not validated again while it is unchanged
    assertThat(backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.events).filteredOn(ClientInvalidEvent.class::isInstance).hasSize(1);
    // The fault is found before the keys are read
    assertThat(this.fetcher.calls).hasSize(1);

    // A change of the jwks_uri: the keys of the old URI are not kept
    final OIDCClientMetadata moved = metadata();
    moved.setJWKSetURI(URI.create(OTHER_JWKS_URI));
    repository.clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, moved));
    final RequesterRecord record = backend.lookup(CLIENT_ID);
    assertThat(record.invalidReason()).isEqualTo("the keys at the jwks_uri cannot be fetched - HTTP status 503");
    assertThat(backend.resolveKeys(CLIENT_ID, moved, matcher("key"))).isEmpty();

    this.fetcher.jwks.put(OTHER_JWKS_URI, keys(NEW_KEY, "new-key"));
    this.clock.advance(TEMPORARY);
    assertThat(backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(keyIds(backend.resolveKeys(CLIENT_ID, moved, matcher("new-key")))).containsExactly("new-key");
  }

  @Test
  void aChangedSecretIsNotAChangeButAnAddedOneIs() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    final OidcClientRecord without = OidcClientRecord.of(CLIENT_ID, metadata);
    final OIDCClientMetadata withSecret = metadata();
    withSecret.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    withSecret.setCustomField(OidcClientRecord.CLIENT_SECRET, "one");
    final OIDCClientMetadata otherSecret = metadata();
    otherSecret.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    otherSecret.setCustomField(OidcClientRecord.CLIENT_SECRET, "two");

    assertThat(ValidatedClient.fingerprint(without))
        .isNotEqualTo(ValidatedClient.fingerprint(OidcClientRecord.of(CLIENT_ID, withSecret)));
    assertThat(ValidatedClient.fingerprint(OidcClientRecord.of(CLIENT_ID, withSecret)))
        .isEqualTo(ValidatedClient.fingerprint(OidcClientRecord.of(CLIENT_ID, otherSecret)))
        .doesNotContain("one");
  }

  @Test
  void outcomesOfClientsNoLongerConfiguredAreForgotten() {
    this.store.put("configuration", new ValidatedClient("https://gone.example.com", "x", null, null, null));
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSet(keys(KEY, "key"));
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, metadata)));
    backend.setClientValidation(this.validation(backend.getName()));
    assertThat(this.store.getAll("configuration")).extracting(ValidatedClient::clientId).containsExactly(CLIENT_ID);
  }

  private static JWKMatcher matcher(final String kid) {
    return JWKMatcher.forJWSHeader(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build());
  }

  private static List<String> keyIds(final List<JWK> keys) {
    return keys.stream().map(JWK::getKeyID).toList();
  }

  /** A repository that may be unable to list its clients, or to be read at all. */
  private static final class ListingRepository implements ClientRepository {

    final Map<String, OidcClientRecord> clients = new ConcurrentHashMap<>();

    private final boolean canList;

    volatile boolean failing;

    ListingRepository(final boolean canList) {
      this.canList = canList;
    }

    @Override
    public OidcClientRecord findByClientId(final String clientId) {
      if (this.failing) {
        throw new ClientRegistryException("the database could not be reached");
      }
      return this.clients.get(clientId);
    }

    @Override
    public List<OidcClientRecord> findAll() {
      if (this.failing) {
        throw new ClientRegistryException("the database could not be reached");
      }
      return this.canList ? List.copyOf(this.clients.values()) : null;
    }
  }

}
