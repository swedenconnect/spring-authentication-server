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

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;

import se.swedenconnect.spring.authnserver.oidc.RedisTestNodes;

/**
 * Tests for {@link RedisClientValidationStore}, against a Redis container. Two stores with connections of their own
 * play two nodes.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisClientValidationStoreTest extends ClientTestSupport {

  @Container
  private static final GenericContainer<?> REDIS = RedisTestNodes.container();

  private static LettuceConnectionFactory nodeA;

  private static LettuceConnectionFactory nodeB;

  private final TestClock clock = new TestClock();

  private RedisClientValidationStore storeA;

  private RedisClientValidationStore storeB;

  @BeforeAll
  static void init() {
    nodeA = RedisTestNodes.connect(REDIS);
    nodeB = RedisTestNodes.connect(REDIS);
  }

  @AfterAll
  static void close() {
    nodeA.destroy();
    nodeB.destroy();
  }

  @BeforeEach
  void setup() {
    RedisTestNodes.flush(nodeA);
    this.storeA = new RedisClientValidationStore(new StringRedisTemplate(nodeA), "test");
    this.storeB = new RedisClientValidationStore(new StringRedisTemplate(nodeB), "test");
  }

  @Test
  void anOutcomePutByOneNodeIsSeenByTheOther() {
    final HeldKeys held = new HeldKeys(JWKS_URI, false, keys(KEY, "key"), null);
    final ValidatedClient valid = new ValidatedClient(CLIENT_ID, "fingerprint", null, null, held);
    final ValidatedClient invalid = new ValidatedClient("https://other.example.com", "other", "the reason",
        this.clock.instant().plusSeconds(300), null);
    this.storeA.put("source", valid);
    this.storeA.put("source", invalid);

    final ValidatedClient read = this.storeB.get("source", CLIENT_ID);
    assertThat(read).isNotNull();
    assertThat(read.fingerprint()).isEqualTo("fingerprint");
    assertThat(read.isValid()).isTrue();
    assertThat(read.heldKeys().uri()).isEqualTo(JWKS_URI);
    assertThat(read.heldKeys().keys().getKeyByKeyId("key").toPublicJWK())
        .isEqualTo(keys(KEY, "key").getKeyByKeyId("key"));
    assertThat(this.storeB.get("source", "https://other.example.com")).isEqualTo(invalid);
    assertThat(this.storeB.getAll("source")).hasSize(2);
    assertThat(this.storeB.get("another-source", CLIENT_ID)).isNull();
    assertThat(this.storeB.getAll("another-source")).isEmpty();

    this.storeB.remove("source", CLIENT_ID);
    assertThat(this.storeA.get("source", CLIENT_ID)).isNull();
    assertThat(this.storeA.getAll("source")).extracting(ValidatedClient::clientId)
        .containsExactly("https://other.example.com");
  }

  @Test
  void theNodesShareTheOutcomesAndTheHeldKeys() {
    final StubKeysFetcher fetcher = new StubKeysFetcher();
    fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final Map<String, OidcClientRecord> clients = new ConcurrentHashMap<>();
    clients.put(CLIENT_ID, OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()));
    final ClientRepository repository = clients::get;

    final RepositoryClientBackend backendA = new RepositoryClientBackend(repository);
    backendA.setClientValidation(this.validation(this.storeA, fetcher));
    final RepositoryClientBackend backendB = new RepositoryClientBackend(repository);
    backendB.setClientValidation(this.validation(this.storeB, fetcher));

    // Node A validates the client, and node B uses the outcome and the keys without a fetch
    assertThat(backendA.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(fetcher.calls).hasSize(1);
    assertThat(backendB.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(backendB.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("key"))).extracting(JWK::getKeyID)
        .containsExactly("key");
    assertThat(fetcher.calls).hasSize(1);

    // Keys read again by node A, for an unknown key, are used by node B
    fetcher.jwks.put(JWKS_URI, keys(NEW_KEY, "new-key"));
    assertThat(backendA.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("new-key"))).hasSize(1);
    assertThat(fetcher.calls).hasSize(2);
    assertThat(backendB.resolveKeys(CLIENT_ID, jwksUriMetadata(), matcher("new-key"))).hasSize(1);
    assertThat(fetcher.calls).hasSize(2);
  }

  @Test
  void theScheduleRunsOnOneNodeAtATime() {
    final StubKeysFetcher fetcher = new StubKeysFetcher();
    fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ConfigurationClientBackend backendA =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backendA.setClientValidation(this.validation(this.storeA, fetcher));
    final ConfigurationClientBackend backendB =
        new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata())));
    backendB.setClientValidation(this.validation(this.storeB, fetcher));
    assertThat(fetcher.calls).hasSize(2);

    final ClientKeysRefresher refresherA =
        new ClientKeysRefresher(List.of(backendA), this.storeA.getJobLock(), Duration.ofMinutes(10));
    final ClientKeysRefresher refresherB =
        new ClientKeysRefresher(List.of(backendB), this.storeB.getJobLock(), Duration.ofMinutes(10));

    assertThat(refresherA.refresh()).isTrue();
    assertThat(refresherB.refresh()).isFalse();
    assertThat(fetcher.calls).hasSize(3);
    // The node that holds the lock runs the next round as well
    assertThat(refresherA.refresh()).isTrue();
    assertThat(fetcher.calls).hasSize(4);
  }

  private ClientValidation validation(final ClientValidationStore store, final ClientKeysFetcher fetcher) {
    return new ClientValidation(RepositoryClientBackend.DEFAULT_NAME,
        new ClientMetadataValidator(new PairwiseClientCheck(null), fetcher), store, Duration.ofMinutes(5),
        this.clock);
  }

  private static JWKMatcher matcher(final String kid) {
    return JWKMatcher.forJWSHeader(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build());
  }

}
