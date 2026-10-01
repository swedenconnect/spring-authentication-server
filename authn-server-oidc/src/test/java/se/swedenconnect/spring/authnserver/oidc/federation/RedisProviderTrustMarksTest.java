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
package se.swedenconnect.spring.authnserver.oidc.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport.CONTRACT;
import static se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport.ENTITY_ID;
import static se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport.LOA3;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.spring.authnserver.oidc.RedisTestNodes;

/**
 * Tests for {@link ProviderTrustMarks} with a {@link RedisProviderTrustMarkStore}, against a Redis container. Two
 * instances with connections of their own play two nodes.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisProviderTrustMarksTest {

  @Container
  private static final GenericContainer<?> REDIS = RedisTestNodes.container();

  private static final Duration RETRY = Duration.ofMinutes(5);

  private static LettuceConnectionFactory nodeA;

  private static LettuceConnectionFactory nodeB;

  private final ECKey issuerKey = FederationSupport.key("tmi");

  private final FederationSupport.TestClock clock = new FederationSupport.TestClock();

  private final FederationSupport.StubFederationClient clientA = new FederationSupport.StubFederationClient();

  private final FederationSupport.StubFederationClient clientB = new FederationSupport.StubFederationClient();

  private StringRedisTemplate template;

  private ProviderTrustMarks nodeOne;

  private ProviderTrustMarks nodeTwo;

  @TempDir
  Path directory;

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
    this.template = new StringRedisTemplate(nodeA);
    this.nodeOne = this.trustMarks(nodeA, this.clientA);
    this.nodeTwo = this.trustMarks(nodeB, this.clientB);
  }

  @Test
  void oneNodeFetchesAndBothPublish() {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.clientA.answer(mark);
    this.clientB.answer(mark);

    assertThat(this.nodeOne.refresh() + this.nodeTwo.refresh()).isEqualTo(1);
    assertThat(this.clientA.requests.size() + this.clientB.requests.size()).isEqualTo(1);

    assertThat(this.nodeOne.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, mark.serialize()));
    assertThat(this.nodeTwo.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, mark.serialize()));
    assertThat(this.nodeTwo.getStates()).isEqualTo(this.nodeOne.getStates());
    assertThat(this.nodeTwo.getStates().getFirst().expiresAt())
        .isEqualTo(this.clock.instant().plus(Duration.ofDays(30)));
    assertThat(this.template.getExpire("test:oidc:provider-trust-mark:" + LOA3))
        .isBetween(Duration.ofDays(31).toSeconds() - 5, Duration.ofDays(31).toSeconds());
  }

  @Test
  void theFailureStateIsSharedByAllNodes() {
    this.clientA.answer(new IllegalStateException("Connection refused"));
    this.clientB.answer(new IllegalStateException("Connection refused"));

    assertThat(this.nodeOne.refresh() + this.nodeTwo.refresh()).isZero();
    final TrustMarkState state = this.nodeTwo.getStates().getFirst();
    assertThat(state.isFailing()).isTrue();
    assertThat(state.consecutiveFailures()).isEqualTo(1);
    assertThat(state.lastFailureReason()).isEqualTo("Connection refused");
    assertThat(this.nodeOne.getStates()).isEqualTo(this.nodeTwo.getStates());
    assertThat(this.template.getExpire("test:oidc:provider-trust-mark:" + LOA3))
        .isBetween(Duration.ofDays(1).toSeconds() - 5, Duration.ofDays(1).toSeconds());

    // The next attempt is after the retry interval, by whichever node holds the lock
    this.releaseLock();
    this.clock.advance(RETRY);
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.clientA.answers.clear();
    this.clientB.answers.clear();
    this.clientA.answer(mark);
    this.clientB.answer(mark);
    assertThat(this.nodeTwo.refresh() + this.nodeOne.refresh()).isEqualTo(1);
    assertThat(this.nodeOne.getStates().getFirst().isFailing()).isFalse();
    assertThat(this.nodeOne.getTrustMarks()).hasSize(1);
  }

  @Test
  void aNodeThatStartsLaterPublishesTheTrustMarksWithoutFetchingThem() {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.clientA.answer(mark);
    assertThat(this.nodeOne.refresh()).isEqualTo(1);

    final FederationSupport.StubFederationClient clientC = new FederationSupport.StubFederationClient();
    final ProviderTrustMarks later = this.trustMarks(nodeB, clientC);
    later.loadStored();
    assertThat(later.refresh()).isZero();
    assertThat(clientC.requests).isEmpty();
    assertThat(later.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, mark.serialize()));
  }

  @Test
  void aTrustMarkIsRenewedByTheNodeHoldingTheLockWhenItIsDue() {
    this.clientA.answer(this.mark(LOA3, Duration.ofDays(4)));
    assertThat(this.nodeOne.refresh()).isEqualTo(1);
    this.clock.advance(Duration.ofDays(3));

    final SignedJWT renewed = this.mark(LOA3, Duration.ofDays(4));
    this.clientA.answers.clear();
    this.clientA.answer(renewed);
    this.clientB.answer(renewed);
    // The lock of node one is still held, so node two leaves the round to it
    assertThat(this.nodeTwo.refresh()).isZero();
    assertThat(this.nodeOne.refresh()).isEqualTo(1);
    assertThat(this.nodeTwo.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, renewed.serialize()));
  }

  @Test
  void aTrustMarkWithoutExpiryIsKeptUntilReplaced() {
    this.clientA.answer(this.mark(CONTRACT, null));
    final ProviderTrustMarks trustMarks = new ProviderTrustMarks(ENTITY_ID,
        List.of(FederationSupport.source(CONTRACT, this.issuerKey)), this.store(nodeA), this.clientA, null, RETRY,
        this.clock);
    assertThat(trustMarks.refresh()).isEqualTo(1);
    assertThat(this.template.getExpire("test:oidc:provider-trust-mark:" + CONTRACT)).isEqualTo(-1L);
  }

  @Test
  void theCacheDirectoryIsWrittenWhenGiven() throws Exception {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.clientA.answer(mark);
    final ProviderTrustMarks trustMarks = new ProviderTrustMarks(ENTITY_ID,
        List.of(FederationSupport.source(LOA3, this.issuerKey)), this.store(nodeA), this.clientA, this.directory,
        RETRY, this.clock);
    assertThat(trustMarks.refresh()).isEqualTo(1);
    try (final var files = Files.list(this.directory)) {
      assertThat(files).hasSize(1);
    }
  }

  @Test
  void anEntryThatCannotBeReadIsTreatedAsMissing() {
    this.template.opsForValue().set("test:oidc:provider-trust-mark:" + LOA3, "not json");
    assertThat(this.nodeOne.getTrustMarks()).isEmpty();
    assertThat(this.nodeOne.getStates().getFirst().published()).isFalse();
  }

  @Test
  void invalidArguments() {
    assertThatThrownBy(() -> new RedisProviderTrustMarkStore(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RedisProviderTrustMarkStore(this.template, ""))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(new RedisProviderTrustMarkStore(this.template).getJobLock()).isNotNull();
  }

  private void releaseLock() {
    this.template.delete("test:lock:" + ProviderTrustMarks.JOB_NAME);
  }

  private RedisProviderTrustMarkStore store(final LettuceConnectionFactory node) {
    return new RedisProviderTrustMarkStore(new StringRedisTemplate(node), "test", this.clock);
  }

  private ProviderTrustMarks trustMarks(final LettuceConnectionFactory node,
      final FederationSupport.StubFederationClient client) {
    return new ProviderTrustMarks(ENTITY_ID, List.of(FederationSupport.source(LOA3, this.issuerKey)),
        this.store(node), client, null, RETRY, this.clock);
  }

  private SignedJWT mark(final String type, final Duration lifetime) {
    final Instant now = this.clock.instant();
    return FederationSupport.trustMark(this.issuerKey, type, now, lifetime != null ? now.plus(lifetime) : null);
  }

}
