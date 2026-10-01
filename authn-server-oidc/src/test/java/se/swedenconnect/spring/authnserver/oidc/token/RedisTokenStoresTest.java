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
package se.swedenconnect.spring.authnserver.oidc.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import se.swedenconnect.spring.authnserver.oidc.RedisTestNodes;

/**
 * Tests for the Redis stores of authorization codes, access tokens and client assertions, against a Redis container.
 * Two stores with connections of their own play two nodes.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisTokenStoresTest {

  @Container
  private static final GenericContainer<?> REDIS = RedisTestNodes.container();

  private static LettuceConnectionFactory nodeA;

  private static LettuceConnectionFactory nodeB;

  private MutableClock clock;

  private StringRedisTemplate templateA;

  private StringRedisTemplate templateB;

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
    this.clock = new MutableClock(Instant.now().truncatedTo(ChronoUnit.MILLIS));
    this.templateA = new StringRedisTemplate(nodeA);
    this.templateB = new StringRedisTemplate(nodeB);
  }

  @Test
  void aCodeSavedOnOneNodeIsRedeemedOnceOnAnyNode() {
    final RedisAuthorizationCodeStore a = new RedisAuthorizationCodeStore(this.templateA, "test", this.clock);
    final RedisAuthorizationCodeStore b = new RedisAuthorizationCodeStore(this.templateB, "test", this.clock);
    final AuthorizationCodeData code = this.code("c1", 60, 360);
    a.save(code);

    final AuthorizationCodeStore.Redemption first = b.redeem("c1");
    assertThat(first).isNotNull();
    assertThat(first.replay()).isFalse();
    assertThat(first.code()).isEqualTo(code);
    b.registerAccessToken("c1", "at-1");

    final AuthorizationCodeStore.Redemption second = a.redeem("c1");
    assertThat(second).isNotNull();
    assertThat(second.replay()).isTrue();
    assertThat(second.accessToken()).isEqualTo("at-1");

    // A used code is kept after its expiry, until it is no longer retained
    this.clock.advance(Duration.ofSeconds(120));
    assertThat(a.redeem("c1").replay()).isTrue();
    this.clock.advance(Duration.ofSeconds(240));
    assertThat(a.redeem("c1")).isNull();
    assertThat(a.redeem("unknown")).isNull();
  }

  @Test
  void aReplayBeforeTheAccessTokenIsRegisteredHasNoAccessToken() {
    final RedisAuthorizationCodeStore store = new RedisAuthorizationCodeStore(this.templateA, "test", this.clock);
    store.save(this.code("c1", 60, 360));
    assertThat(store.redeem("c1").replay()).isFalse();
    final AuthorizationCodeStore.Redemption replay = store.redeem("c1");
    assertThat(replay.replay()).isTrue();
    assertThat(replay.accessToken()).isNull();

    // Registering for a code that has not been redeemed does nothing
    store.save(this.code("c2", 60, 360));
    store.registerAccessToken("c2", "at-2");
    assertThat(store.redeem("c2").replay()).isFalse();
  }

  @Test
  void anExpiredCodeCannotBeRedeemed() {
    final RedisAuthorizationCodeStore store = new RedisAuthorizationCodeStore(this.templateA, "test", this.clock);
    store.save(this.code("c1", 60, 360));
    this.clock.advance(Duration.ofSeconds(60));
    assertThat(store.redeem("c1")).isNull();
  }

  @Test
  void codeEntriesExpireInRedisWhenTheCodeIsNoLongerRetained() {
    final RedisAuthorizationCodeStore store = new RedisAuthorizationCodeStore(this.templateA, "test", this.clock);
    store.save(this.code("c1", 60, 360));
    store.redeem("c1");
    store.registerAccessToken("c1", "at-1");
    assertThat(this.templateA.getExpire("test:oidc:code:c1")).isBetween(355L, 360L);
    assertThat(this.templateA.getExpire("test:oidc:code-use:c1")).isBetween(355L, 360L);
  }

  @Test
  void concurrentRedemptionsFromTwoNodesGiveTheCodeOnce() throws Exception {
    final List<AuthorizationCodeStore> stores = List.of(
        new RedisAuthorizationCodeStore(this.templateA, "test", this.clock),
        new RedisAuthorizationCodeStore(this.templateB, "test", this.clock));
    stores.getFirst().save(this.code("c1", 60, 360));
    final List<Supplier<Boolean>> tasks = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      final AuthorizationCodeStore store = stores.get(i % 2);
      tasks.add(() -> {
        final AuthorizationCodeStore.Redemption redemption = store.redeem("c1");
        return redemption != null && !redemption.replay();
      });
    }
    assertThat(RedisTestNodes.countSuccesses(tasks)).isEqualTo(1);
  }

  @Test
  void accessTokensExpireAndAreRevokedAndSingleUseTokensAreUsedOnce() {
    final RedisAccessTokenStore a = new RedisAccessTokenStore(this.templateA, "test", this.clock);
    final RedisAccessTokenStore b = new RedisAccessTokenStore(this.templateB, "test", this.clock);
    a.save(this.token("single", true));
    a.save(this.token("multi", false));
    a.save(this.token("revoked", false));

    assertThat(b.get("single")).isEqualTo(this.token("single", true));
    assertThat(b.markUsed("single")).isTrue();
    assertThat(a.get("single")).isNull();
    assertThat(a.markUsed("single")).isFalse();

    assertThat(b.markUsed("multi")).isTrue();
    assertThat(a.markUsed("multi")).isTrue();
    assertThat(b.get("multi")).isNotNull();

    a.revoke("revoked");
    assertThat(b.get("revoked")).isNull();
    assertThat(b.markUsed("unknown")).isFalse();
    assertThat(this.templateA.hasKey("test:oidc:access-token:revoked")).isFalse();

    assertThat(this.templateA.getExpire("test:oidc:access-token:multi")).isBetween(295L, 300L);
    assertThat(this.templateA.getExpire("test:oidc:access-token-use:single")).isBetween(295L, 300L);

    this.clock.advance(Duration.ofSeconds(300));
    assertThat(b.get("multi")).isNull();
    assertThat(b.markUsed("multi")).isFalse();
  }

  @Test
  void concurrentUseOfASingleUseTokenFromTwoNodesSucceedsOnce() throws Exception {
    final List<AccessTokenStore> stores = List.of(
        new RedisAccessTokenStore(this.templateA, "test", this.clock),
        new RedisAccessTokenStore(this.templateB, "test", this.clock));
    stores.getFirst().save(this.token("single", true));
    final List<Supplier<Boolean>> tasks = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      final AccessTokenStore store = stores.get(i % 2);
      tasks.add(() -> store.markUsed("single"));
    }
    assertThat(RedisTestNodes.countSuccesses(tasks)).isEqualTo(1);
  }

  @Test
  void anAssertionIdIsAcceptedOncePerClientUntilItExpires() throws Exception {
    final RedisClientAssertionReplayCache a = new RedisClientAssertionReplayCache(this.templateA, "test", this.clock);
    final RedisClientAssertionReplayCache b = new RedisClientAssertionReplayCache(this.templateB, "test", this.clock);
    assertThat(a.register("client", "jti-1", this.clock.instant().plusSeconds(60))).isTrue();
    assertThat(b.register("client", "jti-1", this.clock.instant().plusSeconds(60))).isFalse();
    assertThat(b.register("other", "jti-1", this.clock.instant().plusSeconds(60))).isTrue();
    assertThat(this.templateA.getExpire("test:oidc:client-assertion:client jti-1")).isBetween(55L, 60L);

    assertThat(a.register("client", "jti-2", Instant.now().plusMillis(300))).isTrue();
    Thread.sleep(400);
    assertThat(b.register("client", "jti-2", Instant.now().plusSeconds(60))).isTrue();
  }

  @Test
  void concurrentRegistrationsFromTwoNodesSucceedOnce() throws Exception {
    final List<ClientAssertionReplayCache> caches = List.of(
        new RedisClientAssertionReplayCache(this.templateA, "test", this.clock),
        new RedisClientAssertionReplayCache(this.templateB, "test", this.clock));
    final Instant expiresAt = this.clock.instant().plusSeconds(60);
    final List<Supplier<Boolean>> tasks = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      final ClientAssertionReplayCache cache = caches.get(i % 2);
      tasks.add(() -> cache.register("client", "jti-1", expiresAt));
    }
    assertThat(RedisTestNodes.countSuccesses(tasks)).isEqualTo(1);
  }

  @Test
  void theDefaultPrefixIsUsed() {
    new RedisAccessTokenStore(this.templateA).save(this.token("t1", false));
    new RedisAuthorizationCodeStore(this.templateA).save(this.code("c1", 60, 360));
    new RedisClientAssertionReplayCache(this.templateA).register("client", "jti", Instant.now().plusSeconds(60));
    assertThat(this.templateA.keys("authn-server:*")).containsExactlyInAnyOrder(
        "authn-server:oidc:access-token:t1", "authn-server:oidc:code:c1",
        "authn-server:oidc:client-assertion:client jti");
  }

  @Test
  void anEntryThatCannotBeReadIsTreatedAsMissing() {
    this.templateA.opsForValue().set("test:oidc:code:bad", "not json");
    this.templateA.opsForValue().set("test:oidc:access-token:bad", "{\"value\":\"bad\"}");
    assertThat(new RedisAuthorizationCodeStore(this.templateA, "test", this.clock).redeem("bad")).isNull();
    assertThat(new RedisAccessTokenStore(this.templateA, "test", this.clock).get("bad")).isNull();
  }

  @Test
  void invalidArguments() {
    assertThatThrownBy(() -> new RedisAuthorizationCodeStore(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RedisAccessTokenStore(this.templateA, ""))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new RedisClientAssertionReplayCache(this.templateA, "test", null))
        .isInstanceOf(NullPointerException.class);
  }

  private AuthorizationCodeData code(final String code, final long expiresIn, final long retainedFor) {
    final Instant now = this.clock.instant();
    return new AuthorizationCodeData(code, "client-1", "https://rp.example.com/cb", "challenge", "S256", "nonce",
        List.of("openid", "profile"), "sub-1", now.minusSeconds(10), "http://id.elegnamnden.se/loa/1.0/loa3",
        "{\"name\":\"Kalle\"}", "{}", now, now.plusSeconds(expiresIn), now.plusSeconds(retainedFor),
        "correlation-1");
  }

  private AccessTokenData token(final String value, final boolean singleUse) {
    final Instant now = this.clock.instant();
    return new AccessTokenData(value, "client-1", "sub-1", List.of("openid"), "{\"name\":\"Kalle\"}", now,
        now.plus(Duration.ofMinutes(5)), singleUse, "correlation-1");
  }

  /** A clock that the test moves. */
  private static class MutableClock extends Clock {

    private Instant now;

    MutableClock(final Instant now) {
      this.now = now;
    }

    void advance(final Duration duration) {
      this.now = this.now.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return this.now;
    }
  }

}
