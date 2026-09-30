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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;

/**
 * Tests for the in-memory stores of authorization codes, access tokens and client assertions.
 *
 * @author Martin Lindström
 */
class InMemoryStoresTest {

  private static final Instant NOW = Instant.parse("2026-09-30T10:00:00Z");

  @Test
  void aCodeIsRedeemedOnceAndAReplayCarriesTheAccessToken() {
    final MutableClock clock = new MutableClock(NOW);
    final InMemoryAuthorizationCodeStore store = new InMemoryAuthorizationCodeStore(clock);
    store.save(code("c1", NOW.plusSeconds(60), NOW.plusSeconds(360)));

    final AuthorizationCodeStore.Redemption first = store.redeem("c1");
    assertThat(first).isNotNull();
    assertThat(first.replay()).isFalse();
    store.registerAccessToken("c1", "at-1");

    final AuthorizationCodeStore.Redemption second = store.redeem("c1");
    assertThat(second).isNotNull();
    assertThat(second.replay()).isTrue();
    assertThat(second.accessToken()).isEqualTo("at-1");

    // A used code is kept after its expiry, until it is no longer retained
    clock.now = NOW.plusSeconds(120);
    assertThat(store.redeem("c1").replay()).isTrue();
    clock.now = NOW.plusSeconds(360);
    assertThat(store.redeem("c1")).isNull();
    assertThat(store.redeem("unknown")).isNull();
  }

  @Test
  void anExpiredCodeCannotBeRedeemed() {
    final MutableClock clock = new MutableClock(NOW);
    final InMemoryAuthorizationCodeStore store = new InMemoryAuthorizationCodeStore(clock);
    store.save(code("c1", NOW.plusSeconds(60), NOW.plusSeconds(360)));
    clock.now = NOW.plusSeconds(60);
    assertThat(store.redeem("c1")).isNull();

    // Saving purges entries that are no longer retained
    clock.now = NOW.plusSeconds(400);
    store.save(code("c2", NOW.plusSeconds(460), NOW.plusSeconds(760)));
    assertThat(store.redeem("c2")).isNotNull();
  }

  @Test
  void accessTokensExpireAndAreRevokedAndSingleUseTokensAreUsedOnce() {
    final MutableClock clock = new MutableClock(NOW);
    final InMemoryAccessTokenStore store = new InMemoryAccessTokenStore(clock);
    store.save(token("single", true));
    store.save(token("multi", false));
    store.save(token("revoked", false));

    assertThat(store.get("single")).isNotNull();
    assertThat(store.markUsed("single")).isTrue();
    assertThat(store.get("single")).isNull();
    assertThat(store.markUsed("single")).isFalse();

    assertThat(store.markUsed("multi")).isTrue();
    assertThat(store.markUsed("multi")).isTrue();
    assertThat(store.get("multi")).isNotNull();

    store.revoke("revoked");
    assertThat(store.get("revoked")).isNull();
    assertThat(store.markUsed("unknown")).isFalse();

    clock.now = NOW.plusSeconds(300);
    assertThat(store.get("multi")).isNull();
    assertThat(store.markUsed("multi")).isFalse();
  }

  @Test
  void anAssertionIdIsAcceptedOncePerClientUntilItExpires() {
    final MutableClock clock = new MutableClock(NOW);
    final InMemoryClientAssertionReplayCache cache = new InMemoryClientAssertionReplayCache(clock);
    assertThat(cache.register("client", "jti-1", NOW.plusSeconds(60))).isTrue();
    assertThat(cache.register("client", "jti-1", NOW.plusSeconds(60))).isFalse();
    assertThat(cache.register("other", "jti-1", NOW.plusSeconds(60))).isTrue();

    clock.now = NOW.plusSeconds(61);
    assertThat(cache.register("client", "jti-1", NOW.plusSeconds(120))).isTrue();
  }

  @Test
  void theDataObjectsDoNotRevealTheUser() {
    assertThat(code("c1", NOW, NOW).toString()).doesNotContain("197705232382").contains("client-1");
    assertThat(token("t1", true).toString()).doesNotContain("sub-1").contains("client-1");
  }

  private static AuthorizationCodeData code(final String code, final Instant expiresAt, final Instant retainUntil) {
    final AuthenticatedUser user = new AuthenticatedUser(
        List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3", NOW, "127.0.0.1");
    return new AuthorizationCodeData(code, "client-1", "https://rp.example.com/cb", null, null, null,
        List.of("openid"), "sub-1", user, new AuthenticationRequirements(), "{}", "{}", NOW, expiresAt, retainUntil);
  }

  private static AccessTokenData token(final String value, final boolean singleUse) {
    return new AccessTokenData(value, "client-1", "sub-1", List.of("openid"), "{}", NOW,
        NOW.plus(Duration.ofMinutes(5)), singleUse);
  }

  /** A clock that the test moves. */
  private static class MutableClock extends Clock {

    Instant now;

    MutableClock(final Instant now) {
      this.now = now;
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return this.now;
    }
  }

}
