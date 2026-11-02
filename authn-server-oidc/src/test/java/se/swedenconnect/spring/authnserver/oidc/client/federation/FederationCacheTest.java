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

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link InMemoryFederationCache}, {@link CachedClientRecord} and {@link FederationCacheSettings}.
 *
 * @author Martin Lindström
 */
class FederationCacheTest extends FederationTestSupport {

  @Test
  void anExpiredEntryIsNeverHandedOut() {
    final TestClock clock = new TestClock();
    final InMemoryFederationCache cache = new InMemoryFederationCache(clock);
    cache.put(CachedClientRecord.notFound(CLIENT_ID, clock.instant(), Duration.ofMinutes(1)));

    assertThat(cache.get(CLIENT_ID)).isNotNull();
    assertThat(cache.size()).isEqualTo(1);

    clock.advance(Duration.ofMinutes(2));
    assertThat(cache.get(CLIENT_ID)).isNull();
    assertThat(cache.size()).isZero();
  }

  @Test
  void anEntryCanBeRemovedAndExpiredEntriesCanBePurged() {
    final TestClock clock = new TestClock();
    final InMemoryFederationCache cache = new InMemoryFederationCache(clock);
    cache.put(CachedClientRecord.notFound("one", clock.instant(), Duration.ofMinutes(1)));
    cache.put(CachedClientRecord.notFound("two", clock.instant(), Duration.ofHours(1)));

    cache.remove("one");
    assertThat(cache.size()).isEqualTo(1);

    clock.advance(Duration.ofMinutes(2));
    cache.purgeExpired();
    assertThat(cache.size()).isEqualTo(1);

    clock.advance(Duration.ofHours(1));
    cache.purgeExpired();
    assertThat(cache.size()).isZero();
  }

  @Test
  void anEntryForAnUnknownClientHoldsNoClient() {
    final Instant now = Instant.now();
    final CachedClientRecord record = CachedClientRecord.notFound(CLIENT_ID, now, Duration.ofMinutes(1));

    assertThat(record.isFound()).isFalse();
    assertThat(record.metadata()).isNull();
    assertThat(record.getMarks(now)).isEmpty();
    assertThat(record.isExpired(now)).isFalse();
    assertThat(record.isExpired(now.plus(Duration.ofMinutes(1)))).isTrue();
  }

  @Test
  void theMarksAreTheResolvedOnesAndTheValidOnDemandOnes() {
    final Instant now = Instant.now();
    final CachedClientRecord record = CachedClientRecord
        .found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(MARK_ONE),
            now.plus(Duration.ofHours(1))), now, null)
        .withTrustMark(MARK_TWO, now.plus(Duration.ofMinutes(10)));

    assertThat(record.getMarks(now)).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);
    assertThat(record.getMarks(now.plus(Duration.ofMinutes(11)))).containsExactly(MARK_ONE);
  }

  @Test
  void trustMarksAreCarriedOverFromAnEarlierEntry() {
    final Instant now = Instant.now();
    final CachedClientRecord earlier = CachedClientRecord
        .found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(),
            now.plus(Duration.ofHours(1))), now, null)
        .withTrustMark(MARK_ONE, now.plus(Duration.ofMinutes(30)))
        .withTrustMark(MARK_TWO, now.plus(Duration.ofMinutes(5)));

    final CachedClientRecord later = CachedClientRecord
        .found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(),
            now.plus(Duration.ofHours(2))), now, null)
        .carryOverTrustMarks(earlier, now.plus(Duration.ofMinutes(10)));

    assertThat(later.onDemandTrustMarks()).containsOnlyKeys(MARK_ONE);
    assertThat(later.carryOverTrustMarks(null, now)).isSameAs(later);
  }

  @Test
  void aTrustMarkThatTheResolveResponseNowCarriesIsNotCarriedOver() {
    final Instant now = Instant.now();
    final CachedClientRecord earlier = CachedClientRecord
        .found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(),
            now.plus(Duration.ofHours(1))), now, null)
        .withTrustMark(MARK_ONE, now.plus(Duration.ofMinutes(30)));

    final CachedClientRecord later = CachedClientRecord
        .found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(MARK_ONE),
            now.plus(Duration.ofHours(2))), now, null)
        .carryOverTrustMarks(earlier, now);

    assertThat(later.onDemandTrustMarks()).isEmpty();
    assertThat(later.getMarks(now)).containsExactly(MARK_ONE);
  }

  @Test
  void theSettingsAreValidated() {
    assertThatThrownBy(() -> new FederationCacheSettings(Duration.ZERO, Duration.ofMinutes(1)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new FederationCacheSettings(Duration.ofMinutes(-1), Duration.ofMinutes(1)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new FederationCacheSettings(null, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theDefaultsAreNoMaximumAge() {
    final FederationCacheSettings settings = FederationCacheSettings.defaults();

    assertThat(settings.maximumAge()).isNull();
    assertThat(settings.notFoundTimeToLive()).isEqualTo(FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE);
  }

}
