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

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationClientBackendTest.StubResolver;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link FederationCacheRefresher}.
 *
 * @author Martin Lindström
 */
class FederationCacheRefresherTest extends FederationTestSupport {

  private static final Duration VALIDITY = Duration.ofMinutes(10);

  @Test
  void onlyEntriesThatAreAboutToExpireAreRefreshed() {
    final Fixture fixture = new Fixture(refreshSettings(1, 10));
    fixture.resolve("client-one");

    assertThat(fixture.refresher.refresh()).isZero();

    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(fixture.refresher.refresh()).isEqualTo(1);
    assertThat(fixture.cache.get("client-one").expiresAt())
        .isEqualTo(fixture.clock.instant().plus(VALIDITY));
  }

  @Test
  void onlyClientsThatAreUsedOftenEnoughAreRefreshed() {
    final Fixture fixture = new Fixture(refreshSettings(3, 10));
    fixture.resolve("frequent");
    fixture.resolve("frequent");
    fixture.resolve("frequent");
    fixture.resolve("rare");

    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(fixture.refresher.refresh()).isEqualTo(1);
    assertThat(fixture.resolver.asked).containsExactly("frequent");
  }

  @Test
  void neverMoreClientsThanTheMaximumAreRefreshed() {
    final Fixture fixture = new Fixture(refreshSettings(1, 2));
    fixture.resolve("client-one");
    fixture.resolve("client-two");
    fixture.resolve("client-three");

    fixture.clock.advance(Duration.ofMinutes(6));

    assertThat(fixture.refresher.refresh()).isEqualTo(2);
  }

  @Test
  void aClientThatTheResolverNoLongerKnowsIsDropped() {
    final Fixture fixture = new Fixture(refreshSettings(1, 10));
    fixture.resolve("client-one");
    fixture.clock.advance(Duration.ofMinutes(6));

    fixture.resolver.answerFor = clientId -> null;
    assertThat(fixture.refresher.refresh()).isZero();
    assertThat(fixture.cache.get("client-one")).isNull();
  }

  @Test
  void aResolverThatFailsLeavesTheEntryAlone() {
    final Fixture fixture = new Fixture(refreshSettings(1, 10));
    fixture.resolve("client-one");
    fixture.clock.advance(Duration.ofMinutes(6));

    fixture.resolver.failure = new ClientRegistryException("the resolver could not be reached");
    assertThat(fixture.refresher.refresh()).isZero();
    assertThat(fixture.cache.get("client-one")).isNotNull();
    fixture.refresher.run();
  }

  @Test
  void trustMarksThatWereAskedForOnDemandAreCarriedOver() {
    final Fixture fixture = new Fixture(refreshSettings(1, 10));
    fixture.resolve("client-one");
    fixture.cache.put(fixture.cache.get("client-one")
        .withTrustMark(MARK_TWO, fixture.clock.instant().plus(Duration.ofHours(1))));

    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(fixture.refresher.refresh()).isEqualTo(1);

    assertThat(fixture.cache.get("client-one").getMarks(fixture.clock.instant())).contains(MARK_TWO);
  }

  @Test
  void aTrustMarkThatHasExpiredIsNotCarriedOver() {
    final Fixture fixture = new Fixture(refreshSettings(1, 10));
    fixture.resolve("client-one");
    fixture.cache.put(fixture.cache.get("client-one")
        .withTrustMark(MARK_TWO, fixture.clock.instant().plus(Duration.ofMinutes(1))));

    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(fixture.refresher.refresh()).isEqualTo(1);

    assertThat(fixture.cache.get("client-one").onDemandTrustMarks()).isEmpty();
  }

  @Test
  void theJobIsOffByDefault() {
    final Fixture off = new Fixture(FederationCacheSettings.RefreshSettings.disabled());
    off.refresher.start();
    off.refresher.close();
    assertThat(FederationCacheSettings.defaults().refresh().enabled()).isFalse();
  }

  @Test
  void theJobCanBeStartedAndStopped() {
    final Fixture fixture = new Fixture(new FederationCacheSettings.RefreshSettings(true,
        Duration.ofMillis(100), Duration.ofMinutes(5), 1, Duration.ofMinutes(10), 10, 100));
    try {
      fixture.refresher.start();
      fixture.refresher.start();
    }
    finally {
      fixture.refresher.close();
      fixture.refresher.close();
    }
  }

  @Test
  void noQualifyingClientsMeansNothingToDo() {
    final Fixture fixture = new Fixture(refreshSettings(5, 10));
    assertThat(fixture.refresher.refresh()).isZero();
  }

  private static FederationCacheSettings.RefreshSettings refreshSettings(
      final int minimumLookups, final int maximumClients) {
    return new FederationCacheSettings.RefreshSettings(true, Duration.ofMinutes(1), Duration.ofMinutes(5),
        minimumLookups, Duration.ofMinutes(10), maximumClients, 100);
  }

  /**
   * The parts of a test.
   */
  private static class Fixture {

    /** The clock of the test. */
    final TestClock clock = new TestClock();

    /** The cache of the test. */
    final InMemoryFederationCache cache;

    /** The resolver of the test. */
    final StubResolver resolver = new StubResolver();

    /** How often each client is looked up. */
    final LookupTracker lookupTracker;

    /** The refresher under test. */
    final FederationCacheRefresher refresher;

    Fixture(final FederationCacheSettings.RefreshSettings refresh) {
      final FederationCacheSettings settings = new FederationCacheSettings(null,
          FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE, refresh);
      this.cache = new InMemoryFederationCache(this.clock);
      this.lookupTracker = new LookupTracker(refresh.maximumTrackedClients(), refresh.lookupPeriod(), this.clock);
      this.refresher = new FederationCacheRefresher(
          this.cache, this.resolver, this.lookupTracker, settings, this.clock);
      this.resolver.answerFor = clientId -> new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
          this.clock.instant().plus(VALIDITY));
    }

    /**
     * Records a lookup of a client and puts its entry in the cache.
     *
     * @param clientId the {@code client_id} of the client
     */
    void resolve(final String clientId) {
      this.lookupTracker.record(clientId);
      this.cache.put(CachedClientRecord.found(
          new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
              this.clock.instant().plus(VALIDITY)),
          this.clock.instant(), null));
    }

  }

}
