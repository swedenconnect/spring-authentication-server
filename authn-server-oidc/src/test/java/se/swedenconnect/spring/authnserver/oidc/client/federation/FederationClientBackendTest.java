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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link FederationClientBackend}, its cache and the on-demand trust marks.
 *
 * @author Martin Lindström
 */
class FederationClientBackendTest extends FederationTestSupport {

  @Test
  void aResolvedClientIsCachedAndTheResolverIsNotAskedAgain() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of(MARK_ONE));

    final RequesterRecord first = fixture.backend.lookup(CLIENT_ID);
    final RequesterRecord second = fixture.backend.lookup(CLIENT_ID);

    assertThat(first).isNotNull();
    assertThat(first.getDisplayName(null)).isEqualTo("The Client");
    assertThat(first.marks()).containsExactly(MARK_ONE);
    assertThat(second).isNotNull();
    assertThat(fixture.resolver.calls).isEqualTo(1);
  }

  @Test
  void anEntryLivesUntilTheResolveResponseExpires() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());

    fixture.backend.lookup(CLIENT_ID);
    fixture.clock.advance(Duration.ofMinutes(9));
    fixture.backend.lookup(CLIENT_ID);
    assertThat(fixture.resolver.calls).isEqualTo(1);

    fixture.clock.advance(Duration.ofMinutes(2));
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    assertThat(fixture.resolver.calls).isEqualTo(2);
  }

  @Test
  void theMaximumAgeCutsAnEntryShort() {
    final Fixture fixture = new Fixture(new FederationCacheSettings(Duration.ofMinutes(5),
        FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE, FederationCacheSettings.RefreshSettings.disabled()));
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());

    fixture.backend.lookup(CLIENT_ID);
    fixture.clock.advance(Duration.ofMinutes(4));
    fixture.backend.lookup(CLIENT_ID);
    assertThat(fixture.resolver.calls).isEqualTo(1);

    fixture.clock.advance(Duration.ofMinutes(2));
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    assertThat(fixture.resolver.calls).isEqualTo(2);
  }

  @Test
  void theMaximumAgeIsNotUsedWhenTheResponseExpiresFirst() {
    final Fixture fixture = new Fixture(new FederationCacheSettings(Duration.ofHours(2),
        FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE, FederationCacheSettings.RefreshSettings.disabled()));
    final Instant expiresAt = fixture.clock.instant().plus(Duration.ofMinutes(10));
    fixture.resolver.answer = new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), Set.of(), expiresAt);

    fixture.backend.lookup(CLIENT_ID);

    assertThat(fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(expiresAt);
  }

  @Test
  void anUnknownClientIsCachedForTheConfiguredTime() {
    final Fixture fixture = new Fixture(new FederationCacheSettings(null, Duration.ofSeconds(30),
        FederationCacheSettings.RefreshSettings.disabled()));

    assertThat(fixture.backend.lookup(CLIENT_ID)).isNull();
    assertThat(fixture.backend.lookup(CLIENT_ID)).isNull();
    assertThat(fixture.resolver.calls).isEqualTo(1);

    fixture.clock.advance(Duration.ofSeconds(31));
    assertThat(fixture.backend.lookup(CLIENT_ID)).isNull();
    assertThat(fixture.resolver.calls).isEqualTo(2);
  }

  @Test
  void aResolverThatFailsIsNotCachedAsAnUnknownClient() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.failure = new ClientRegistryException("the resolver could not be reached");

    assertThatThrownBy(() -> fixture.backend.lookup(CLIENT_ID)).isInstanceOf(ClientRegistryException.class);
    assertThat(fixture.cache.get(CLIENT_ID)).isNull();

    fixture.resolver.failure = null;
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());
    assertThat(fixture.backend.lookup(CLIENT_ID)).isNotNull();
    assertThat(fixture.resolver.calls).isEqualTo(2);
  }

  @Test
  void anOnDemandTrustMarkIsAddedToTheCachedRecordAndNotAskedForAgain() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of(MARK_ONE));
    fixture.trustMarkRequester.answer =
        new TrustMarkRequester.TrustMark(MARK_TWO, fixture.clock.instant().plus(Duration.ofMinutes(30)));

    final RequesterRecord record = fixture.backend.requestMark(CLIENT_ID, MARK_TWO);

    assertThat(record).isNotNull();
    assertThat(record.marks()).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);
    assertThat(fixture.backend.lookup(CLIENT_ID).marks()).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);

    assertThat(fixture.backend.requestMark(CLIENT_ID, MARK_TWO).marks())
        .containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);
    assertThat(fixture.trustMarkRequester.calls).isEqualTo(1);
  }

  @Test
  void aTrustMarkThatTheResolveResponseAlreadyCarriesIsNotAskedFor() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of(MARK_ONE));

    assertThat(fixture.backend.requestMark(CLIENT_ID, MARK_ONE).marks()).containsExactly(MARK_ONE);
    assertThat(fixture.trustMarkRequester.calls).isZero();
  }

  @Test
  void anOnDemandTrustMarkIsDroppedWhenItExpiresBeforeTheRecord() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());
    fixture.trustMarkRequester.answer =
        new TrustMarkRequester.TrustMark(MARK_TWO, fixture.clock.instant().plus(Duration.ofMinutes(10)));

    assertThat(fixture.backend.requestMark(CLIENT_ID, MARK_TWO).marks()).containsExactly(MARK_TWO);

    fixture.clock.advance(Duration.ofMinutes(11));
    assertThat(fixture.backend.lookup(CLIENT_ID).marks()).isEmpty();
  }

  @Test
  void anOnDemandTrustMarkWithoutExpiryIsKeptForAsLongAsTheRecord() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(20), Set.of());
    fixture.trustMarkRequester.answer = new TrustMarkRequester.TrustMark(MARK_TWO, null);

    fixture.backend.requestMark(CLIENT_ID, MARK_TWO);

    assertThat(fixture.cache.get(CLIENT_ID).onDemandTrustMarks().get(MARK_TWO))
        .isEqualTo(fixture.cache.get(CLIENT_ID).expiresAt());
  }

  @Test
  void aTrustMarkThatIsNotObtainedLeavesTheRecordUnchanged() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of(MARK_ONE));

    final RequesterRecord record = fixture.backend.requestMark(CLIENT_ID, MARK_TWO);

    assertThat(record).isNotNull();
    assertThat(record.marks()).containsExactly(MARK_ONE);
  }

  @Test
  void aTrustMarkThatDoesNotVerifyIsNotAdded() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());
    fixture.trustMarkRequester.failure = new ClientRegistryException("the trust mark does not verify");

    assertThatThrownBy(() -> fixture.backend.requestMark(CLIENT_ID, MARK_TWO))
        .isInstanceOf(ClientRegistryException.class);
    assertThat(fixture.backend.lookup(CLIENT_ID).marks()).isEmpty();
  }

  @Test
  void askingForAMarkForAnUnknownClientGivesNothing() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());

    assertThat(fixture.backend.requestMark(CLIENT_ID, MARK_ONE)).isNull();
    assertThat(fixture.trustMarkRequester.calls).isZero();
  }

  @Test
  void theBackendCountsLookupsAndCanBeNamed() {
    final Fixture fixture = new Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(1), Set.of());

    assertThat(fixture.backend.getName()).isEqualTo(FederationClientBackend.DEFAULT_NAME);
    fixture.backend.setName("my-federation");
    assertThat(fixture.backend.getName()).isEqualTo("my-federation");

    fixture.backend.lookup(CLIENT_ID);
    fixture.backend.lookup(CLIENT_ID);

    assertThat(fixture.backend.getLookupTracker().getFrequentClients(2, 10)).containsExactly(CLIENT_ID);
  }

  /**
   * The parts of a test.
   */
  static class Fixture {

    /** The clock of the test. */
    final TestClock clock = new TestClock();

    /** The cache of the test. */
    final InMemoryFederationCache cache;

    /** The resolver of the test. */
    final StubResolver resolver = new StubResolver();

    /** The trust mark requester of the test. */
    final StubTrustMarkRequester trustMarkRequester = new StubTrustMarkRequester();

    /** The backend under test. */
    final FederationClientBackend backend;

    /** The cache settings. */
    final FederationCacheSettings settings;

    Fixture(final FederationCacheSettings settings) {
      this.settings = settings;
      this.cache = new InMemoryFederationCache(this.clock);
      this.backend = new FederationClientBackend(
          this.resolver, this.trustMarkRequester, this.cache, settings, this.clock);
    }

    /**
     * Creates what the resolver answers with.
     *
     * @param validity how long the resolution is valid
     * @param trustMarkTypes the trust mark types of the response
     * @return a {@link ResolvedClient}
     */
    ResolvedClient resolved(final Duration validity, final Set<String> trustMarkTypes) {
      return new ResolvedClient(CLIENT_ID, clientMetadata("The Client"), trustMarkTypes,
          this.clock.instant().plus(validity));
    }

  }

  /**
   * A resolver that answers with what the test has put in it.
   */
  static class StubResolver implements FederationResolver {

    /** What the resolver answers with, or {@code null} for an unknown client. */
    ResolvedClient answer;

    /** What the resolver fails with, or {@code null} if it does not fail. */
    ClientRegistryException failure;

    /** The number of calls made. */
    int calls;

    /** The clients that were asked for. */
    final List<String> asked = new ArrayList<>();

    /** Works out the answer from the client, taking precedence over {@link #answer} when set. */
    Function<String, ResolvedClient> answerFor;

    @Override
    public @Nullable ResolvedClient resolve(final @Nonnull String clientId) {
      this.calls++;
      this.asked.add(clientId);
      if (this.failure != null) {
        throw this.failure;
      }
      return this.answerFor != null ? this.answerFor.apply(clientId) : this.answer;
    }

  }

  /**
   * A trust mark requester that answers with what the test has put in it.
   */
  static class StubTrustMarkRequester implements TrustMarkRequester {

    /** What the requester answers with, or {@code null} for no trust mark. */
    TrustMark answer;

    /** What the requester fails with, or {@code null} if it does not fail. */
    ClientRegistryException failure;

    /** The number of calls made. */
    int calls;

    @Override
    public @Nullable TrustMark request(final @Nonnull String clientId, final @Nonnull String trustMarkType) {
      this.calls++;
      if (this.failure != null) {
        throw this.failure;
      }
      return this.answer != null && this.answer.type().equals(trustMarkType) ? this.answer : null;
    }

  }

}
