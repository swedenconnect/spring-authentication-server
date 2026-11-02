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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.job.JobLock;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;

/**
 * Tests for {@link FederationClientCollector}.
 *
 * @author Martin Lindström
 */
class FederationClientCollectorTest extends FederationTestSupport {

  private static final String INTERMEDIATE = "https://im.example.com";

  private static final String RP_ONE = "https://rp1.example.com";

  private static final String RP_TWO = "https://rp2.example.com";

  private static final String RP_THREE = "https://rp3.example.com";

  private static final String RP_INTERMEDIATE = "https://rp-im.example.com";

  private static final String OP = "https://op.example.com";

  private static final String OTHER = "https://other.example.com";

  private final List<ApplicationEvent> events = new ArrayList<>();

  @Test
  void theWalkStartsAtTheTrustAnchorAndCachesEveryClient() {
    final Fixture fixture = this.federation(FederationCollectorSettings.defaults());

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result).isNotNull();
    assertThat(result.complete()).isTrue();
    assertThat(result.entities()).isEqualTo(8);
    assertThat(result.clients()).isEqualTo(4);
    assertThat(fixture.cachedClients()).containsExactlyInAnyOrder(RP_ONE, RP_TWO, RP_THREE, RP_INTERMEDIATE);
    assertThat(this.added()).containsExactlyInAnyOrder(RP_ONE, RP_TWO, RP_THREE, RP_INTERMEDIATE);
    assertThat(fixture.resolver.calls).containsExactlyInAnyOrder(TRUST_ANCHOR, INTERMEDIATE, RP_ONE, RP_TWO,
        RP_THREE, RP_INTERMEDIATE, OP, OTHER);

    // The entity that is both a client and lists subordinates is walked into
    assertThat(fixture.listedEntities()).containsExactly(TRUST_ANCHOR, INTERMEDIATE, RP_INTERMEDIATE);
    assertThat(fixture.client.listingRequests).allSatisfy(r -> {
      assertThat(r.parameters().entityType()).isNull();
      assertThat(r.parameters().intermediate()).isNull();
      assertThat(r.parameters().trustMarked()).isNull();
      assertThat(r.parameters().trustMarkType()).isNull();
      assertThat(r.federationEntityMetadata().get(HttpFederationClient.FEDERATION_LIST_ENDPOINT))
          .isEqualTo(r.federationEntityMetadata().get(HttpFederationClient.LISTING_ENTITY_ID) + "/list");
    });

    // An entity that is neither, and one that the resolver does not know, are only remembered
    assertThat(fixture.store.get(OP)).isNotNull().satisfies(r -> {
      assertThat(r.isFound()).isTrue();
      assertThat(r.toClient()).isNull();
      assertThat(r.listEndpoint()).isNull();
    });
    assertThat(fixture.store.get(OTHER)).isNotNull().satisfies(r -> assertThat(r.isFound()).isFalse());
  }

  @Test
  void theWalkStartsAtTheConfiguredIntermediates() {
    final Fixture fixture = this.federation(new FederationCollectorSettings(true, Duration.ofMinutes(30),
        List.of(INTERMEDIATE), true));

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.complete()).isTrue();
    assertThat(fixture.cachedClients()).containsExactlyInAnyOrder(RP_TWO, RP_THREE, RP_INTERMEDIATE);
    assertThat(fixture.resolver.calls).doesNotContain(TRUST_ANCHOR, RP_ONE, OP);
    assertThat(fixture.listedEntities()).containsExactly(INTERMEDIATE, RP_INTERMEDIATE);
  }

  @Test
  void aLoopInTheListingsIsVisitedOnce() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, INTERMEDIATE);
    fixture.lister(INTERMEDIATE, TRUST_ANCHOR, INTERMEDIATE, RP_ONE, INTERMEDIATE);
    fixture.rp(RP_ONE);

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.entities()).isEqualTo(3);
    assertThat(fixture.resolver.calls).containsExactly(TRUST_ANCHOR, INTERMEDIATE, RP_ONE);
    assertThat(fixture.listedEntities()).containsExactly(TRUST_ANCHOR, INTERMEDIATE);
    assertThat(fixture.cachedClients()).containsExactly(RP_ONE);
  }

  @Test
  void storedResolveResultsAreReusedUntilTheyExpire() {
    final Fixture fixture = this.federation(FederationCollectorSettings.defaults());
    fixture.collector.collect();
    fixture.resolver.calls.clear();
    fixture.client.listingRequests.clear();

    // Within the lifetime of the answers, only the not found answer has expired
    fixture.clock.advance(Duration.ofMinutes(30));
    fixture.collector.collect();
    assertThat(fixture.resolver.calls).containsExactly(OTHER);
    assertThat(fixture.listedEntities()).containsExactly(TRUST_ANCHOR, INTERMEDIATE, RP_INTERMEDIATE);

    // Once they have expired, every entity is resolved again
    fixture.resolver.calls.clear();
    fixture.clock.advance(Duration.ofHours(2));
    fixture.collector.collect();
    assertThat(fixture.resolver.calls).hasSize(8);
  }

  @Test
  void theMaximumAgeLimitsHowLongAResolveResultIsReused() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults(),
        new FederationCacheSettings(Duration.ofMinutes(20), FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE));
    fixture.lister(TRUST_ANCHOR, OP);
    fixture.op(OP);
    fixture.collector.collect();
    fixture.resolver.calls.clear();

    fixture.clock.advance(Duration.ofMinutes(10));
    fixture.collector.collect();
    assertThat(fixture.resolver.calls).isEmpty();

    fixture.clock.advance(Duration.ofMinutes(11));
    fixture.collector.collect();
    assertThat(fixture.resolver.calls).containsExactly(TRUST_ANCHOR, OP);
  }

  @Test
  void aClientThatExpiresBeforeTheNextRunIsRenewedWithItsTrustMarks() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, RP_ONE, RP_TWO);
    fixture.rp(RP_ONE, Duration.ofMinutes(50));
    fixture.rp(RP_TWO, Duration.ofHours(3));
    fixture.collector.collect();
    final Instant firstExpiry = fixture.cache.get(RP_ONE).expiresAt();
    fixture.cache.put(fixture.cache.get(RP_ONE).withTrustMark(MARK_TWO, null));
    fixture.resolver.calls.clear();

    // RP_ONE expires before the run after this one, RP_TWO does not
    fixture.clock.advance(Duration.ofMinutes(25));
    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.renewed()).isEqualTo(1);
    assertThat(fixture.resolver.calls).containsExactly(RP_ONE);
    assertThat(fixture.cache.get(RP_ONE).expiresAt()).isAfter(firstExpiry);
    assertThat(fixture.cache.get(RP_ONE).getMarks(fixture.clock.instant())).contains(MARK_TWO);
    assertThat(this.added()).containsExactlyInAnyOrder(RP_ONE, RP_TWO);
  }

  @Test
  void aCachedClientThatIsNotListedIsRenewedToo() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR);
    fixture.rp(RP_ONE, Duration.ofMinutes(20));
    fixture.backend.lookup(RP_ONE);
    fixture.resolver.calls.clear();

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.renewed()).isEqualTo(1);
    assertThat(fixture.resolver.calls).containsExactly(TRUST_ANCHOR, RP_ONE);
  }

  @Test
  void aCachedClientThatACompleteRunDidNotFindIsResolvedAgainAndStaysIfKnown() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE);
    fixture.rp(RP_TWO);
    fixture.backend.lookup(RP_TWO);
    fixture.resolver.calls.clear();

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.complete()).isTrue();
    assertThat(fixture.resolver.calls).containsExactly(TRUST_ANCHOR, RP_ONE, RP_TWO);
    assertThat(fixture.cachedClients()).containsExactlyInAnyOrder(RP_ONE, RP_TWO);
    assertThat(this.removed()).isEmpty();
  }

  @Test
  void aClientThatTheResolverNoLongerKnowsIsKeptUntilItExpires() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE, Duration.ofMinutes(90));
    fixture.collector.collect();
    final Instant expiresAt = fixture.cache.get(RP_ONE).expiresAt();

    // The client is no longer listed and no longer known
    fixture.lister(TRUST_ANCHOR);
    fixture.resolver.entities.remove(RP_ONE);
    fixture.clock.advance(Duration.ofHours(1).plusMinutes(1));
    FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.retained()).isEqualTo(1);
    assertThat(result.removed()).isZero();
    assertThat(fixture.cache.get(RP_ONE)).isNotNull().satisfies(e -> assertThat(e.isFound()).isTrue());
    assertThat(fixture.store.getRetainedClients()).singleElement().satisfies(c -> {
      assertThat(c.clientId()).isEqualTo(RP_ONE);
      assertThat(c.since()).isEqualTo(fixture.clock.instant());
      assertThat(c.expiresAt()).isEqualTo(expiresAt);
    });
    assertThat(this.removed()).isEmpty();

    // Once the entry has expired, the next not found answer removes the client
    fixture.clock.advance(Duration.ofMinutes(30));
    result = fixture.collector.collect();
    assertThat(result.retained()).isZero();
    assertThat(fixture.cache.get(RP_ONE)).isNotNull().satisfies(e -> assertThat(e.isFound()).isFalse());
    assertThat(fixture.store.getRetainedClients()).isEmpty();
    assertThat(this.removed()).containsExactly(RP_ONE);
  }

  @Test
  void aClientThatTheResolverNoLongerKnowsIsDroppedAtOnceWhenNotKept() {
    final Fixture fixture = new Fixture(new FederationCollectorSettings(true, Duration.ofMinutes(30), List.of(),
        false));
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE);
    fixture.collector.collect();

    fixture.lister(TRUST_ANCHOR);
    fixture.resolver.entities.remove(RP_ONE);
    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.removed()).isEqualTo(1);
    assertThat(fixture.cache.get(RP_ONE)).isNotNull().satisfies(e -> assertThat(e.isFound()).isFalse());
    assertThat(fixture.backend.getClient(RP_ONE)).isNull();
    assertThat(fixture.store.getRetainedClients()).isEmpty();
    assertThat(this.removed()).containsExactly(RP_ONE);
  }

  @Test
  void aNotFoundAnswerWhenRenewingIsHandledTheSameWay() {
    for (final boolean keep : List.of(true, false)) {
      this.events.clear();
      final Fixture fixture = new Fixture(new FederationCollectorSettings(true, Duration.ofMinutes(30), List.of(),
          keep));
      fixture.lister(TRUST_ANCHOR, RP_ONE);
      fixture.rp(RP_ONE, Duration.ofMinutes(50));
      fixture.collector.collect();

      // Still listed, but the resolver no longer knows it when it is renewed
      fixture.resolver.entities.remove(RP_ONE);
      fixture.clock.advance(Duration.ofMinutes(25));
      fixture.collector.collect();

      assertThat(fixture.cache.get(RP_ONE).isFound()).isEqualTo(keep);
      assertThat(fixture.store.getRetainedClients()).hasSize(keep ? 1 : 0);
      assertThat(this.removed()).hasSize(keep ? 0 : 1);
    }
  }

  @Test
  void aRetainedClientThatIsKnownAgainIsPutBack() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE, Duration.ofMinutes(40));
    fixture.collector.collect();
    fixture.lister(TRUST_ANCHOR);
    fixture.resolver.entities.remove(RP_ONE);
    fixture.collector.collect();
    assertThat(fixture.store.getRetainedClients()).hasSize(1);

    fixture.rp(RP_ONE, Duration.ofHours(3));
    fixture.clock.advance(Duration.ofMinutes(45));
    fixture.collector.collect();

    assertThat(fixture.cache.get(RP_ONE)).isNotNull().satisfies(e -> assertThat(e.isFound()).isTrue());
    assertThat(fixture.store.getRetainedClients()).isEmpty();
    assertThat(this.removed()).isEmpty();
  }

  @Test
  void aRetainedClientThatARequestHasResolvedIsNotResolvedAgain() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE, Duration.ofMinutes(40));
    fixture.collector.collect();
    fixture.lister(TRUST_ANCHOR);
    fixture.resolver.entities.remove(RP_ONE);
    fixture.collector.collect();

    // A request after the entry expired gets not found, which removes the client
    fixture.clock.advance(Duration.ofMinutes(41));
    assertThat(fixture.backend.lookup(RP_ONE)).isNull();
    assertThat(this.removed()).containsExactly(RP_ONE);
    fixture.resolver.calls.clear();

    fixture.collector.collect();
    assertThat(fixture.resolver.calls).doesNotContain(RP_ONE);
    assertThat(fixture.store.getRetainedClients()).isEmpty();
    assertThat(this.removed()).containsExactly(RP_ONE);
  }

  @Test
  void aPartialRunNeverCountsAsEvidenceThatAClientIsGone() {
    final Fixture fixture = this.federation(FederationCollectorSettings.defaults());
    fixture.collector.collect();
    fixture.resolver.calls.clear();

    // The intermediate can no longer list its subordinates
    fixture.client.listings.remove(INTERMEDIATE);
    fixture.resolver.entities.remove(RP_TWO);
    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.complete()).isFalse();
    assertThat(fixture.resolver.calls).doesNotContain(RP_TWO, RP_THREE, RP_INTERMEDIATE);
    assertThat(fixture.cachedClients()).contains(RP_TWO, RP_THREE, RP_INTERMEDIATE);
    assertThat(fixture.store.getRetainedClients()).isEmpty();
  }

  @Test
  void aFailedResolutionMakesTheRunPartial() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, INTERMEDIATE);
    fixture.rp(RP_ONE);
    fixture.backend.lookup(RP_ONE);
    fixture.resolver.failing.add(INTERMEDIATE);
    fixture.resolver.calls.clear();

    final FederationClientCollector.RunResult result = fixture.collector.collect();

    assertThat(result.complete()).isFalse();
    assertThat(fixture.resolver.calls).containsExactly(TRUST_ANCHOR, INTERMEDIATE);
  }

  @Test
  void aFailureDoesNotStopTheRunAndIsTriedAgainAtTheNextRun() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults());
    fixture.lister(TRUST_ANCHOR, OP, INTERMEDIATE, RP_ONE);
    fixture.op(OP);
    fixture.lister(INTERMEDIATE, RP_TWO);
    fixture.client.listings.remove(INTERMEDIATE);
    fixture.rp(RP_ONE);
    fixture.rp(RP_TWO);
    fixture.resolver.failing.add(OP);

    FederationClientCollector.RunResult result = fixture.collector.collect();
    assertThat(result.complete()).isFalse();
    assertThat(fixture.cachedClients()).containsExactly(RP_ONE);
    assertThat(fixture.store.get(OP)).isNull();

    fixture.resolver.failing.clear();
    fixture.client.listings.put(INTERMEDIATE, List.of(RP_TWO));
    fixture.resolver.calls.clear();
    result = fixture.collector.collect();
    assertThat(result.complete()).isTrue();
    assertThat(fixture.resolver.calls).containsExactlyInAnyOrder(OP, RP_TWO);
    assertThat(fixture.cachedClients()).containsExactlyInAnyOrder(RP_ONE, RP_TWO);
  }

  @Test
  void theJobIsNotStartedWhenTurnedOff() {
    final Fixture off = new Fixture(new FederationCollectorSettings(false, Duration.ofMinutes(30), List.of(), true));
    off.collector.start();
    assertThat(off.collector.isStarted()).isFalse();

    final Fixture on = new Fixture(FederationCollectorSettings.defaults());
    on.collector.start();
    on.collector.start();
    assertThat(on.collector.isStarted()).isTrue();
    on.collector.close();
    assertThat(on.collector.isStarted()).isFalse();
  }

  @Test
  void aRunIsSkippedWhenAnotherNodeHoldsTheLock() {
    final Fixture fixture = new Fixture(FederationCollectorSettings.defaults(), FederationCacheSettings.defaults(),
        new InMemoryFederationCache(new TestClock()) {
          @Override
          public @NonNull JobLock getJobLock() {
            return (job, lease) -> false;
          }
        });
    fixture.lister(TRUST_ANCHOR, RP_ONE);
    fixture.rp(RP_ONE);

    assertThat(fixture.collector.collect()).isNull();
    fixture.collector.run();
    assertThat(fixture.resolver.calls).isEmpty();
  }

  @Test
  void theSettingsAreValidated() {
    final FederationCollectorSettings defaults = FederationCollectorSettings.defaults();
    assertThat(defaults.enabled()).isTrue();
    assertThat(defaults.interval()).isEqualTo(Duration.ofMinutes(30));
    assertThat(defaults.intermediates()).isEmpty();
    assertThat(defaults.keepUntilExpiry()).isTrue();
    assertThatThrownBy(() -> new FederationCollectorSettings(true, Duration.ZERO, List.of(), true))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new FederationCollectorSettings(true, Duration.ofMinutes(1), List.of(" "), true))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * Sets up a federation: the trust anchor lists an intermediate, a client, an OP and an entity that the resolver
   * does not know. The intermediate lists a client and an entity that is both a client and lists a client.
   *
   * @param settings the settings of the job
   * @return the fixture
   */
  private Fixture federation(final FederationCollectorSettings settings) {
    final Fixture fixture = new Fixture(settings);
    fixture.lister(TRUST_ANCHOR, INTERMEDIATE, RP_ONE, OP, OTHER);
    fixture.lister(INTERMEDIATE, RP_TWO, RP_INTERMEDIATE);
    fixture.rp(RP_ONE);
    fixture.rp(RP_TWO);
    fixture.op(OP);
    fixture.entity(RP_INTERMEDIATE, true, true, Duration.ofHours(2));
    fixture.client.listings.put(RP_INTERMEDIATE, List.of(RP_THREE));
    fixture.rp(RP_THREE);
    return fixture;
  }

  private List<String> added() {
    return this.events.stream()
        .filter(ClientAddedEvent.class::isInstance)
        .map(e -> ((ClientAddedEvent) e).getClient().identifier())
        .toList();
  }

  private List<String> removed() {
    return this.events.stream()
        .filter(ClientRemovedEvent.class::isInstance)
        .map(e -> ((ClientRemovedEvent) e).getClient().identifier())
        .toList();
  }

  /**
   * The parts of a test.
   */
  private class Fixture {

    final TestClock clock;

    final FederationCache cache;

    final InMemoryFederationEntityStore store;

    final EntityResolver resolver;

    final StubFederationClient client = new StubFederationClient();

    final FederationClientBackend backend;

    final FederationClientCollector collector;

    Fixture(final FederationCollectorSettings settings) {
      this(settings, FederationCacheSettings.defaults());
    }

    Fixture(final FederationCollectorSettings settings, final FederationCacheSettings cacheSettings) {
      this(settings, cacheSettings, null);
    }

    Fixture(final FederationCollectorSettings settings, final FederationCacheSettings cacheSettings,
        final FederationCache cache) {
      this.clock = new TestClock();
      this.cache = cache != null ? cache : new InMemoryFederationCache(this.clock);
      this.store = new InMemoryFederationEntityStore(this.clock);
      this.resolver = new EntityResolver(this.clock);
      this.backend = new FederationClientBackend(this.resolver, (id, type) -> null, this.cache, cacheSettings,
          this.clock);
      final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
      tracker.setApplicationEventPublisher(e -> FederationClientCollectorTest.this.events.add((ApplicationEvent) e));
      tracker.start();
      this.backend.setClientChangeTracker(tracker);
      this.collector = new FederationClientCollector(this.backend, this.store, this.client,
          FederationSettings.of(new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
              new FederationSettings.Resolver(TRUST_ANCHOR, null, null)),
          settings);
    }

    void lister(final String entityId, final String... subordinates) {
      this.entity(entityId, false, true, Duration.ofHours(2));
      this.client.listings.put(entityId, List.of(subordinates));
    }

    void rp(final String entityId) {
      this.rp(entityId, Duration.ofHours(2));
    }

    void rp(final String entityId, final Duration validity) {
      this.entity(entityId, true, false, validity);
    }

    void op(final String entityId) {
      this.entity(entityId, false, false, Duration.ofHours(2));
    }

    void entity(final String entityId, final boolean client, final boolean lister, final Duration validity) {
      this.resolver.entities.put(entityId, new ResolvedEntity(entityId,
          client ? clientMetadata("Client " + entityId) : null, lister ? entityId + "/list" : null, Set.of(),
          Instant.EPOCH));
      this.resolver.validity.put(entityId, validity);
    }

    List<String> cachedClients() {
      return this.cache.getEntries().stream()
          .filter(CachedClientRecord::isFound)
          .map(CachedClientRecord::clientId)
          .toList();
    }

    List<String> listedEntities() {
      return this.client.listingRequests.stream()
          .map(r -> (String) r.federationEntityMetadata().get(HttpFederationClient.LISTING_ENTITY_ID))
          .toList();
    }

  }

  /**
   * A resolver that answers with the entities that the test has put in it.
   */
  private static class EntityResolver implements FederationResolver {

    /** The entities that the resolver knows. Their expiry is taken from {@link #validity}. */
    final Map<String, ResolvedEntity> entities = new HashMap<>();

    /** How long each answer is valid. */
    final Map<String, Duration> validity = new HashMap<>();

    /** The entities whose resolution fails. */
    final Set<String> failing = new HashSet<>();

    /** The entities that were resolved, in order. */
    final List<String> calls = new ArrayList<>();

    /** The clock, so that each answer gets a fresh expiry. */
    final TestClock clock;

    EntityResolver(final TestClock clock) {
      this.clock = clock;
    }

    @Override
    public @Nullable ResolvedClient resolve(final @NonNull String clientId) {
      final ResolvedEntity entity = this.resolveEntity(clientId);
      return entity != null ? entity.toClient() : null;
    }

    @Override
    public @Nullable ResolvedEntity resolveEntity(final @NonNull String entityId) {
      this.calls.add(entityId);
      if (this.failing.contains(entityId)) {
        throw new ClientRegistryException("The resolver could not be reached");
      }
      final ResolvedEntity entity = this.entities.get(entityId);
      if (entity == null) {
        return null;
      }
      return new ResolvedEntity(entityId, entity.clientMetadata(), entity.listEndpoint(), entity.trustMarkTypes(),
          this.clock.instant().plus(this.validity.get(entityId)));
    }

  }

}
