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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ApplicationEvent;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;

/**
 * Tests for the management methods of {@link FederationClientBackend}, the changes it reports and the cache kept in a
 * file.
 *
 * @author Martin Lindström
 */
class FederationClientManagementTest extends FederationTestSupport {

  private final List<ApplicationEvent> events = new ArrayList<>();

  @Test
  void aResolvedClientIsAddedOnceAndAnExpiredEntryIsNotARemoval() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());

    fixture.backend.lookup(CLIENT_ID);
    fixture.clock.advance(Duration.ofMinutes(11));
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);

    assertThat(fixture.resolver.calls).isEqualTo(2);
    assertThat(this.added()).containsExactly(CLIENT_ID);
    assertThat(this.removed()).isEmpty();
  }

  @Test
  void aClientReportedAsNotFoundIsRemoved() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    fixture.clock.advance(Duration.ofMinutes(11));
    fixture.resolver.answer = null;

    assertThat(fixture.backend.lookup(CLIENT_ID)).isNull();
    fixture.clock.advance(Duration.ofMinutes(2));
    assertThat(fixture.backend.lookup(CLIENT_ID)).isNull();

    assertThat(this.removed()).containsExactly(CLIENT_ID);
    assertThat(this.events.stream().filter(ClientRemovedEvent.class::isInstance).findFirst().orElseThrow())
        .extracting(e -> ((ClientRemovedEvent) e).getReason())
        .isEqualTo(FederationClientBackend.NOT_FOUND_REASON);
  }

  @Test
  void anUnknownClientIdThatWasNeverKnownGivesNoEvent() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    assertThat(fixture.backend.lookup("https://unknown.example.com")).isNull();
    assertThat(this.events).isEmpty();
  }

  @Test
  void theCachedClientsAreListedAndShown() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    final OIDCClientMetadata metadata = clientMetadata("The Client");
    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "secret");
    metadata.setCustomField(OidcClientRecord.ORGANIZATION_IDENTIFIER, "urn:glue:iso6523:0007:5566778899");
    fixture.resolver.answer = new ResolvedClient(CLIENT_ID, metadata, Set.of(MARK_ONE),
        fixture.clock.instant().plus(Duration.ofHours(1)));
    fixture.backend.lookup(CLIENT_ID);
    fixture.backend.lookup("https://unknown.example.com");

    assertThat(fixture.backend.getClients()).singleElement()
        .satisfies(c -> assertThat(c.requester().identifier()).isEqualTo(CLIENT_ID))
        .satisfies(c -> assertThat(c.organizationNumber()).isEqualTo("urn:glue:iso6523:0007:5566778899"))
        .satisfies(c -> assertThat(c.marks()).containsExactly(MARK_ONE))
        .satisfies(c -> assertThat(c.source()).isEqualTo(FederationClientBackend.DEFAULT_NAME))
        .satisfies(c -> assertThat(c.expiresAt()).isEqualTo(fixture.clock.instant().plus(Duration.ofHours(1))));
    final RegisteredClient client = fixture.backend.getClient(CLIENT_ID);
    assertThat(client).isNotNull();
    assertThat(fixture.backend.getClient("https://unknown.example.com")).isNull();
    assertThat(fixture.backend.getClient("https://never.example.com")).isNull();

    final String json = fixture.backend.getMetadata(CLIENT_ID);
    assertThat(json).contains("\"client_name\":\"The Client\"").doesNotContain("secret");
    assertThat(fixture.backend.getMetadata("https://unknown.example.com")).isNull();

    assertThat(fixture.backend.getSources()).singleElement()
        .satisfies(s -> assertThat(s.clients()).isEqualTo(1))
        .satisfies(s -> assertThat(s.lastUpdate()).isEqualTo(fixture.clock.instant()))
        .extracting(ClientSource::name).isEqualTo(FederationClientBackend.DEFAULT_NAME);
  }

  @Test
  void aClientIsResolvedAgainOnRequest() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);

    fixture.clock.advance(Duration.ofMinutes(1));
    fixture.resolver.answer = fixture.resolved(Duration.ofHours(2), Set.of(MARK_ONE));
    final ClientUpdateResult result = fixture.backend.update(CLIENT_ID);

    assertThat(result.outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);
    assertThat(fixture.resolver.calls).isEqualTo(2);
    assertThat(fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(fixture.clock.instant().plus(Duration.ofHours(2)));
    assertThat(fixture.backend.getClient(CLIENT_ID).marks()).containsExactly(MARK_ONE);
    assertThat(this.added()).containsExactly(CLIENT_ID);
  }

  @Test
  void aClientThatIsNotFoundOnRequestIsRemoved() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    fixture.resolver.answer = null;

    assertThat(fixture.backend.update(CLIENT_ID).outcome()).isEqualTo(ClientUpdateResult.Outcome.REMOVED);
    assertThat(fixture.backend.getClient(CLIENT_ID)).isNull();
    assertThat(this.removed()).containsExactly(CLIENT_ID);
  }

  @Test
  void aFailedUpdateKeepsTheEntryHeldBefore() {
    final FederationClientBackendTest.Fixture fixture = this.fixture();
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    fixture.resolver.failure = new ClientRegistryException("the resolver could not be reached");

    final ClientUpdateResult result = fixture.backend.update(CLIENT_ID);

    assertThat(result.outcome()).isEqualTo(ClientUpdateResult.Outcome.FAILED);
    assertThat(result.message()).contains("could not be reached");
    assertThat(fixture.backend.getClient(CLIENT_ID)).isNotNull();
    assertThat(this.removed()).isEmpty();

    assertThat(fixture.backend.update("https://never.example.com").outcome())
        .isEqualTo(ClientUpdateResult.Outcome.FAILED);
  }

  @Test
  void theRefresherReportsAClientThatIsNoLongerKnown() {
    final FederationCacheSettings settings = new FederationCacheSettings(null,
        FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE,
        new FederationCacheSettings.RefreshSettings(true, Duration.ofMinutes(1), Duration.ofMinutes(5), 1,
            Duration.ofHours(1), 10, 100));
    final FederationClientBackendTest.Fixture fixture = new FederationClientBackendTest.Fixture(settings);
    fixture.backend.setClientChangeTracker(this.tracker());
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(3), Set.of());
    fixture.backend.lookup(CLIENT_ID);

    final FederationCacheRefresher refresher = new FederationCacheRefresher(fixture.backend);
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(3), Set.of());
    assertThat(refresher.refresh()).isEqualTo(1);
    fixture.resolver.answer = null;
    assertThat(refresher.refresh()).isZero();

    assertThat(this.added()).containsExactly(CLIENT_ID);
    assertThat(this.removed()).containsExactly(CLIENT_ID);
  }

  @Test
  void theCachedClientsAreReportedWhenTheTrackerIsAssigned() {
    final FederationClientBackendTest.Fixture fixture =
        new FederationClientBackendTest.Fixture(FederationCacheSettings.defaults());
    fixture.resolver.answer = fixture.resolved(Duration.ofMinutes(10), Set.of());
    fixture.backend.lookup(CLIENT_ID);
    fixture.backend.lookup("https://unknown.example.com");
    assertThat(this.events).isEmpty();

    fixture.backend.setClientChangeTracker(this.tracker());
    assertThat(this.added()).containsExactly(CLIENT_ID);
    fixture.backend.setClientChangeTracker(null);
  }

  @Test
  void theCacheInAFileSurvivesARestart(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("oidc/federation-cache.json");
    final TestClock clock = new TestClock();
    final InMemoryFederationCache cache = new InMemoryFederationCache(file, clock);
    final OIDCClientMetadata metadata = clientMetadata("The Client");
    cache.put(new CachedClientRecord(CLIENT_ID, metadata, Set.of(MARK_ONE), Map.of(),
        clock.instant().plus(Duration.ofHours(1))).withTrustMark(MARK_TWO, clock.instant().plus(Duration.ofHours(2))));
    cache.put(CachedClientRecord.notFound("https://unknown.example.com", clock.instant(), Duration.ofMinutes(10)));
    cache.put(new CachedClientRecord("https://short.example.com", metadata, Set.of(), Map.of(),
        clock.instant().plus(Duration.ofMinutes(5))));
    cache.remove("https://nothing.example.com");
    cache.close();
    assertThat(file).exists();

    clock.advance(Duration.ofMinutes(6));
    final InMemoryFederationCache restarted = new InMemoryFederationCache(file, clock);
    assertThat(restarted.size()).isEqualTo(2);
    final CachedClientRecord entry = restarted.get(CLIENT_ID);
    assertThat(entry).isNotNull();
    assertThat(entry.metadata().getName()).isEqualTo("The Client");
    assertThat(entry.getMarks(clock.instant())).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);
    assertThat(restarted.get("https://unknown.example.com")).isNotNull();
    assertThat(restarted.get("https://short.example.com")).isNull();
    restarted.close();
  }

  @Test
  void aCacheFileThatCannotBeReadIsNotUsed(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("federation-cache.json");
    Files.writeString(file, "not json");
    final InMemoryFederationCache cache = new InMemoryFederationCache(file, new TestClock());
    assertThat(cache.size()).isZero();

    Files.writeString(file, "[{\"clientId\":\"x\",\"metadata\":\"not json\",\"expiresAt\":\"2999-01-01T00:00:00Z\"}]");
    assertThat(new InMemoryFederationCache(file, new TestClock()).size()).isZero();
  }

  @Test
  void theCacheIsWrittenAfterAChange(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("federation-cache.json");
    final TestClock clock = new TestClock();
    final InMemoryFederationCache cache = new InMemoryFederationCache(file, clock);
    cache.put(new CachedClientRecord(CLIENT_ID, clientMetadata("The Client"), Set.of(), Map.of(),
        clock.instant().plus(Duration.ofHours(1))));
    final long deadline = System.currentTimeMillis() + InMemoryFederationCache.WRITE_DELAY.toMillis() + 5000;
    while (!Files.exists(file) && System.currentTimeMillis() < deadline) {
      Thread.sleep(100);
    }
    assertThat(file).exists();
    cache.close();
    new InMemoryFederationCache(clock).close();
  }

  private FederationClientBackendTest.Fixture fixture() {
    final FederationClientBackendTest.Fixture fixture =
        new FederationClientBackendTest.Fixture(FederationCacheSettings.defaults());
    fixture.backend.setClientChangeTracker(this.tracker());
    return fixture;
  }

  private ClientChangeTracker tracker() {
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.start();
    return tracker;
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

}
