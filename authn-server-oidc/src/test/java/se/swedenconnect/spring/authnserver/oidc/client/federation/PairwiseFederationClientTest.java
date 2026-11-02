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

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientInvalidEvent;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;

/**
 * Tests for the check of pairwise clients when a {@link FederationClientBackend} resolves them.
 *
 * @author Martin Lindström
 */
class PairwiseFederationClientTest extends FederationTestSupport {

  private static final String SECTOR = "https://sector.example.com/redirects.json";

  private static final String CALLBACK_ONE = "https://client.example.com/cb";

  private static final String CALLBACK_TWO = "https://app.example.com/cb";

  private static final Duration TEMPORARY = Duration.ofMinutes(5);

  private final StubSectorIdentifierFetcher fetcher = new StubSectorIdentifierFetcher();

  private final List<ApplicationEvent> events = new ArrayList<>();

  private FederationClientBackendTest.Fixture fixture;

  @BeforeEach
  void setUp() {
    this.fixture = new FederationClientBackendTest.Fixture(new FederationCacheSettings(null, TEMPORARY));
    this.fixture.backend.setPairwiseClientCheck(new PairwiseClientCheck(this.fetcher));
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.start();
    this.fixture.backend.setClientChangeTracker(tracker);
  }

  @Test
  void theDocumentIsCheckedByDefault() {
    final FederationClientBackend backend = new FederationClientBackend(this.fixture.resolver,
        this.fixture.trustMarkRequester, this.fixture.cache, FederationCacheSettings.defaults());
    assertThat(backend.getPairwiseClientCheck().isSectorIdentifierUriChecked()).isTrue();
  }

  @Test
  void aClientWithARegistrationErrorIsKeptButMarkedAsInvalidUntilItIsResolvedAgain() {
    this.answer(Duration.ofHours(1), null, CALLBACK_ONE, CALLBACK_TWO);

    final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);

    assertThat(record).isNotNull();
    assertThat(record.isValid()).isFalse();
    assertThat(record.invalidReason()).contains("2 different hosts");
    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt())
        .isEqualTo(this.fixture.clock.instant().plus(Duration.ofHours(1)));

    // Shown as invalid in the list of clients
    final RegisteredClient registered = this.fixture.backend.getClient(CLIENT_ID);
    assertThat(registered.invalidReason()).isEqualTo(record.invalidReason());
    assertThat(this.fixture.backend.getClients()).singleElement()
        .satisfies(c -> assertThat(c.invalidReason()).isEqualTo(record.invalidReason()));

    // An audit event is given, with the client and the reason
    assertThat(this.events).hasSize(2);
    assertThat(this.events.get(0)).isInstanceOf(ClientAddedEvent.class);
    assertThat(this.events.get(1)).isInstanceOfSatisfying(ClientInvalidEvent.class, e -> {
      assertThat(e.getClient().identifier()).isEqualTo(CLIENT_ID);
      assertThat(e.getClient().source()).isEqualTo(FederationClientBackend.DEFAULT_NAME);
      assertThat(e.getReason()).isEqualTo(record.invalidReason());
    });

    // A request for the cached client does not resolve it again
    this.fixture.clock.advance(Duration.ofMinutes(30));
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fixture.resolver.calls).isEqualTo(1);

    // Once fixed, the client is valid when it is resolved again
    this.answer(Duration.ofHours(1), null, CALLBACK_ONE);
    assertThat(this.fixture.backend.update(CLIENT_ID).outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fixture.backend.getClient(CLIENT_ID).invalidReason()).isNull();
  }

  @Test
  void aDocumentThatCannotBeFetchedMarksTheClientForTheNotFoundTime() {
    this.answer(Duration.ofHours(1), SECTOR, CALLBACK_ONE);
    this.fetcher.failure = new IOException("HTTP status 503");

    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(this.fixture.clock.instant().plus(TEMPORARY));

    // Within the time, the client stays invalid and nothing is fetched
    this.fixture.clock.advance(TEMPORARY.minusSeconds(1));
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fetcher.calls).hasSize(1);

    // When the mark has run out, the client is resolved and checked again at its next request
    this.fixture.clock.advance(Duration.ofSeconds(2));
    this.fetcher.failure = null;
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_ONE));
    this.answer(Duration.ofHours(1), SECTOR, CALLBACK_ONE);
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fixture.resolver.calls).isEqualTo(2);
    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void theTemporaryMarkDoesNotOutliveTheEntry() {
    this.answer(Duration.ofMinutes(2), SECTOR, CALLBACK_ONE);
    this.fetcher.failure = new IOException("unreachable");

    this.fixture.backend.lookup(CLIENT_ID);

    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt())
        .isEqualTo(this.fixture.clock.instant().plus(Duration.ofMinutes(2)));
  }

  @Test
  void aSuccessfulCheckIsRememberedAcrossReResolvesUntilTheCombinationChanges() {
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_ONE, CALLBACK_TWO));
    this.answer(Duration.ofHours(1), SECTOR, CALLBACK_ONE);

    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(this.fixture.cache.get(CLIENT_ID).verifiedSector())
        .isEqualTo(new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE)));

    // The operator's re-resolve does not fetch the same combination again
    this.fixture.backend.update(CLIENT_ID);
    assertThat(this.fetcher.calls).hasSize(1);

    // New redirect URIs are checked, and when the document cannot be fetched the client stays valid with them
    this.fetcher.failure = new IOException("unreachable");
    this.answer(Duration.ofHours(1), SECTOR, CALLBACK_ONE, CALLBACK_TWO);
    this.fixture.backend.update(CLIENT_ID);
    assertThat(this.fetcher.calls).hasSize(2);
    final RequesterRecord record = this.fixture.backend.lookup(CLIENT_ID);
    assertThat(record.isValid()).isTrue();
    assertThat(record.getProtocolMetadata(OIDCClientMetadata.class)
        .getRedirectionURIs()).hasSize(2);

    // A new sector_identifier_uri that cannot be fetched marks the client
    this.answer(Duration.ofHours(1), "https://new.example.com/redirects.json", CALLBACK_ONE);
    this.fixture.backend.update(CLIENT_ID);
    assertThat(this.fixture.backend.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(this.fixture.cache.get(CLIENT_ID).expiresAt()).isEqualTo(this.fixture.clock.instant().plus(TEMPORARY));
  }

  @Test
  void aClientWhoseEntryHasExpiredIsCheckedAsForTheFirstTime() {
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_ONE));
    this.answer(Duration.ofMinutes(10), SECTOR, CALLBACK_ONE);
    this.fixture.backend.lookup(CLIENT_ID);

    this.fixture.clock.advance(Duration.ofMinutes(11));
    this.answer(Duration.ofMinutes(10), SECTOR, CALLBACK_ONE);
    this.fixture.backend.lookup(CLIENT_ID);

    assertThat(this.fetcher.calls).hasSize(2);
  }

  @Test
  void theRememberedCheckIsKeptInTheStoredForm() throws Exception {
    final CachedClientRecord record = new CachedClientRecord(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE),
        Set.of(MARK_ONE), Map.of(), this.fixture.clock.instant(), "the reason",
        new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE)));

    final CachedClientRecord read = StoredClientRecord.of(record).toRecord();

    assertThat(read.invalidReason()).isEqualTo("the reason");
    assertThat(read.verifiedSector()).isEqualTo(record.verifiedSector());
    assertThat(read.withTrustMark(MARK_TWO, null).invalidReason()).isEqualTo("the reason");
    assertThat(read.withTrustMark(MARK_TWO, null).withoutTrustMark(MARK_TWO).verifiedSector())
        .isEqualTo(record.verifiedSector());
  }

  private void answer(final Duration validity, final String sectorIdentifierUri, final String... redirectUris) {
    this.fixture.resolver.answer = new ResolvedClient(CLIENT_ID,
        pairwiseMetadata("The Client", sectorIdentifierUri, redirectUris), Set.of(),
        this.fixture.clock.instant().plus(validity));
  }

}
