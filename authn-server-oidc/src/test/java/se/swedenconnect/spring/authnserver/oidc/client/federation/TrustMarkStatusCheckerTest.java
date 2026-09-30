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

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link TrustMarkStatusChecker}.
 *
 * @author Martin Lindström
 */
class TrustMarkStatusCheckerTest extends FederationTestSupport {

  private static final URI TRUST_MARK_ENDPOINT = URI.create("https://tmi.example.com/trust_mark");

  private static final URI STATUS_ENDPOINT = URI.create("https://tmi.example.com/trust_mark_status");

  private static final Duration INTERVAL = Duration.ofHours(1);

  @Test
  void aTrustMarkWithoutExpiryIsCheckedAndKeptWhenActive() {
    final Fixture fixture = new Fixture(true);
    final String mark = fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusResponse = trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, mark, "active");

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.client.trustMarkStatusRequests).hasSize(1);
    assertThat(fixture.client.trustMarkStatusRequests.getFirst().parameters().trustMarkJwt()).isEqualTo(mark);
    assertThat(fixture.client.trustMarkStatusRequests.getFirst().federationEntityMetadata())
        .containsEntry(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT, STATUS_ENDPOINT.toString());
    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void aWithdrawnTrustMarkIsRemovedAndTheClientNoLongerHasIt() {
    final Fixture fixture = new Fixture(true);
    final String mark = fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusResponse = trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, mark, "revoked");

    assertThat(fixture.checker.check()).isEqualTo(1);

    assertThat(fixture.cache.get(CLIENT_ID).onDemandTrustMarks()).isEmpty();
    assertThat(fixture.marks()).isEmpty();
  }

  @Test
  void anyStatusButActiveRemovesTheTrustMark() {
    for (final String status : List.of("expired", "invalid", "something-else")) {
      final Fixture fixture = new Fixture(true);
      final String mark = fixture.addOnDemandMark(null);
      fixture.client.trustMarkStatusResponse = trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, mark, status);

      assertThat(fixture.checker.check()).as(status).isEqualTo(1);
    }
  }

  @Test
  void aTrustMarkExpiringAfterTheNextCheckIsChecked() {
    final Fixture fixture = new Fixture(true);
    final String mark = fixture.addOnDemandMark(fixture.clock.instant().plus(INTERVAL).plusSeconds(60));
    fixture.client.trustMarkStatusResponse = trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, mark, "revoked");

    assertThat(fixture.checker.check()).isEqualTo(1);
  }

  @Test
  void aTrustMarkExpiringBeforeTheNextCheckIsNotChecked() {
    final Fixture fixture = new Fixture(true);
    fixture.addOnDemandMark(fixture.clock.instant().plus(INTERVAL));

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.client.trustMarkStatusRequests).isEmpty();
    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void anUnreachableStatusEndpointLeavesTheTrustMark() {
    final Fixture fixture = new Fixture(true);
    fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusFailure = new ClientRegistryException("Connection refused");

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void aStatusResponseThatDoesNotVerifyLeavesTheTrustMark() {
    final Fixture fixture = new Fixture(true);
    final String mark = fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusResponse = trustMarkStatus(key("other"), TRUST_MARK_ISSUER, mark, "revoked");

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void aStatusResponseAboutAnotherTrustMarkLeavesTheTrustMark() {
    final Fixture fixture = new Fixture(true);
    fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusResponse =
        trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, "x.y.z", "revoked");

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void anIssuerWithoutAStatusEndpointIsNotAsked() {
    final Fixture fixture = new Fixture(false);
    fixture.addOnDemandMark(null);

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.client.trustMarkStatusRequests).isEmpty();
  }

  @Test
  void trustMarksOfTheResolveResponseAreNotChecked() {
    final Fixture fixture = new Fixture(true);
    fixture.cache.put(CachedClientRecord.found(new ResolvedClient(CLIENT_ID, clientMetadata("The Client"),
        Set.of(MARK_TWO), fixture.clock.instant().plus(Duration.ofDays(1))), fixture.clock.instant(), null));

    assertThat(fixture.checker.check()).isZero();

    assertThat(fixture.client.trustMarkStatusRequests).isEmpty();
  }

  @Test
  void aTrustMarkReplacedDuringTheCheckIsNotRemoved() {
    final Fixture fixture = new Fixture(true);
    final String mark = fixture.addOnDemandMark(null);
    fixture.client.trustMarkStatusResponse = trustMarkStatus(fixture.issuerKey, TRUST_MARK_ISSUER, mark, "revoked");
    final FederationCache replacingCache = new InMemoryFederationCache(fixture.clock) {
      @Override
      public CachedClientRecord get(final String clientId) {
        return fixture.cache.get(clientId).withTrustMark(
            new TrustMarkRequester.TrustMark(MARK_TWO, null, "renewed.trust.mark"));
      }

      @Override
      public Collection<CachedClientRecord> getEntries() {
        return fixture.cache.getEntries();
      }

      @Override
      public void put(final CachedClientRecord record) {
        fixture.cache.put(record);
      }
    };
    final TrustMarkStatusChecker checker =
        new TrustMarkStatusChecker(replacingCache, fixture.settings, fixture.client, INTERVAL, fixture.clock);

    checker.check();

    assertThat(fixture.marks()).containsExactly(MARK_TWO);
  }

  @Test
  void theIntervalMustBePositive() {
    final Fixture fixture = new Fixture(true);
    assertThatThrownBy(() -> new TrustMarkStatusChecker(
        fixture.cache, fixture.settings, fixture.client, Duration.ZERO, fixture.clock))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theJobCanBeStartedAndStopped() {
    final Fixture fixture = new Fixture(true);
    try (final TrustMarkStatusChecker checker = new TrustMarkStatusChecker(fixture.cache, fixture.settings)) {
      checker.start();
      checker.start();
    }
  }

  /**
   * The objects of a test.
   */
  static class Fixture {

    final TestClock clock = new TestClock();

    final ECKey issuerKey = key("tmi");

    final InMemoryFederationCache cache = new InMemoryFederationCache(this.clock);

    final StubFederationClient client = new StubFederationClient();

    final FederationSettings settings;

    final TrustMarkStatusChecker checker;

    Fixture(final boolean withStatusEndpoint) {
      this.settings = new FederationSettings(
          new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
          new FederationSettings.Resolver(TRUST_ANCHOR, URI.create("https://ta.example.com/resolve"), null),
          Map.of(MARK_TWO, new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT,
              publicKeys(this.issuerKey), withStatusEndpoint ? STATUS_ENDPOINT : null)));
      this.checker = new TrustMarkStatusChecker(this.cache, this.settings, this.client, INTERVAL, this.clock);
    }

    /**
     * Puts a client in the cache that holds an on-demand trust mark.
     *
     * @param expiresAt the expiry of the trust mark, or {@code null}
     * @return the trust mark JWT
     */
    String addOnDemandMark(final Instant expiresAt) {
      final String mark = trustMark(this.issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_TWO, expiresAt).serialize();
      final CachedClientRecord record = CachedClientRecord.found(new ResolvedClient(CLIENT_ID,
          clientMetadata("The Client"), Set.of(), this.clock.instant().plus(Duration.ofDays(1))),
          this.clock.instant(), null);
      this.cache.put(record.withTrustMark(new TrustMarkRequester.TrustMark(MARK_TWO, expiresAt, mark)));
      return mark;
    }

    /**
     * Gets the marks of the client, as the client registry sees them.
     *
     * @return the marks
     */
    Set<String> marks() {
      final CachedClientRecord record = this.cache.get(CLIENT_ID);
      return record == null ? Set.of() : record.getMarks(this.clock.instant());
    }

  }

}
