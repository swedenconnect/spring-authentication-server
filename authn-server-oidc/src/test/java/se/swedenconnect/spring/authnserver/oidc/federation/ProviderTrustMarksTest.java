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
import static se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport.ISSUER;
import static se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport.LOA3;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.spring.audit.appevents.SystemAlertEvent;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link ProviderTrustMarks}.
 *
 * @author Martin Lindström
 */
class ProviderTrustMarksTest {

  private static final Duration RETRY = Duration.ofMinutes(5);

  private final ECKey issuerKey = FederationSupport.key("tmi");

  private final FederationSupport.TestClock clock = new FederationSupport.TestClock();

  private final FederationSupport.StubFederationClient client = new FederationSupport.StubFederationClient();

  @TempDir
  Path directory;

  @Test
  void aFetchedTrustMarkIsCheckedAndPublished() {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.client.answer(mark);
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);

    assertThat(trustMarks.refresh()).isEqualTo(1);

    assertThat(trustMarks.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, mark.serialize()));
    assertThat(this.client.requests).hasSize(1);
    assertThat(this.client.requests.getFirst().subject().getValue()).isEqualTo(ENTITY_ID);
    assertThat(this.client.requests.getFirst().trustMarkType().getValue()).isEqualTo(LOA3);
    assertThat(this.client.requests.getFirst().trustMarkIssuer().getValue()).isEqualTo(ISSUER);
    final TrustMarkState state = trustMarks.getStates().getFirst();
    assertThat(state.published()).isTrue();
    assertThat(state.isFailing()).isFalse();
    assertThat(state.expiresAt()).isEqualTo(this.clock.instant().plus(Duration.ofDays(30)));
  }

  @Test
  void aTrustMarkIsFetchedAgainWhenThreeQuartersOfItsLifetimeHavePassed() {
    final SignedJWT first = this.mark(LOA3, Duration.ofDays(4));
    final SignedJWT second = this.mark(LOA3, Duration.ofDays(8));
    this.client.answer(first).answer(second);
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);
    trustMarks.refresh();

    this.clock.advance(Duration.ofDays(3).minusMinutes(1));
    assertThat(trustMarks.refresh()).isZero();
    this.clock.advance(Duration.ofMinutes(1));
    assertThat(trustMarks.refresh()).isEqualTo(1);

    assertThat(trustMarks.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, second.serialize()));
  }

  @Test
  void aTrustMarkWithoutExpiryIsKeptAndNeverFetchedAgain() {
    final SignedJWT mark = this.mark(LOA3, null);
    this.client.answer(mark);
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);
    trustMarks.refresh();

    this.clock.advance(Duration.ofDays(3650));
    assertThat(trustMarks.refresh()).isZero();

    assertThat(this.client.requests).hasSize(1);
    assertThat(trustMarks.getTrustMarks()).hasSize(1);
    assertThat(trustMarks.getStates().getFirst().expiresAt()).isNull();
  }

  @Test
  void aTrustMarkThatFailsTheCheckIsNotPublished() {
    final ECKey otherKey = FederationSupport.key("other");
    final Instant now = this.clock.instant();
    final Instant exp = now.plus(Duration.ofDays(1));
    final List<SignedJWT> invalid = List.of(
        FederationSupport.trustMark(otherKey, LOA3, now, exp),
        FederationSupport.trustMark(this.issuerKey, "jwt", ISSUER, ENTITY_ID, LOA3, now, exp),
        FederationSupport.trustMark(this.issuerKey, "trust-mark+jwt", "https://other.example.com", ENTITY_ID, LOA3,
            now, exp),
        FederationSupport.trustMark(this.issuerKey, "trust-mark+jwt", ISSUER, "https://other.example.com", LOA3,
            now, exp),
        FederationSupport.trustMark(this.issuerKey, CONTRACT, now, exp),
        FederationSupport.trustMark(this.issuerKey, LOA3, now.minus(Duration.ofDays(2)),
            now.minus(Duration.ofDays(1))));

    for (final SignedJWT mark : invalid) {
      final FederationSupport.StubFederationClient stub = new FederationSupport.StubFederationClient().answer(mark);
      final ProviderTrustMarks trustMarks = new ProviderTrustMarks(ENTITY_ID,
          List.of(FederationSupport.source(LOA3, this.issuerKey)), stub, null, RETRY, this.clock);

      assertThat(trustMarks.refresh()).isZero();
      assertThat(trustMarks.getTrustMarks()).isEmpty();
      assertThat(trustMarks.getStates().getFirst().isFailing()).isTrue();
    }
  }

  @Test
  void aFailedFetchKeepsTheCurrentTrustMarkUntilItExpiresAndIsRetried() {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(4));
    this.client.answer(mark).answer(new ClientRegistryException("Connection refused"));
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);
    trustMarks.refresh();

    this.clock.advance(Duration.ofDays(3));
    assertThat(trustMarks.refresh()).isZero();

    TrustMarkState state = trustMarks.getStates().getFirst();
    assertThat(state.isFailing()).isTrue();
    assertThat(state.consecutiveFailures()).isEqualTo(1);
    assertThat(state.lastFailureReason()).contains("Connection refused");
    assertThat(state.published()).isTrue();
    assertThat(trustMarks.getTrustMarks()).hasSize(1);

    this.clock.advance(RETRY.minusSeconds(1));
    trustMarks.refresh();
    assertThat(this.client.requests).hasSize(2);
    this.clock.advance(Duration.ofSeconds(1));
    trustMarks.refresh();
    assertThat(this.client.requests).hasSize(3);
    assertThat(trustMarks.getStates().getFirst().consecutiveFailures()).isEqualTo(2);

    this.clock.advance(Duration.ofDays(1));
    assertThat(trustMarks.getTrustMarks()).isEmpty();
    state = trustMarks.getStates().getFirst();
    assertThat(state.published()).isFalse();
    assertThat(state.expiresAt()).isNull();
  }

  @Test
  void aFailedFetchIsPublishedAsASystemAlert() {
    this.client.answer(new ClientRegistryException("Connection refused"));
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);
    final List<Object> events = new ArrayList<>();
    trustMarks.setEventPublisher(events::add);

    trustMarks.refresh();

    assertThat(events).singleElement().isInstanceOfSatisfying(SystemAlertEvent.class, e -> {
      assertThat(e.getMessage()).contains(LOA3, ENTITY_ID);
      assertThat(e.getException()).hasMessageContaining("Connection refused");
    });
  }

  @Test
  void aSuccessfulFetchRaisesNoAlert() {
    this.client.answer(this.mark(LOA3, Duration.ofDays(30)));
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);
    final List<Object> events = new ArrayList<>();
    trustMarks.setEventPublisher(events::add);

    assertThat(trustMarks.refresh()).isOne();
    assertThat(events).isEmpty();
  }

  @Test
  void anIssuerThatHasNotIssuedTheTrustMarkIsAFailure() {
    final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3);

    assertThat(trustMarks.refresh()).isZero();

    assertThat(trustMarks.getStates().getFirst().lastFailureReason()).contains("has not issued");
  }

  @Test
  void aFailureForOneTypeDoesNotAffectAnother() {
    final ECKey contractKey = FederationSupport.key("contract");
    final SignedJWT contract = FederationSupport.trustMark(contractKey, CONTRACT, this.clock.instant(), null);
    final FederationSupport.StubFederationClient stub = new FederationSupport.StubFederationClient() {
      @Override
      public SignedJWT trustMark(final FederationRequest<TrustMarkRequest> request) {
        if (LOA3.equals(request.parameters().trustMarkType().getValue())) {
          throw new ClientRegistryException("Connection refused");
        }
        return contract;
      }
    };
    final ProviderTrustMarks trustMarks = new ProviderTrustMarks(ENTITY_ID,
        List.of(FederationSupport.source(LOA3, this.issuerKey), FederationSupport.source(CONTRACT, contractKey)),
        stub, null, RETRY, this.clock);

    assertThat(trustMarks.refresh()).isEqualTo(1);

    assertThat(trustMarks.getTrustMarks()).extracting(TrustMarkEntry::trustMarkType).containsExactly(CONTRACT);
    assertThat(trustMarks.getStates()).extracting(TrustMarkState::isFailing).containsExactly(true, false);
  }

  @Test
  void fetchedTrustMarksArePersistedAndUsedAfterARestart() {
    final SignedJWT mark = this.mark(LOA3, Duration.ofDays(30));
    this.client.answer(mark);
    this.trustMarks(this.directory, LOA3).refresh();

    final FederationSupport.StubFederationClient restarted =
        new FederationSupport.StubFederationClient().answer(new ClientRegistryException("Connection refused"));
    final ProviderTrustMarks afterRestart = new ProviderTrustMarks(ENTITY_ID,
        List.of(FederationSupport.source(LOA3, this.issuerKey)), restarted, this.directory, RETRY, this.clock);
    afterRestart.loadStored();

    assertThat(afterRestart.getTrustMarks()).containsExactly(new TrustMarkEntry(LOA3, mark.serialize()));
    assertThat(afterRestart.refresh()).isZero();
    assertThat(restarted.requests).isEmpty();
  }

  @Test
  void anExpiredOrInvalidStoredTrustMarkIsNotUsed() throws IOException {
    this.client.answer(this.mark(LOA3, Duration.ofDays(30)));
    this.trustMarks(this.directory, LOA3).refresh();
    final Path file;
    try (final Stream<Path> files = Files.list(this.directory)) {
      file = files.filter(f -> f.toString().endsWith(".jwt")).findFirst().orElseThrow();
    }

    final Instant now = this.clock.instant();
    Files.writeString(file, FederationSupport.trustMark(this.issuerKey, LOA3, now.minus(Duration.ofDays(2)),
        now.minus(Duration.ofDays(1))).serialize());
    ProviderTrustMarks afterRestart = this.trustMarks(this.directory, LOA3);
    afterRestart.loadStored();
    assertThat(afterRestart.getTrustMarks()).isEmpty();

    Files.writeString(file, FederationSupport.trustMark(FederationSupport.key("x"), LOA3, now,
        now.plus(Duration.ofDays(1))).serialize());
    afterRestart = this.trustMarks(this.directory, LOA3);
    afterRestart.loadStored();
    assertThat(afterRestart.getTrustMarks()).isEmpty();

    Files.writeString(file, "garbage");
    afterRestart = this.trustMarks(this.directory, LOA3);
    afterRestart.loadStored();
    assertThat(afterRestart.getTrustMarks()).isEmpty();
  }

  @Test
  void withoutACacheDirectoryNothingIsStored() throws IOException {
    this.client.answer(this.mark(LOA3, Duration.ofDays(30)));
    this.trustMarks(null, LOA3).refresh();
    try (final Stream<Path> files = Files.list(this.directory)) {
      assertThat(files).isEmpty();
    }
  }

  @Test
  void aTypeMayOnlyBeConfiguredOnce() {
    assertThatThrownBy(() -> new ProviderTrustMarks(ENTITY_ID, List.of(FederationSupport.source(LOA3, this.issuerKey),
        FederationSupport.source(LOA3, this.issuerKey)), this.client, null, RETRY, this.clock))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ProviderTrustMarks(ENTITY_ID, List.of(), this.client, null, Duration.ZERO,
        this.clock)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theJobCanBeStartedAndStopped() {
    this.client.answer(this.mark(LOA3, Duration.ofDays(30)));
    try (final ProviderTrustMarks trustMarks = this.trustMarks(null, LOA3)) {
      trustMarks.start();
      trustMarks.start();
    }
    try (final ProviderTrustMarks none = new ProviderTrustMarks(ENTITY_ID, List.of())) {
      none.start();
      assertThat(none.getTrustMarks()).isEmpty();
    }
  }

  private SignedJWT mark(final String type, final Duration lifetime) {
    final Instant now = this.clock.instant();
    return FederationSupport.trustMark(this.issuerKey, type, now, lifetime != null ? now.plus(lifetime) : null);
  }

  private ProviderTrustMarks trustMarks(final Path cacheDirectory, final String type) {
    return new ProviderTrustMarks(ENTITY_ID, List.of(FederationSupport.source(type, this.issuerKey)), this.client,
        cacheDirectory, RETRY, this.clock);
  }

}
