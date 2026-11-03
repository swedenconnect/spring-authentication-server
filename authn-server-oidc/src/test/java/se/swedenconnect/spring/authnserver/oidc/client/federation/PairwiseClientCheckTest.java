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
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.client.PairwiseClientCheck;
import se.swedenconnect.spring.authnserver.oidc.client.VerifiedSector;

/**
 * Tests for {@link PairwiseClientCheck}.
 *
 * @author Martin Lindström
 */
class PairwiseClientCheckTest extends FederationTestSupport {

  private static final String SECTOR = "https://sector.example.com/redirects.json";

  private static final String CALLBACK_ONE = "https://rp.example.com/cb";

  private static final String CALLBACK_TWO = "https://app.example.com/cb";

  private final StubSectorIdentifierFetcher fetcher = new StubSectorIdentifierFetcher();

  private final PairwiseClientCheck check = new PairwiseClientCheck(this.fetcher);

  @Test
  void aClientThatIsNotPairwiseIsNotChecked() {
    final OIDCClientMetadata metadata = pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO);
    metadata.setSubjectType(SubjectType.PUBLIC);
    assertThat(this.check.check(CLIENT_ID, metadata, null)).isEqualTo(PairwiseClientCheck.Outcome.valid(null));

    metadata.setSubjectType(null);
    assertThat(this.check.check(CLIENT_ID, metadata, null).isValid()).isTrue();
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void severalRedirectHostsWithoutSectorIdentifierUriIsInvalidUntilResolvedAgain() {
    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", null, CALLBACK_ONE, CALLBACK_TWO), null);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isFalse();
    assertThat(outcome.invalidReason()).contains("2 different hosts", "no sector_identifier_uri");
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void oneRedirectHostWithoutSectorIdentifierUriIsValid() {
    assertThat(this.check.check(CLIENT_ID,
        pairwiseMetadata("RP", null, CALLBACK_ONE, "https://rp.example.com/other"), null).isValid()).isTrue();
  }

  @Test
  void severalRedirectHostsAreRejectedAlsoWhenTheCheckIsTurnedOff() {
    final PairwiseClientCheck off = new PairwiseClientCheck(null);
    assertThat(off.isSectorIdentifierUriChecked()).isFalse();

    assertThat(off.check(CLIENT_ID, pairwiseMetadata("RP", null, CALLBACK_ONE, CALLBACK_TWO), null).isValid())
        .isFalse();
    assertThat(off.check(CLIENT_ID, pairwiseMetadata("RP", "http://sector.example.com", CALLBACK_ONE), null)
        .isValid()).isTrue();
  }

  @Test
  void aDocumentListingAllRedirectUrisIsRemembered() {
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_TWO, CALLBACK_ONE, "https://third.example.com/cb"));

    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO), null);

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.verifiedSector()).isEqualTo(new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE, CALLBACK_TWO)));

    // The same combination is not fetched again, also when the document is gone
    this.fetcher.failure = new IOException("gone");
    assertThat(this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_TWO, CALLBACK_ONE),
        outcome.verifiedSector())).isEqualTo(outcome);
    assertThat(this.fetcher.calls).containsExactly(SECTOR);
  }

  @Test
  void aDocumentThatDoesNotListEveryRedirectUriIsInvalidUntilResolvedAgain() {
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_ONE));

    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO), null);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isFalse();
    assertThat(outcome.verifiedSector()).isNull();
    assertThat(outcome.invalidReason()).isEqualTo(
        "the document at the sector_identifier_uri does not list the redirect URI " + CALLBACK_TWO);
  }

  @Test
  void aDocumentThatIsNotAnArrayOfStringsIsTreatedAsNotListingTheRedirectUris() {
    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE), null);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isFalse();
    assertThat(outcome.invalidReason()).contains("not a JSON array of strings");
  }

  @Test
  void aSectorIdentifierUriWithoutHttpsIsTreatedAsNotListingTheRedirectUris() {
    final PairwiseClientCheck.Outcome outcome = this.check.check(CLIENT_ID,
        pairwiseMetadata("RP", "http://sector.example.com/redirects.json", CALLBACK_ONE), null);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isFalse();
    assertThat(outcome.invalidReason()).contains("does not use https");
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void aDocumentThatCannotBeFetchedAtTheFirstCheckIsATemporaryMark() {
    this.fetcher.failure = new IOException("HTTP status 503");

    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE), null);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isTrue();
    assertThat(outcome.invalidReason()).contains("cannot be fetched", "HTTP status 503");
  }

  @Test
  void aChangedSectorIdentifierUriThatCannotBeFetchedIsATemporaryMark() {
    this.fetcher.failure = new IOException("unreachable");

    final PairwiseClientCheck.Outcome outcome = this.check.check(CLIENT_ID,
        pairwiseMetadata("RP", "https://new.example.com/redirects.json", CALLBACK_ONE),
        new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE)));

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isTrue();
    assertThat(outcome.verifiedSector()).isNull();
  }

  @Test
  void onlyChangedRedirectUrisAndADocumentThatCannotBeFetchedKeepTheClientValid() {
    this.fetcher.failure = new IOException("unreachable");
    final VerifiedSector earlier = new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE));

    final PairwiseClientCheck.Outcome outcome =
        this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO), earlier);

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.verifiedSector()).isEqualTo(earlier);
    assertThat(this.fetcher.calls).containsExactly(SECTOR);

    // When the document can be fetched, the new redirect URIs must be listed
    this.fetcher.failure = null;
    this.fetcher.documents.put(SECTOR, List.of(CALLBACK_ONE));
    assertThat(this.check.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO), earlier)
        .isValid()).isFalse();
  }

  @Test
  void withTheCheckTurnedOffTheDocumentIsNotFetched() {
    final PairwiseClientCheck off = new PairwiseClientCheck(null);
    final VerifiedSector earlier = new VerifiedSector(SECTOR, Set.of(CALLBACK_ONE));

    assertThat(off.check(CLIENT_ID, pairwiseMetadata("RP", SECTOR, CALLBACK_ONE, CALLBACK_TWO), earlier))
        .isEqualTo(PairwiseClientCheck.Outcome.valid(earlier));
    assertThat(this.fetcher.calls).isEmpty();
  }

}
