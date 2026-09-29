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
package se.swedenconnect.spring.authnserver.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;

/**
 * Tests for {@link AuthenticationUsageTrack} and {@link AuthenticationUse}.
 *
 * @author Martin Lindström
 */
class AuthenticationUsageTrackTest {

  static final Instant INSTANT = Instant.parse("2026-09-29T08:12:00Z");

  @Test
  void anEmptyTrackHasNoRecords() {
    final AuthenticationUsageTrack track = new AuthenticationUsageTrack();
    assertThat(track.size()).isZero();
    assertThat(track.getUsages()).isEmpty();
    assertThat(track.getOriginalAuthentication()).isNull();
    assertThat(track.getLatestUse()).isNull();
  }

  @Test
  void theFirstRecordIsTheOriginalAuthentication() {
    final AuthenticationUse original = new AuthenticationUse(AuthenticationProtocol.SAML,
        "https://sp.example.com/sp", "_1a2b3c", INSTANT, List.of(AttributeIdentifiers.SURNAME));
    final AuthenticationUsageTrack track = new AuthenticationUsageTrack(original);

    assertThat(track.getOriginalAuthentication()).isEqualTo(original);
    assertThat(track.getLatestUse()).isEqualTo(original);

    final AuthenticationUse second = new AuthenticationUse(AuthenticationProtocol.OIDC, "client-1", null,
        INSTANT.plusSeconds(60), List.of(AttributeIdentifiers.GIVEN_NAME));
    track.registerUse(second);

    assertThat(track.size()).isEqualTo(2);
    assertThat(track.getOriginalAuthentication()).isEqualTo(original);
    assertThat(track.getLatestUse()).isEqualTo(second);
    assertThat(track.getUsages()).containsExactly(original, second);
    assertThat(track.toString()).contains("client-1");
  }

  @Test
  void theUsageListIsUnmodifiable() {
    final AuthenticationUsageTrack track = new AuthenticationUsageTrack();
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> track.getUsages().add(use()));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void aRecordRequiresProtocolRequesterInstantAndRequestedAttributes() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationUse(null, "client-1", null, INSTANT, List.of()))
        .withMessage("protocol must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationUse(AuthenticationProtocol.OIDC, null, null, INSTANT, List.of()))
        .withMessage("requester must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationUse(AuthenticationProtocol.OIDC, "client-1", null, null, List.of()))
        .withMessage("instant must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationUse(AuthenticationProtocol.OIDC, "client-1", null, INSTANT, null))
        .withMessage("requestedAttributes must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationUsageTrack().registerUse(null))
        .withMessage("use must not be null");
  }

  @Test
  void aRecordWithoutARequestIdOrRequestedAttributesIsAllowed() {
    final AuthenticationUse use =
        new AuthenticationUse(AuthenticationProtocol.OIDC, "client-1", null, INSTANT, List.of());
    assertThat(use.requestId()).isNull();
    assertThat(use.requestedAttributes()).isEmpty();
  }

  @Test
  void theRequestedAttributesAreCopied() {
    final List<String> requested = new ArrayList<>(List.of(AttributeIdentifiers.SURNAME));
    final AuthenticationUse use =
        new AuthenticationUse(AuthenticationProtocol.SAML, "sp", "_1", INSTANT, requested);
    requested.add(AttributeIdentifiers.GIVEN_NAME);
    assertThat(use.requestedAttributes()).containsExactly(AttributeIdentifiers.SURNAME);
  }

  @Test
  void theTrackSurvivesSerialization() throws Exception {
    final AuthenticationUsageTrack track = new AuthenticationUsageTrack(use());
    track.registerUse(new AuthenticationUse(AuthenticationProtocol.OIDC, "client-1", null, INSTANT.plusSeconds(10),
        List.of(AttributeIdentifiers.EMAIL)));

    final AuthenticationUsageTrack restored = SerializationTestSupport.roundTrip(track);
    assertThat(restored).isEqualTo(track).hasSameHashCodeAs(track);
    assertThat(restored.getUsages()).isEqualTo(track.getUsages());
  }

  private static AuthenticationUse use() {
    return new AuthenticationUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1a2b3c", INSTANT,
        List.of(AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME));
  }

}
