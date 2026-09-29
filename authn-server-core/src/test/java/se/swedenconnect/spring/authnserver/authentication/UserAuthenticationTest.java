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

import java.io.Serializable;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;

/**
 * Tests for {@link UserAuthentication}.
 *
 * @author Martin Lindström
 */
class UserAuthenticationTest {

  /** Stand-in for the protocol specific request data that a protocol module puts in the result. */
  record TestRequestData(String requestId, String requester) implements Serializable {
  }

  @Test
  void theResultHoldsTheAuthenticatedUser() {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    final UserAuthentication authentication = new UserAuthentication(user);

    assertThat(authentication.getAuthenticatedUser()).isSameAs(user);
    assertThat(authentication.getPrincipal()).isSameAs(user);
    assertThat(authentication.getDetails()).isSameAs(user);
    assertThat(authentication.getCredentials()).isEqualTo("");
    assertThat(authentication.getAuthorities()).isEmpty();
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getName()).isEqualTo("197705232382");
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void aMissingUserIsRejected() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new UserAuthentication(null))
        .withMessage("user must not be null");
  }

  @Test
  void theResultIsReusableForSsoByDefault() {
    final UserAuthentication authentication = new UserAuthentication(AuthenticatedUserTest.user());
    assertThat(authentication.isReuseForSso()).isTrue();

    authentication.setReuseForSso(false);
    assertThat(authentication.isReuseForSso()).isFalse();

    authentication.setReuseForSso(true);
    assertThat(authentication.isReuseForSso()).isTrue();
  }

  @Test
  void aResultWithADisplayedSignMessageIsNeverReusable() {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    user.setSignMessageDisplayed(true, "sv");

    final UserAuthentication authentication = new UserAuthentication(user);
    assertThat(authentication.isReuseForSso()).isFalse();

    authentication.setReuseForSso(true);
    assertThat(authentication.isReuseForSso()).isFalse();
  }

  @Test
  void aSignMessageDisplayedAfterTheResultWasCreatedAlsoMakesItNonReusable() {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    final UserAuthentication authentication = new UserAuthentication(user);
    assertThat(authentication.isReuseForSso()).isTrue();

    user.setSignMessageDisplayed(true, "en");
    assertThat(authentication.isReuseForSso()).isFalse();
  }

  @Test
  void protocolRequestDataIsCarriedAndCanBeCleared() {
    final UserAuthentication authentication = new UserAuthentication(AuthenticatedUserTest.user());
    assertThat(authentication.getProtocolRequestData()).isNull();
    assertThat(authentication.getProtocolRequestData(TestRequestData.class)).isNull();

    final TestRequestData data = new TestRequestData("_1a2b3c", "https://sp.example.com/sp");
    authentication.setProtocolRequestData(data);
    assertThat(authentication.getProtocolRequestData()).isSameAs(data);
    assertThat(authentication.getProtocolRequestData(TestRequestData.class)).isSameAs(data);
    assertThat(authentication.getProtocolRequestData(String.class)).isNull();

    authentication.clearProtocolRequestData();
    assertThat(authentication.getProtocolRequestData()).isNull();
  }

  @Test
  void theFirstRegisteredUseIsTheOriginalAuthentication() {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    final UserAuthentication authentication = new UserAuthentication(user);

    assertThat(authentication.getUsageTrack().size()).isZero();
    assertThat(authentication.isSsoApplied()).isFalse();

    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1a2b3c",
        List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME));

    final AuthenticationUse original = authentication.getUsageTrack().getOriginalAuthentication();
    assertThat(original).isNotNull();
    assertThat(original.protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(original.requester()).isEqualTo("https://sp.example.com/sp");
    assertThat(original.requestId()).isEqualTo("_1a2b3c");
    assertThat(original.instant()).isEqualTo(user.getAuthnInstant());
    assertThat(original.requestedAttributes())
        .containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME);
    assertThat(authentication.isSsoApplied()).isFalse();
  }

  @Test
  void aSecondUseMeansThatSsoWasApplied() {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    final UserAuthentication authentication = new UserAuthentication(user);

    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1a2b3c",
        List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));
    authentication.registerUse(AuthenticationProtocol.OIDC, "client-1", null, null);

    assertThat(authentication.isSsoApplied()).isTrue();
    assertThat(authentication.getUsageTrack().size()).isEqualTo(2);

    final AuthenticationUse latest = authentication.getUsageTrack().getLatestUse();
    assertThat(latest).isNotNull();
    assertThat(latest.protocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(latest.requester()).isEqualTo("client-1");
    assertThat(latest.requestId()).isNull();
    assertThat(latest.requestedAttributes()).isEmpty();
    assertThat(latest.instant()).isAfterOrEqualTo(user.getAuthnInstant());
  }

  @Test
  void theResultSurvivesSerialization() throws Exception {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.setProtocolRequestData(new TestRequestData("_1a2b3c", "https://sp.example.com/sp"));
    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1a2b3c",
        List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));
    authentication.registerUse(AuthenticationProtocol.OIDC, "client-1", null, List.of(AttributeIdentifiers.EMAIL));

    final UserAuthentication restored = SerializationTestSupport.roundTrip(authentication);

    assertThat(restored.getAuthenticatedUser()).isEqualTo(user);
    assertThat(restored.getDetails()).isEqualTo(user);
    assertThat(restored.isAuthenticated()).isTrue();
    assertThat(restored.getName()).isEqualTo("197705232382");
    assertThat(restored.isReuseForSso()).isTrue();
    assertThat(restored.getProtocolRequestData(TestRequestData.class))
        .isEqualTo(new TestRequestData("_1a2b3c", "https://sp.example.com/sp"));
    assertThat(restored.getUsageTrack().getUsages()).isEqualTo(authentication.getUsageTrack().getUsages());
    assertThat(restored.isSsoApplied()).isTrue();
  }

  @Test
  void theResultSurvivesSerializationAfterTheRequestDataWasCleared() throws Exception {
    final AuthenticatedUser user = AuthenticatedUserTest.user();
    user.setSignMessageDisplayed(true, "sv");
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.setProtocolRequestData(new TestRequestData("_1a2b3c", "https://sp.example.com/sp"));
    authentication.registerUse(AuthenticationProtocol.OIDC, "client-1", null, List.of(AttributeIdentifiers.EMAIL));
    authentication.clearProtocolRequestData();

    final UserAuthentication restored = SerializationTestSupport.roundTrip(authentication);

    assertThat(restored.getProtocolRequestData()).isNull();
    assertThat(restored.isReuseForSso()).isFalse();
    assertThat(restored.getAuthenticatedUser().isSignMessageDisplayed()).isTrue();
    assertThat(restored.getAuthenticatedUser().getSignMessageLanguage()).isEqualTo("sv");
    assertThat(restored.getUsageTrack().size()).isEqualTo(1);
  }

}
