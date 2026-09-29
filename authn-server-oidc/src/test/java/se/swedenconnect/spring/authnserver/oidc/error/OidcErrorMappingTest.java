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
package se.swedenconnect.spring.authnserver.oidc.error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.OIDCError;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;

/**
 * Tests for {@link OidcErrorMapping}.
 *
 * @author Martin Lindström
 */
class OidcErrorMappingTest {

  @Test
  void theErrorsThatMeanTheAuthenticationWasNotCompletedAreAccessDenied() {
    for (final AuthenticationError error : new AuthenticationError[] {
        AuthenticationError.AUTHN_FAILED, AuthenticationError.CANCEL, AuthenticationError.FRAUD,
        AuthenticationError.POSSIBLE_FRAUD, AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED,
        AuthenticationError.UNKNOWN_PRINCIPAL }) {
      assertThat(OidcErrorMapping.of(error, null).getCode()).isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);
    }
  }

  @Test
  void anUnsupportedAuthenticationContextIsAnUnmetAuthenticationRequirement() {
    assertThat(OidcErrorMapping.of(AuthenticationError.NO_AUTHN_CONTEXT, null).getCode())
        .isEqualTo(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE);
  }

  @Test
  void aRequesterThatMayNotUseTheServerIsAnUnauthorizedClient() {
    assertThat(OidcErrorMapping.of(AuthenticationError.NOT_AUTHORIZED, null).getCode())
        .isEqualTo(OAuth2Error.UNAUTHORIZED_CLIENT_CODE);
  }

  @Test
  void aPassiveRequestGetsLoginRequiredOrInteractionRequiredFromTheReason() {
    assertThat(OidcErrorMapping.of(AuthenticationError.PASSIVE_NOT_POSSIBLE,
        SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES).getCode()).isEqualTo(OIDCError.INTERACTION_REQUIRED_CODE);

    for (final SsoDenialReason reason : SsoDenialReason.values()) {
      if (reason == SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES) {
        continue;
      }
      assertThat(OidcErrorMapping.of(AuthenticationError.PASSIVE_NOT_POSSIBLE, reason).getCode())
          .isEqualTo(OIDCError.LOGIN_REQUIRED_CODE);
    }
    assertThat(OidcErrorMapping.of(AuthenticationError.PASSIVE_NOT_POSSIBLE, null).getCode())
        .isEqualTo(OIDCError.LOGIN_REQUIRED_CODE);
  }

  @Test
  void everyErrorCarriesADescriptionForTheRequestersLogs() {
    for (final AuthenticationError error : AuthenticationError.values()) {
      assertThat(OidcErrorMapping.of(error, null).getDescription()).isEqualTo(error.getDefaultMessage());
    }
  }

  @Test
  void theDescriptionOfTheExceptionIsUsedWhenThereIsOne() {
    final AuthenticationErrorException exception =
        new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "The BankID server said no");
    assertThat(OidcErrorMapping.of(exception).getCode()).isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);
    assertThat(OidcErrorMapping.of(exception).getDescription()).isEqualTo("The BankID server said no");
  }

  @Test
  void theReasonOfTheExceptionDecidesThePassiveError() {
    final AuthenticationErrorException exception = new AuthenticationErrorException(
        AuthenticationError.PASSIVE_NOT_POSSIBLE, SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES);
    assertThat(OidcErrorMapping.of(exception).getCode()).isEqualTo(OIDCError.INTERACTION_REQUIRED_CODE);
    assertThat(OidcErrorMapping.of(exception).getDescription())
        .isEqualTo(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES.getDescription());
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void theMappingNeedsAnError() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> OidcErrorMapping.of(null, null))
        .withMessage("error must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> OidcErrorMapping.of(null))
        .withMessage("exception must not be null");
  }

}
