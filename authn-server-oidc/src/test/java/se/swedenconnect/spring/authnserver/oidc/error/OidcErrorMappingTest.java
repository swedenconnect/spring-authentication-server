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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.ErrorObject;
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
    for (final AuthenticationError error : List.of(AuthenticationError.AUTHN_FAILED, AuthenticationError.CANCEL,
        AuthenticationError.FRAUD, AuthenticationError.POSSIBLE_FRAUD, AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED,
        AuthenticationError.UNKNOWN_PRINCIPAL, AuthenticationError.PASSIVE_NOT_POSSIBLE,
        AuthenticationError.NO_AUTHN_CONTEXT, AuthenticationError.NOT_AUTHORIZED)) {
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
  void anErrorOfTheApplicationIsReportedWithItsOwnError() {
    final AuthenticationErrorException exception = new AuthenticationErrorException(
        new OidcError(OAuth2Error.INVALID_REQUEST), "The request asks for something the application does not do");

    final ErrorObject error = OidcErrorMapping.of(exception);

    assertThat(error.getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST_CODE);
    assertThat(error.getDescription()).isEqualTo("The request asks for something the application does not do");
  }

  @Test
  void anErrorOfTheApplicationWithACodeThatTheAuthorizationEndpointMayNotReturnIsAccessDenied() {
    assertThat(OidcErrorMapping.of(new OidcError(OAuth2Error.INVALID_GRANT), null).getCode())
        .isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);
    assertThat(OidcErrorMapping.of(new OidcError(new ErrorObject("my_error")), null).getCode())
        .isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);
  }

  @Test
  void anErrorOfTheApplicationWithoutAnOidcErrorIsAccessDenied() {
    final AuthenticationError error = new AuthenticationError() {
      @Override
      public @NonNull String getMessageCode() {
        return "app.error.other";
      }

      @Override
      public @NonNull String getDefaultMessage() {
        return "Other error";
      }
    };
    final ErrorObject errorObject = OidcErrorMapping.of(error, null);
    assertThat(errorObject.getCode()).isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);
    assertThat(errorObject.getDescription()).isEqualTo("Other error");
  }

  @Test
  void anErrorOfTheApplicationSurvivesSerialization() throws Exception {
    final AuthenticationErrorException exception =
        new AuthenticationErrorException(new OidcError(OAuth2Error.INVALID_REQUEST), "Unsupported");

    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(exception);
    }
    final AuthenticationErrorException restored;
    try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      restored = (AuthenticationErrorException) in.readObject();
    }

    assertThat(restored.getError()).isEqualTo(exception.getError());
    assertThat(OidcErrorMapping.of(restored).getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST_CODE);
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

  /**
   * An error of the application with an OpenID Connect error.
   *
   * @param error the error
   */
  record OidcError(ErrorObject error) implements OidcAuthenticationError {

    @Override
    public @NonNull ErrorObject getOidcError() {
      return this.error;
    }

    @Override
    public @NonNull String getMessageCode() {
      return "app.error.unsupported";
    }

    @Override
    public @NonNull String getDefaultMessage() {
      return "The request is not supported";
    }

  }

}
