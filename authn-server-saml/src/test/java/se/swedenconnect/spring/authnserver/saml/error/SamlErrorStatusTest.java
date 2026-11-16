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
package se.swedenconnect.spring.authnserver.saml.error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.StatusCode;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Tests for {@link SamlErrorStatus}.
 *
 * @author Martin Lindström
 */
@SuppressWarnings("HttpUrlsUsage")
class SamlErrorStatusTest {

  /** The built-in errors. */
  private static final List<AuthenticationError> BUILT_IN = List.of(AuthenticationError.AUTHN_FAILED,
      AuthenticationError.CANCEL, AuthenticationError.FRAUD, AuthenticationError.POSSIBLE_FRAUD,
      AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED, AuthenticationError.UNKNOWN_PRINCIPAL,
      AuthenticationError.PASSIVE_NOT_POSSIBLE, AuthenticationError.NO_AUTHN_CONTEXT, AuthenticationError.NOT_AUTHORIZED);

  /** A status of the application. */
  private static final SamlErrorStatus NO_AVAILABLE_IDP =
      new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.NO_AVAILABLE_IDP);

  @Test
  void everyErrorMapsToItsSamlStatus() {
    assertThat(SamlErrorStatus.of(AuthenticationError.AUTHN_FAILED))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    assertThat(SamlErrorStatus.of(AuthenticationError.CANCEL))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, "http://id.elegnamnden.se/status/1.0/cancel"));
    assertThat(SamlErrorStatus.of(AuthenticationError.FRAUD))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, "http://id.elegnamnden.se/status/1.0/fraud"));
    assertThat(SamlErrorStatus.of(AuthenticationError.POSSIBLE_FRAUD))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, "http://id.elegnamnden.se/status/1.0/possibleFraud"));
    assertThat(SamlErrorStatus.of(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    assertThat(SamlErrorStatus.of(AuthenticationError.UNKNOWN_PRINCIPAL))
        .isEqualTo(new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.UNKNOWN_PRINCIPAL));
    assertThat(SamlErrorStatus.of(AuthenticationError.PASSIVE_NOT_POSSIBLE))
        .isEqualTo(new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_PASSIVE));
    assertThat(SamlErrorStatus.of(AuthenticationError.NO_AUTHN_CONTEXT))
        .isEqualTo(new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_AUTHN_CONTEXT));
    assertThat(SamlErrorStatus.of(AuthenticationError.NOT_AUTHORIZED))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED));
  }

  @Test
  void everyErrorHasAMapping() {
    for (final AuthenticationError error : BUILT_IN) {
      final SamlErrorStatus status = SamlErrorStatus.of(error);
      assertThat(status.statusCode()).isIn(StatusCode.RESPONDER, StatusCode.REQUESTER);
      assertThat(status.subStatusCode()).isNotEmpty();
    }
  }

  @Test
  void anErrorOfTheApplicationIsReportedWithItsOwnStatus() {
    final SamlError error = new SamlError(NO_AVAILABLE_IDP);
    assertThat(SamlErrorStatus.of(error)).isEqualTo(NO_AVAILABLE_IDP);

    final SamlErrorStatusException exception =
        SamlErrorStatusException.of(new AuthenticationErrorException(error, "No IdP for the country"));
    assertThat(exception.getStatus()).isEqualTo(NO_AVAILABLE_IDP);
    assertThat(exception.getStatusMessageCode()).isEqualTo("app.error.no-service");
    assertThat(exception.getDescription()).isEqualTo("No IdP for the country");
  }

  @Test
  void anErrorOfTheApplicationWithoutASamlStatusIsReportedAsAuthnFailed() {
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
    assertThat(SamlErrorStatus.of(error)).isEqualTo(SamlErrorStatus.DEFAULT)
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
  }

  @Test
  void theFraudCodesAreTheSwedenConnectOnes() {
    assertThat(SamlErrorStatus.FRAUD).isEqualTo("http://id.elegnamnden.se/status/1.0/fraud");
    assertThat(SamlErrorStatus.POSSIBLE_FRAUD).isEqualTo("http://id.elegnamnden.se/status/1.0/possibleFraud");
    assertThat(SamlErrorStatus.CANCEL).isEqualTo("http://id.elegnamnden.se/status/1.0/cancel");
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void aStatusNeedsBothCodes() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new SamlErrorStatus(null, StatusCode.AUTHN_FAILED))
        .withMessage("statusCode must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new SamlErrorStatus(StatusCode.RESPONDER, null))
        .withMessage("subStatusCode must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> SamlErrorStatus.of(null))
        .withMessage("error must not be null");
  }

  /**
   * An error of the application with a SAML status.
   *
   * @param status the SAML status
   */
  record SamlError(SamlErrorStatus status) implements SamlAuthenticationError {

    @Override
    public @NonNull SamlErrorStatus getSamlErrorStatus() {
      return this.status;
    }

    @Override
    public @NonNull String getMessageCode() {
      return "app.error.no-service";
    }

    @Override
    public @NonNull String getDefaultMessage() {
      return "No authentication service available";
    }

  }

}
