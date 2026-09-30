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

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.StatusCode;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;

/**
 * Tests for {@link SamlErrorStatus}.
 *
 * @author Martin Lindström
 */
@SuppressWarnings("HttpUrlsUsage")
class SamlErrorStatusTest {

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
    for (final AuthenticationError error : AuthenticationError.values()) {
      final SamlErrorStatus status = SamlErrorStatus.of(error);
      assertThat(status.statusCode()).isIn(StatusCode.RESPONDER, StatusCode.REQUESTER);
      assertThat(status.subStatusCode()).isNotEmpty();
    }
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

}
