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
package se.swedenconnect.spring.authnserver.error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;

/**
 * Tests for the protocol-neutral error model.
 *
 * @author Martin Lindström
 */
class ErrorModelTest {

  @Test
  void everyErrorHasAMessageCodeAndADefaultMessage() {
    for (final AuthenticationError error : AuthenticationError.values()) {
      assertThat(error.getMessageCode()).startsWith("authn-server.error.");
      assertThat(error.getDefaultMessage()).isNotEmpty();
    }
    assertThat(AuthenticationError.AUTHN_FAILED.getMessageCode()).isEqualTo("authn-server.error.authn-failed");
  }

  @Test
  void anExceptionCarriesTheErrorAndADescriptionForLogs() {
    final AuthenticationErrorException exception = new AuthenticationErrorException(AuthenticationError.CANCEL);
    assertThat(exception.getError()).isEqualTo(AuthenticationError.CANCEL);
    assertThat(exception.getMessageCode()).isEqualTo(AuthenticationError.CANCEL.getMessageCode());
    assertThat(exception.getDescription()).isEqualTo(AuthenticationError.CANCEL.getDefaultMessage());
    assertThat(exception.getSsoDenialReason()).isNull();

    final AuthenticationErrorException described =
        new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "The BankID server said no");
    assertThat(described.getDescription()).isEqualTo("The BankID server said no");

    final Throwable cause = new IllegalStateException("boom");
    assertThat(new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "failed", cause))
        .hasMessage("failed")
        .hasCause(cause);
  }

  @Test
  void aPassiveErrorCarriesTheReasonForRefusingSingleSignOn() {
    final AuthenticationErrorException exception = new AuthenticationErrorException(
        AuthenticationError.PASSIVE_NOT_POSSIBLE, SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES);
    assertThat(exception.getSsoDenialReason()).isEqualTo(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES);
    assertThat(exception.getDescription()).isEqualTo(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES.getDescription());
  }

  @Test
  @SuppressWarnings({ "DataFlowIssue", "ThrowableNotThrown" })
  void anExceptionNeedsAnError() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationErrorException(null))
        .withMessage("error must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticationErrorException(AuthenticationError.CANCEL, (SsoDenialReason) null))
        .withMessage("ssoDenialReason must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new UnrecoverableErrorException(null))
        .withMessage("error must not be null");
  }

  @Test
  void theCoreDefinesTheUnrecoverableErrorsThatDoNotDependOnAProtocol() {
    for (final CommonUnrecoverableError error : CommonUnrecoverableError.values()) {
      assertThat(error.getMessageCode()).startsWith("authn-server.error.unrecoverable.");
      assertThat(error.getDescription()).isNotEmpty();
    }
    assertThat(CommonUnrecoverableError.values())
        .containsExactly(CommonUnrecoverableError.INTERNAL, CommonUnrecoverableError.INVALID_SESSION);
  }

  @Test
  void aProtocolModuleCanAddUnrecoverableErrorsOfItsOwn() {
    final UnrecoverableError error = new UnrecoverableError() {

      @Override
      public @NonNull String getMessageCode() {
        return "oidc.error.unrecoverable.unknown-client";
      }

      @Override
      public @NonNull String getDescription() {
        return "The client is not registered";
      }
    };
    final UnrecoverableErrorException exception = new UnrecoverableErrorException(error);
    assertThat(exception.getError()).isSameAs(error);
    assertThat(exception.getMessageCode()).isEqualTo("oidc.error.unrecoverable.unknown-client");
    assertThat(exception).hasMessage("The client is not registered");
  }

  @Test
  void anUnrecoverableErrorCarriesAMessage() {
    assertThat(new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION, "no session id in the cookie"))
        .hasMessage("no session id in the cookie")
        .hasNoCause()
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INVALID_SESSION));
  }

  @Test
  void anUnrecoverableErrorCarriesAMessageAndACause() {
    final Throwable cause = new IllegalStateException("boom");
    assertThat(new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "the database is down", cause))
        .hasMessage("the database is down")
        .hasCause(cause)
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INTERNAL));
  }

}
