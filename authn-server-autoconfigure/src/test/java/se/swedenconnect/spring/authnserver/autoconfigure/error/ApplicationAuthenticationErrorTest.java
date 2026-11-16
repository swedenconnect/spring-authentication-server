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
package se.swedenconnect.spring.authnserver.autoconfigure.error;

import static org.assertj.core.api.Assertions.assertThat;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.StatusCode;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcAuthenticationError;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorMapping;
import se.swedenconnect.spring.authnserver.saml.error.SamlAuthenticationError;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;

/**
 * Tests for an authentication error of the application that is reported in both protocols.
 *
 * @author Martin Lindström
 */
class ApplicationAuthenticationErrorTest {

  @Test
  void anErrorThatImplementsBothInterfacesIsReportedInBothProtocols() {
    final AuthenticationErrorException exception =
        new AuthenticationErrorException(ApplicationErrors.NO_SERVICE_AVAILABLE, "No service for the country");

    assertThat(SamlErrorStatus.of(exception.getError()))
        .isEqualTo(new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.NO_AVAILABLE_IDP));
    assertThat(OidcErrorMapping.of(exception).getCode()).isEqualTo(OAuth2Error.ACCESS_DENIED_CODE);

    final AuthenticationErrorException denied =
        new AuthenticationErrorException(ApplicationErrors.REQUEST_UNSUPPORTED, "Not supported");
    assertThat(SamlErrorStatus.of(denied.getError()))
        .isEqualTo(new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED));
    assertThat(OidcErrorMapping.of(denied).getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST_CODE);
  }

  /**
   * Errors of the application, reported in both protocols.
   */
  enum ApplicationErrors implements SamlAuthenticationError, OidcAuthenticationError {

    NO_SERVICE_AVAILABLE("app.error.no-service", "No authentication service available",
        new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.NO_AVAILABLE_IDP), OAuth2Error.ACCESS_DENIED),

    REQUEST_UNSUPPORTED("app.error.unsupported", "The request is not supported",
        new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED), OAuth2Error.INVALID_REQUEST);

    private final String messageCode;
    private final String defaultMessage;
    private final SamlErrorStatus samlErrorStatus;
    private final ErrorObject oidcError;

    ApplicationErrors(final String messageCode, final String defaultMessage, final SamlErrorStatus samlErrorStatus,
        final ErrorObject oidcError) {
      this.messageCode = messageCode;
      this.defaultMessage = defaultMessage;
      this.samlErrorStatus = samlErrorStatus;
      this.oidcError = oidcError;
    }

    @Override
    public @NonNull String getMessageCode() {
      return this.messageCode;
    }

    @Override
    public @NonNull String getDefaultMessage() {
      return this.defaultMessage;
    }

    @Override
    public @NonNull SamlErrorStatus getSamlErrorStatus() {
      return this.samlErrorStatus;
    }

    @Override
    public @NonNull ErrorObject getOidcError() {
      return this.oidcError;
    }

  }

}
