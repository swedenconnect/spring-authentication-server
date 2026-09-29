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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.OIDCError;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.sso.SsoDenialKind;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;

/**
 * The mapping of the protocol-neutral authentication errors to OpenID Connect and OAuth 2.0 error codes.
 * <p>
 * Every error carries a description. The Swedish OpenID Connect Profile, Section 2.3, states that the
 * {@code error_description} field should hold something the Relying Party can put in its application logs, and that
 * matters most for {@code access_denied}, which says only that the authentication was not completed.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcErrorMapping {

  /**
   * Gets the error to send to the requester.
   *
   * @param exception the exception from the authentication step
   * @return an {@link ErrorObject} carrying the error code and a description for the requester's logs
   */
  public static @Nonnull ErrorObject of(final @Nonnull AuthenticationErrorException exception) {
    Objects.requireNonNull(exception, "exception must not be null");
    return of(exception.getError(), exception.getSsoDenialReason())
        .setDescription(exception.getDescription());
  }

  /**
   * Gets the error to send to the requester.
   *
   * @param error the error
   * @param ssoDenialReason why a previous authentication was not reused, which decides the error code for
   *          {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}. May be {@code null}
   * @return an {@link ErrorObject} carrying the error code and the default description of the error
   */
  public static @Nonnull ErrorObject of(final @Nonnull AuthenticationError error,
      final @Nullable SsoDenialReason ssoDenialReason) {
    Objects.requireNonNull(error, "error must not be null");
    final ErrorObject errorObject = switch (error) {
      case AUTHN_FAILED, CANCEL, FRAUD, POSSIBLE_FRAUD, SIGN_MESSAGE_NOT_DISPLAYED, UNKNOWN_PRINCIPAL ->
          OAuth2Error.ACCESS_DENIED;
      case PASSIVE_NOT_POSSIBLE -> ssoDenialReason != null
          && ssoDenialReason.getKind() == SsoDenialKind.INTERACTION_REQUIRED
              ? OIDCError.INTERACTION_REQUIRED
              : OIDCError.LOGIN_REQUIRED;
      case NO_AUTHN_CONTEXT -> OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS;
      case NOT_AUTHORIZED -> OAuth2Error.UNAUTHORIZED_CLIENT;
    };
    return errorObject.setDescription(error.getDefaultMessage());
  }

  // Hidden constructor
  private OidcErrorMapping() {
  }

}
