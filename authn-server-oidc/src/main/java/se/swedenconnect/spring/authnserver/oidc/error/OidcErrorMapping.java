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

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * <p>
 * The built-in errors have fixed error codes. An error of the application implements {@link OidcAuthenticationError}
 * to be reported with an error of its own. Its code must be one that the authorization endpoint may return, see
 * {@link #AUTHORIZATION_ERROR_CODES}. Another code is replaced by {@code access_denied}. An error of the application
 * that does not implement the interface is reported with {@code access_denied}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcErrorMapping {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcErrorMapping.class);

  /**
   * The error codes that the authorization endpoint may return, from OAuth 2.0 (RFC 6749, Section 4.1.2.1), OpenID
   * Connect Core (Section 3.1.2.6) and the {@code unmet_authentication_requirements} error code.
   */
  public static final Set<String> AUTHORIZATION_ERROR_CODES = Set.of(
      OAuth2Error.INVALID_REQUEST_CODE, OAuth2Error.UNAUTHORIZED_CLIENT_CODE, OAuth2Error.ACCESS_DENIED_CODE,
      OAuth2Error.UNSUPPORTED_RESPONSE_TYPE_CODE, OAuth2Error.INVALID_SCOPE_CODE, OAuth2Error.SERVER_ERROR_CODE,
      OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE, OIDCError.INTERACTION_REQUIRED_CODE, OIDCError.LOGIN_REQUIRED_CODE,
      OIDCError.ACCOUNT_SELECTION_REQUIRED_CODE, OIDCError.CONSENT_REQUIRED_CODE, OAuth2Error.INVALID_REQUEST_URI_CODE,
      OAuth2Error.INVALID_REQUEST_OBJECT_CODE, OAuth2Error.REQUEST_NOT_SUPPORTED_CODE,
      OAuth2Error.REQUEST_URI_NOT_SUPPORTED_CODE, OIDCError.REGISTRATION_NOT_SUPPORTED_CODE,
      OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS_CODE);

  /** The errors of the built-in errors, except {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}. */
  private static final Map<AuthenticationError, ErrorObject> BUILT_IN = Map.of(
      AuthenticationError.AUTHN_FAILED, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.CANCEL, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.FRAUD, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.POSSIBLE_FRAUD, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.UNKNOWN_PRINCIPAL, OAuth2Error.ACCESS_DENIED,
      AuthenticationError.NO_AUTHN_CONTEXT, OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
      AuthenticationError.NOT_AUTHORIZED, OAuth2Error.UNAUTHORIZED_CLIENT);

  /**
   * Gets the error to send to the requester.
   *
   * @param exception the exception from the authentication step
   * @return an {@link ErrorObject} carrying the error code and a description for the requester's logs
   */
  public static @NonNull ErrorObject of(final @NonNull AuthenticationErrorException exception) {
    Objects.requireNonNull(exception, "exception must not be null");
    return of(exception.getError(), exception.getSsoDenialReason())
        .setDescription(exception.getDescription());
  }

  /**
   * Gets the error to send to the requester: the error of a built-in error, the error of an error that implements
   * {@link OidcAuthenticationError}, and {@code access_denied} for any other error.
   *
   * @param error the error
   * @param ssoDenialReason why a previous authentication was not reused, which decides the error code for
   *          {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}. May be {@code null}
   * @return an {@link ErrorObject} carrying the error code and the default description of the error
   */
  public static @NonNull ErrorObject of(final @NonNull AuthenticationError error,
      final @Nullable SsoDenialReason ssoDenialReason) {
    Objects.requireNonNull(error, "error must not be null");
    final ErrorObject errorObject;
    if (error == AuthenticationError.PASSIVE_NOT_POSSIBLE) {
      errorObject = ssoDenialReason != null && ssoDenialReason.getKind() == SsoDenialKind.INTERACTION_REQUIRED
          ? OIDCError.INTERACTION_REQUIRED
          : OIDCError.LOGIN_REQUIRED;
    }
    else if (BUILT_IN.containsKey(error)) {
      errorObject = BUILT_IN.get(error);
    }
    else if (error instanceof final OidcAuthenticationError oidcError) {
      errorObject = applicationError(oidcError);
    }
    else {
      errorObject = OAuth2Error.ACCESS_DENIED;
    }
    return errorObject.setDescription(error.getDefaultMessage());
  }

  /**
   * Gets the error of an error of the application, or {@code access_denied} if its code is not one that the
   * authorization endpoint may return.
   *
   * @param error the error of the application
   * @return an {@link ErrorObject}
   */
  private static @NonNull ErrorObject applicationError(final @NonNull OidcAuthenticationError error) {
    final ErrorObject errorObject = error.getOidcError();
    if (errorObject != null && AUTHORIZATION_ERROR_CODES.contains(errorObject.getCode())) {
      return errorObject;
    }
    log.warn("The authentication error {} gives the error code '{}', which the authorization endpoint may not return"
        + " - access_denied is used", error, errorObject != null ? errorObject.getCode() : null);
    return OAuth2Error.ACCESS_DENIED;
  }

  // Hidden constructor
  private OidcErrorMapping() {
  }

}
