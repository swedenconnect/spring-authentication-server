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

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;

/**
 * The SAML {@code Status} that an {@link AuthenticationError} is reported as.
 * <p>
 * The built-in errors have fixed statuses. An error of the application implements {@link SamlAuthenticationError} to
 * be reported with a status of its own.
 * </p>
 *
 * @param statusCode the main status code
 * @param subStatusCode the subordinate status code
 * @author Martin Lindström
 */
public record SamlErrorStatus(@NonNull String statusCode, @NonNull String subStatusCode) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SamlErrorStatus.class);

  /** The Sweden Connect status code for a cancelled operation. */
  @SuppressWarnings("HttpUrlsUsage")
  public static final String CANCEL = "http://id.elegnamnden.se/status/1.0/cancel";

  /** The Sweden Connect status code for a fraudulent request. */
  @SuppressWarnings("HttpUrlsUsage")
  public static final String FRAUD = "http://id.elegnamnden.se/status/1.0/fraud";

  /** The Sweden Connect status code for a possibly fraudulent request. */
  @SuppressWarnings("HttpUrlsUsage")
  public static final String POSSIBLE_FRAUD = "http://id.elegnamnden.se/status/1.0/possibleFraud";

  /**
   * The status reported when the {@code NameIDPolicy} of an authentication request asks for a {@code Format} that the
   * Identity Provider does not support.
   */
  public static final SamlErrorStatus INVALID_NAMEID_POLICY =
      new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.INVALID_NAMEID_POLICY);

  /** The status reported for an authentication request that is invalid or asks for something unsupported. */
  public static final SamlErrorStatus INVALID_REQUEST =
      new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED);

  /** The message code for {@link #INVALID_REQUEST}. */
  public static final String INVALID_REQUEST_MESSAGE_CODE = "authn-server.error.saml.invalid-request";

  /** The status reported for a {@code SignMessage} that cannot be decrypted or holds nothing to display. */
  public static final SamlErrorStatus SIGN_MESSAGE_ERROR =
      new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED);

  /** The message code for {@link #SIGN_MESSAGE_ERROR}. */
  public static final String SIGN_MESSAGE_ERROR_MESSAGE_CODE = "authn-server.error.saml.sign-message";

  /** The status reported for a {@code UserMessage} with a MIME type that is not supported. */
  public static final SamlErrorStatus INVALID_USER_MESSAGE =
      new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED);

  /** The message code for {@link #INVALID_USER_MESSAGE}. */
  public static final String INVALID_USER_MESSAGE_MESSAGE_CODE = "authn-server.error.saml.invalid-user-message";

  /**
   * The status reported when assertions are to be encrypted, but the Service Provider metadata has no key to encrypt
   * them for.
   */
  public static final SamlErrorStatus ENCRYPT_NOT_POSSIBLE =
      new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.REQUEST_DENIED);

  /** The message code for {@link #ENCRYPT_NOT_POSSIBLE}. */
  public static final String ENCRYPT_NOT_POSSIBLE_MESSAGE_CODE = "authn-server.error.saml.no-encrypt-capabilities";

  /**
   * The status reported when a request is received on a Holder-of-key endpoint without a client certificate. The
   * Holder-of-Key Web Browser SSO Profile requires an error, but does not say which.
   */
  public static final SamlErrorStatus HOLDER_OF_KEY_NO_CERTIFICATE =
      new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED);

  /** The message code for {@link #HOLDER_OF_KEY_NO_CERTIFICATE}. */
  public static final String HOLDER_OF_KEY_NO_CERTIFICATE_MESSAGE_CODE = "authn-server.error.saml.hok-no-certificate";

  /** The status reported for an error of the application that has no status of its own. */
  public static final SamlErrorStatus DEFAULT = new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED);

  /** The statuses of the built-in errors. */
  private static final Map<AuthenticationError, SamlErrorStatus> BUILT_IN = Map.of(
      AuthenticationError.AUTHN_FAILED, new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED),
      AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED,
      new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED),
      AuthenticationError.NOT_AUTHORIZED, new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED),
      AuthenticationError.CANCEL, new SamlErrorStatus(StatusCode.RESPONDER, CANCEL),
      AuthenticationError.FRAUD, new SamlErrorStatus(StatusCode.RESPONDER, FRAUD),
      AuthenticationError.POSSIBLE_FRAUD, new SamlErrorStatus(StatusCode.RESPONDER, POSSIBLE_FRAUD),
      AuthenticationError.UNKNOWN_PRINCIPAL, new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.UNKNOWN_PRINCIPAL),
      AuthenticationError.PASSIVE_NOT_POSSIBLE, new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_PASSIVE),
      AuthenticationError.NO_AUTHN_CONTEXT, new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_AUTHN_CONTEXT));

  /**
   * Constructor.
   *
   * @param statusCode the main status code
   * @param subStatusCode the subordinate status code
   */
  public SamlErrorStatus {
    Objects.requireNonNull(statusCode, "statusCode must not be null");
    Objects.requireNonNull(subStatusCode, "subStatusCode must not be null");
  }

  /**
   * Gets the SAML status for the supplied error: the status of a built-in error, the status of an error that
   * implements {@link SamlAuthenticationError}, and {@link #DEFAULT} for any other error.
   * <p>
   * The status message is not part of the status. Resolve it from the error's message code, falling back on its default
   * message.
   * </p>
   *
   * @param error the error
   * @return a {@link SamlErrorStatus}
   */
  public static @NonNull SamlErrorStatus of(final @NonNull AuthenticationError error) {
    Objects.requireNonNull(error, "error must not be null");
    final SamlErrorStatus builtIn = BUILT_IN.get(error);
    if (builtIn != null) {
      return builtIn;
    }
    if (error instanceof final SamlAuthenticationError samlError) {
      final SamlErrorStatus status = samlError.getSamlErrorStatus();
      if (status != null) {
        return status;
      }
      log.warn("The authentication error {} gives no SAML status - {} is used", error, DEFAULT);
    }
    return DEFAULT;
  }

}
