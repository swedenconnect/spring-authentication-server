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
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.StatusCode;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;

/**
 * The SAML {@code Status} that an {@link AuthenticationError} is reported as.
 *
 * @param statusCode the main status code
 * @param subStatusCode the subordinate status code
 * @author Martin Lindström
 */
public record SamlErrorStatus(@NonNull String statusCode, @NonNull String subStatusCode) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

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
   * Gets the SAML status for the supplied error.
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
    return switch (error) {
      case AUTHN_FAILED, SIGN_MESSAGE_NOT_DISPLAYED ->
          new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED);
      case NOT_AUTHORIZED -> new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED);
      case CANCEL -> new SamlErrorStatus(StatusCode.RESPONDER, CANCEL);
      case FRAUD -> new SamlErrorStatus(StatusCode.RESPONDER, FRAUD);
      case POSSIBLE_FRAUD -> new SamlErrorStatus(StatusCode.RESPONDER, POSSIBLE_FRAUD);
      case UNKNOWN_PRINCIPAL -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.UNKNOWN_PRINCIPAL);
      case PASSIVE_NOT_POSSIBLE -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_PASSIVE);
      case NO_AUTHN_CONTEXT -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_AUTHN_CONTEXT);
    };
  }

}
