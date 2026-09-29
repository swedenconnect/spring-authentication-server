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

import jakarta.annotation.Nonnull;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

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
public record SamlErrorStatus(@Nonnull String statusCode, @Nonnull String subStatusCode) implements Serializable {

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
  public static @Nonnull SamlErrorStatus of(final @Nonnull AuthenticationError error) {
    Objects.requireNonNull(error, "error must not be null");
    return switch (error) {
      case AUTHN_FAILED, SIGN_MESSAGE_NOT_DISPLAYED, NOT_AUTHORIZED ->
          new SamlErrorStatus(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED);
      case CANCEL -> new SamlErrorStatus(StatusCode.RESPONDER, CANCEL);
      case FRAUD -> new SamlErrorStatus(StatusCode.RESPONDER, FRAUD);
      case POSSIBLE_FRAUD -> new SamlErrorStatus(StatusCode.RESPONDER, POSSIBLE_FRAUD);
      case UNKNOWN_PRINCIPAL -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.UNKNOWN_PRINCIPAL);
      case PASSIVE_NOT_POSSIBLE -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_PASSIVE);
      case NO_AUTHN_CONTEXT -> new SamlErrorStatus(StatusCode.REQUESTER, StatusCode.NO_AUTHN_CONTEXT);
    };
  }

}
