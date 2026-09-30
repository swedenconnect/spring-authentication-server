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

import org.jspecify.annotations.NonNull;
import org.springframework.context.MessageSource;

/**
 * The errors that the user authentication step can produce. Each of them can be reported to the requester, in SAML as a
 * {@code Status} and in OpenID Connect as an error response. The protocol modules map them.
 * <p>
 * Errors from the validation of a request, such as an invalid request or a message that cannot be decrypted, are not
 * here. They belong to the protocol module that parses the request.
 * </p>
 *
 * @author Martin Lindström
 */
public enum AuthenticationError {

  /** The authentication of the user failed. */
  AUTHN_FAILED("authn-server.error.authn-failed", "User authentication failed"),

  /** The user cancelled the authentication. */
  CANCEL("authn-server.error.cancel", "User cancelled authentication"),

  /** Fraud was detected during the authentication. */
  FRAUD("authn-server.error.fraud", "Fraud was detected"),

  /** Possible fraud was detected during the authentication. */
  POSSIBLE_FRAUD("authn-server.error.possible-fraud", "Possible fraud was detected"),

  /** A sign message had to be displayed for the user, but was not. */
  SIGN_MESSAGE_NOT_DISPLAYED("authn-server.error.sign-message-not-displayed", "Sign message could not be displayed"),

  /** The authenticated user does not match the attribute values that the requester asked for. */
  UNKNOWN_PRINCIPAL("authn-server.error.unknown-principal", "Unknown principal"),

  /** The request required that the user was not interacted with, and no previous authentication could be reused. */
  PASSIVE_NOT_POSSIBLE("authn-server.error.passive-not-possible", "Passive authentication could not be performed"),

  /** None of the requested authentication contexts can be delivered. */
  NO_AUTHN_CONTEXT("authn-server.error.no-authn-context", "Requested authentication contexts are not supported"),

  /** The requester may not use the server, or may not use the feature it asked for. */
  NOT_AUTHORIZED("authn-server.error.not-authorized", "Not authorized");

  /** The message code for resolving the error message. */
  private final String messageCode;

  /** The message to use when the message code resolves to nothing. */
  private final String defaultMessage;

  /**
   * Constructor.
   *
   * @param messageCode the message code for resolving the error message
   * @param defaultMessage the message to use when the message code resolves to nothing
   */
  AuthenticationError(final String messageCode, final String defaultMessage) {
    this.messageCode = messageCode;
    this.defaultMessage = defaultMessage;
  }

  /**
   * Gets the message code to resolve the error message with, against a {@link MessageSource}.
   *
   * @return the message code
   */
  public @NonNull String getMessageCode() {
    return this.messageCode;
  }

  /**
   * Gets the message to use when the message code resolves to nothing.
   *
   * @return the default message
   */
  public @NonNull String getDefaultMessage() {
    return this.defaultMessage;
  }

}
