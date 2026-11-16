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

import java.io.Serializable;

import org.jspecify.annotations.NonNull;
import org.springframework.context.MessageSource;

/**
 * An error that the user authentication step can produce, and that is reported to the requester, in SAML as a
 * {@code Status} and in OpenID Connect as an error response. The protocol modules map the errors.
 * <p>
 * The built-in errors are the constants of this interface. An application adds errors of its own by implementing the
 * interface of each protocol that the error is to be reported in, {@code SamlAuthenticationError} of the SAML module
 * and {@code OidcAuthenticationError} of the OpenID Connect module. An error that does not implement the interface
 * of a protocol is reported with that protocol's default error. The status or error of a built-in error cannot be
 * changed.
 * </p>
 * <p>
 * The error is kept in the session while the user is redirected, so an implementation must be serializable.
 * </p>
 * <p>
 * Errors from the validation of a request, such as an invalid request or a message that cannot be decrypted, are not
 * authentication errors. They belong to the protocol module that parses the request.
 * </p>
 *
 * @author Martin Lindström
 */
public interface AuthenticationError extends Serializable {

  /** The authentication of the user failed. */
  AuthenticationError AUTHN_FAILED = BuiltInAuthenticationError.AUTHN_FAILED;

  /** The user cancelled the authentication. */
  AuthenticationError CANCEL = BuiltInAuthenticationError.CANCEL;

  /** Fraud was detected during the authentication. */
  AuthenticationError FRAUD = BuiltInAuthenticationError.FRAUD;

  /** Possible fraud was detected during the authentication. */
  AuthenticationError POSSIBLE_FRAUD = BuiltInAuthenticationError.POSSIBLE_FRAUD;

  /** A sign message had to be displayed for the user, but was not. */
  AuthenticationError SIGN_MESSAGE_NOT_DISPLAYED = BuiltInAuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED;

  /** The authenticated user does not match the attribute values that the requester asked for. */
  AuthenticationError UNKNOWN_PRINCIPAL = BuiltInAuthenticationError.UNKNOWN_PRINCIPAL;

  /** The request required that the user was not interacted with, and no previous authentication could be reused. */
  AuthenticationError PASSIVE_NOT_POSSIBLE = BuiltInAuthenticationError.PASSIVE_NOT_POSSIBLE;

  /** None of the requested authentication contexts can be delivered. */
  AuthenticationError NO_AUTHN_CONTEXT = BuiltInAuthenticationError.NO_AUTHN_CONTEXT;

  /** The requester may not use the server, or may not use the feature it asked for. */
  AuthenticationError NOT_AUTHORIZED = BuiltInAuthenticationError.NOT_AUTHORIZED;

  /**
   * Gets the message code to resolve the error message with, against a {@link MessageSource}.
   *
   * @return the message code
   */
  @NonNull String getMessageCode();

  /**
   * Gets the message to use when the message code resolves to nothing.
   *
   * @return the default message
   */
  @NonNull String getDefaultMessage();

}
