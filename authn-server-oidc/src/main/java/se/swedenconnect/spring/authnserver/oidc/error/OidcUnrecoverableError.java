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

import se.swedenconnect.spring.authnserver.error.UnrecoverableError;

/**
 * The unrecoverable errors that only OpenID Connect has.
 *
 * @author Martin Lindström
 */
public enum OidcUnrecoverableError implements UnrecoverableError {

  /** The client is registered in a way that makes it impossible to answer its request. */
  INVALID_CLIENT_CONFIGURATION("authn-server.error.unrecoverable.oidc.client-configuration",
      "The client is not correctly registered"),

  /** The authentication request lacks {@code client_id}, or cannot be processed before a response can be sent. */
  INVALID_AUTHN_REQUEST("authn-server.error.unrecoverable.oidc.invalid-request",
      "The authentication request is invalid and cannot be answered"),

  /** The client is not known. */
  UNKNOWN_CLIENT("authn-server.error.unrecoverable.oidc.unknown-client",
      "The client has not been registered at the OpenID Provider"),

  /** The client could not be looked up, since the client registry failed. */
  CLIENT_LOOKUP_FAILED("authn-server.error.unrecoverable.oidc.client-lookup-failed",
      "The client could not be looked up"),

  /** The redirect URI is missing, or is not registered for the client. */
  INVALID_REDIRECT_URI("authn-server.error.unrecoverable.oidc.redirect-uri",
      "The redirect URI is missing or has not been registered for the client"),

  /** The response mode is not supported. The OpenID Provider answers with HTTP status 400. */
  UNSUPPORTED_RESPONSE_MODE("authn-server.error.unrecoverable.oidc.response-mode",
      "The requested response mode is not supported");

  /** The message code for resolving the error message. */
  private final String messageCode;

  /** The description of the error. */
  private final String description;

  /**
   * Constructor.
   *
   * @param messageCode the message code for resolving the error message
   * @param description the description of the error
   */
  OidcUnrecoverableError(final String messageCode, final String description) {
    this.messageCode = messageCode;
    this.description = description;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String getMessageCode() {
    return this.messageCode;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String getDescription() {
    return this.description;
  }

}
