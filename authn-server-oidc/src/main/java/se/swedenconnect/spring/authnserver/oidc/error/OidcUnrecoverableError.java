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
      "The client is not correctly registered");

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
