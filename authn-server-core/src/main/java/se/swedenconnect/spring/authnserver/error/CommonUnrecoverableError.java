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

import jakarta.annotation.Nonnull;

/**
 * The unrecoverable errors that do not depend on a protocol.
 *
 * @author Martin Lindström
 */
public enum CommonUnrecoverableError implements UnrecoverableError {

  /** Something went wrong inside the server. */
  INTERNAL("authn-server.error.unrecoverable.internal", "An internal error occurred"),

  /** The session data that the request needs could not be found. */
  INVALID_SESSION("authn-server.error.unrecoverable.session", "Required session data could not be found");

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
  CommonUnrecoverableError(final String messageCode, final String description) {
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
