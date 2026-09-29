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
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Thrown for an error that makes it impossible to send the user back to the requester. The user is shown an error page
 * instead.
 *
 * @author Martin Lindström
 */
public class UnrecoverableErrorException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The error. */
  private final UnrecoverableError error;

  /**
   * Constructor.
   *
   * @param error the error
   */
  public UnrecoverableErrorException(final @Nonnull UnrecoverableError error) {
    this(Objects.requireNonNull(error, "error must not be null"), error.getDescription(), null);
  }

  /**
   * Constructor.
   *
   * @param error the error
   * @param message a message for logs
   */
  public UnrecoverableErrorException(final @Nonnull UnrecoverableError error, final @Nonnull String message) {
    this(error, message, null);
  }

  /**
   * Constructor.
   *
   * @param error the error
   * @param message a message for logs
   * @param cause the cause of the error, may be {@code null}
   */
  public UnrecoverableErrorException(final @Nonnull UnrecoverableError error, final @Nonnull String message,
      final @Nullable Throwable cause) {
    super(Objects.requireNonNull(message, "message must not be null"), cause);
    this.error = Objects.requireNonNull(error, "error must not be null");
  }

  /**
   * Gets the error.
   *
   * @return the error
   */
  public @Nonnull UnrecoverableError getError() {
    return this.error;
  }

  /**
   * Gets the message code to resolve the error message with.
   *
   * @return the message code
   */
  public @Nonnull String getMessageCode() {
    return this.error.getMessageCode();
  }

}
