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
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.Objects;

import org.springframework.context.MessageSource;
import org.springframework.security.core.AuthenticationException;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Thrown when the processing of a SAML request fails in a way that is reported back to the Service Provider as a
 * {@code Status}.
 * <p>
 * The errors that the user authentication step produces are reported with
 * {@link se.swedenconnect.spring.authnserver.error.AuthenticationErrorException} and mapped by
 * {@link SamlErrorStatus#of(se.swedenconnect.spring.authnserver.error.AuthenticationError)}. This exception is for the
 * errors that only SAML has, where the request itself asks for something that can not be delivered.
 * </p>
 *
 * @author Martin Lindström
 */
public class SamlErrorStatusException extends AuthenticationException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The status to report. */
  private final SamlErrorStatus status;

  /** The message code for resolving the status message. */
  private final String statusMessageCode;

  /**
   * Constructor.
   *
   * @param status the status to report
   * @param statusMessageCode the message code for resolving the status message
   * @param description a description of what went wrong, for logs. It is never shown to the user
   */
  public SamlErrorStatusException(final @Nonnull SamlErrorStatus status, final @Nonnull String statusMessageCode,
      final @Nonnull String description) {
    this(status, statusMessageCode, description, null);
  }

  /**
   * Constructor.
   *
   * @param status the status to report
   * @param statusMessageCode the message code for resolving the status message
   * @param description a description of what went wrong, for logs. It is never shown to the user
   * @param cause the cause of the error, may be {@code null}
   */
  public SamlErrorStatusException(final @Nonnull SamlErrorStatus status, final @Nonnull String statusMessageCode,
      final @Nonnull String description, final @Nullable Throwable cause) {
    super(Objects.requireNonNull(description, "description must not be null"));
    if (cause != null) {
      this.initCause(cause);
    }
    this.status = Objects.requireNonNull(status, "status must not be null");
    this.statusMessageCode = Objects.requireNonNull(statusMessageCode, "statusMessageCode must not be null");
  }

  /**
   * Gets the status to report.
   *
   * @return a {@link SamlErrorStatus}
   */
  public @Nonnull SamlErrorStatus getStatus() {
    return this.status;
  }

  /**
   * Gets the message code to resolve the status message with, against a {@link MessageSource}.
   *
   * @return the message code
   */
  public @Nonnull String getStatusMessageCode() {
    return this.statusMessageCode;
  }

  /**
   * Gets the description of what went wrong. It is suitable for logs, and is never shown to the user.
   *
   * @return the description
   */
  public @Nonnull String getDescription() {
    return this.getMessage();
  }

}
