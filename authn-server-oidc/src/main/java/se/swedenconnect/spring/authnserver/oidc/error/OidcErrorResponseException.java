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
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.Objects;

import org.springframework.security.core.AuthenticationException;

import com.nimbusds.oauth2.sdk.ErrorObject;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Thrown when the processing of an OpenID Connect authentication request fails in a way that is reported to the client
 * as an error response at its redirect URI.
 * <p>
 * The errors that the user authentication step produces are reported with
 * {@link se.swedenconnect.spring.authnserver.error.AuthenticationErrorException} and mapped by
 * {@link OidcErrorMapping}. This exception is for the errors that the request itself causes, such as
 * {@code invalid_request} or {@code invalid_request_object}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcErrorResponseException extends AuthenticationException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The error code. */
  private final String errorCode;

  /**
   * Constructor.
   *
   * @param error the error, whose code is sent to the client
   * @param description a description of what went wrong, sent as {@code error_description}. It must be suitable for
   *          the client's logs, and must not hold personal data
   */
  public OidcErrorResponseException(final @Nonnull ErrorObject error, final @Nonnull String description) {
    this(error, description, null);
  }

  /**
   * Constructor.
   *
   * @param error the error, whose code is sent to the client
   * @param description a description of what went wrong, sent as {@code error_description}
   * @param cause the cause of the error, may be {@code null}
   */
  public OidcErrorResponseException(final @Nonnull ErrorObject error, final @Nonnull String description,
      final @Nullable Throwable cause) {
    super(Objects.requireNonNull(description, "description must not be null"));
    if (cause != null) {
      this.initCause(cause);
    }
    this.errorCode = Objects.requireNonNull(Objects.requireNonNull(error, "error must not be null").getCode(),
        "error code must not be null");
  }

  /**
   * Gets the error code.
   *
   * @return the error code
   */
  public @Nonnull String getErrorCode() {
    return this.errorCode;
  }

  /**
   * Gets the description of what went wrong.
   *
   * @return the description
   */
  public @Nonnull String getDescription() {
    return this.getMessage();
  }

  /**
   * Gets the error to send to the client, with the description.
   *
   * @return an {@link ErrorObject}
   */
  public @Nonnull ErrorObject toErrorObject() {
    return new ErrorObject(this.errorCode, this.getDescription());
  }

}
