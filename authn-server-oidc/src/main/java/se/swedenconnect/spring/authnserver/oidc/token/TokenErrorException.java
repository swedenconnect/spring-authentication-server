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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.io.Serial;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.oauth2.sdk.ErrorObject;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Thrown when a token request fails. It carries the error that is sent in the token error response, including its
 * HTTP status.
 *
 * @author Martin Lindström
 */
public class TokenErrorException extends Exception {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The error. */
  private final ErrorObject error;

  /**
   * Constructor.
   *
   * @param error the error, whose code and HTTP status are used
   * @param description the description, sent as {@code error_description}. It must not hold personal data
   */
  public TokenErrorException(final @NonNull ErrorObject error, final @NonNull String description) {
    this(error, description, null);
  }

  /**
   * Constructor.
   *
   * @param error the error, whose code and HTTP status are used
   * @param description the description, sent as {@code error_description}
   * @param cause the cause, may be {@code null}
   */
  public TokenErrorException(final @NonNull ErrorObject error, final @NonNull String description,
      final @Nullable Throwable cause) {
    super(Objects.requireNonNull(description, "description must not be null"), cause);
    this.error = Objects.requireNonNull(error, "error must not be null").setDescription(description);
  }

  /**
   * Gets the error, with its description.
   *
   * @return the error
   */
  public @NonNull ErrorObject getError() {
    return this.error;
  }

}
