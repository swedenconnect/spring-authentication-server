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

import java.io.Serial;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.AuthenticationException;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;

/**
 * Thrown when the user authentication step fails in a way that can be reported to the requester. The protocol module
 * turns it into a SAML {@code Status} or an OpenID Connect error response.
 *
 * @author Martin Lindström
 */
public class AuthenticationErrorException extends AuthenticationException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The error. */
  private final AuthenticationError error;

  /** Why a previous authentication was not reused. */
  private final SsoDenialReason ssoDenialReason;

  /**
   * Constructor.
   *
   * @param error the error
   */
  public AuthenticationErrorException(final @NonNull AuthenticationError error) {
    this(Objects.requireNonNull(error, "error must not be null"), error.getDefaultMessage(), null, null);
  }

  /**
   * Constructor.
   *
   * @param error the error
   * @param description a description of what went wrong, suitable for logs and for the error that the requester is
   *          given. It is never shown to the user
   */
  public AuthenticationErrorException(final @NonNull AuthenticationError error, final @NonNull String description) {
    this(error, description, null, null);
  }

  /**
   * Constructor.
   *
   * @param error the error
   * @param description a description of what went wrong
   * @param cause the cause of the error
   */
  public AuthenticationErrorException(final @NonNull AuthenticationError error, final @NonNull String description,
      final @Nullable Throwable cause) {
    this(error, description, cause, null);
  }

  /**
   * Constructor for {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}, where the reason for not reusing a previous
   * authentication decides which error an OpenID Connect requester is given.
   *
   * @param error the error
   * @param ssoDenialReason why a previous authentication was not reused
   */
  public AuthenticationErrorException(final @NonNull AuthenticationError error,
      final @NonNull SsoDenialReason ssoDenialReason) {
    this(error, Objects.requireNonNull(ssoDenialReason, "ssoDenialReason must not be null").getDescription(), null,
        ssoDenialReason);
  }

  /**
   * Constructor.
   *
   * @param error the error
   * @param description a description of what went wrong
   * @param cause the cause of the error, may be {@code null}
   * @param ssoDenialReason why a previous authentication was not reused, may be {@code null}
   */
  protected AuthenticationErrorException(final @NonNull AuthenticationError error, final @NonNull String description,
      final @Nullable Throwable cause, final @Nullable SsoDenialReason ssoDenialReason) {
    super(Objects.requireNonNull(description, "description must not be null"));
    if (cause != null) {
      this.initCause(cause);
    }
    this.error = Objects.requireNonNull(error, "error must not be null");
    this.ssoDenialReason = ssoDenialReason;
  }

  /**
   * Gets the error.
   *
   * @return the error
   */
  public @NonNull AuthenticationError getError() {
    return this.error;
  }

  /**
   * Gets the message code to resolve the error message with.
   *
   * @return the message code
   */
  public @NonNull String getMessageCode() {
    return this.error.getMessageCode();
  }

  /**
   * Gets the description of what went wrong. It is suitable for logs and for the error that the requester is given, and
   * is never shown to the user.
   *
   * @return the description
   */
  public @NonNull String getDescription() {
    return this.getMessage();
  }

  /**
   * Gets the reason why a previous authentication was not reused. It is set when the error is
   * {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}, and decides whether an OpenID Connect requester is given
   * {@code login_required} or {@code interaction_required}.
   *
   * @return the reason, or {@code null} if the error does not come from a refused single sign-on
   */
  public @Nullable SsoDenialReason getSsoDenialReason() {
    return this.ssoDenialReason;
  }

}
