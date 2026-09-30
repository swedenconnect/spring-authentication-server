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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * One authentication in progress, as a storage holds it: the redirect token that started it, when it was started, and
 * the outcome once the module's controller has delivered one.
 * <p>
 * Everything it holds survives Java serialization, so that it can be kept in a session that is written to a store.
 * </p>
 *
 * @author Martin Lindström
 * @see RedirectAuthenticationRepository
 */
public class RedirectAuthenticationState implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The redirect token that started the authentication. */
  private final RedirectForAuthenticationToken redirectToken;

  /** When the authentication was started. */
  private final Instant started;

  /** What the module's controller produced, or {@code null} if it has not delivered a result. */
  private Authentication result;

  /** The error that the module's controller reported, or {@code null} if it has not reported one. */
  private AuthenticationErrorException error;

  /**
   * Constructor.
   *
   * @param redirectToken the redirect token that started the authentication
   * @param started when the authentication was started
   */
  public RedirectAuthenticationState(final @NonNull RedirectForAuthenticationToken redirectToken,
      final @NonNull Instant started) {
    this.redirectToken = Objects.requireNonNull(redirectToken, "redirectToken must not be null");
    this.started = Objects.requireNonNull(started, "started must not be null");
  }

  /**
   * Gets the identifier of the authentication.
   *
   * @return the identifier of the authentication
   */
  public @NonNull String getAuthnId() {
    return this.redirectToken.getAuthnId();
  }

  /**
   * Gets the protocol that the authentication was started for.
   *
   * @return the protocol
   */
  public @NonNull AuthenticationProtocol getProtocol() {
    return this.redirectToken.getProtocol();
  }

  /**
   * Gets the redirect token that started the authentication.
   *
   * @return the redirect token
   */
  public @NonNull RedirectForAuthenticationToken getRedirectToken() {
    return this.redirectToken;
  }

  /**
   * Gets when the authentication was started.
   *
   * @return the instant the authentication was started
   */
  public @NonNull Instant getStarted() {
    return this.started;
  }

  /**
   * Gets what the module's controller produced.
   *
   * @return the result, or {@code null} if the controller has not delivered one
   */
  public @Nullable Authentication getResult() {
    return this.result;
  }

  /**
   * Gets the error that the module's controller reported.
   *
   * @return the error, or {@code null} if the controller has not reported one
   */
  public @Nullable AuthenticationErrorException getError() {
    return this.error;
  }

  /**
   * Predicate telling whether the module's controller has delivered an outcome.
   *
   * @return {@code true} if there is a result or an error and {@code false} otherwise
   */
  public boolean isCompleted() {
    return this.result != null || this.error != null;
  }

  /**
   * Records that the authentication succeeded. Any earlier outcome is replaced.
   *
   * @param result what the module's controller produced
   */
  public void complete(final @NonNull Authentication result) {
    this.result = Objects.requireNonNull(result, "result must not be null");
    this.error = null;
  }

  /**
   * Records that the authentication failed. Any earlier outcome is replaced.
   *
   * @param error the error that the module's controller reported
   */
  public void complete(final @NonNull AuthenticationErrorException error) {
    this.error = Objects.requireNonNull(error, "error must not be null");
    this.result = null;
  }

  /**
   * Predicate telling whether the authentication was started longer ago than the supplied maximum age.
   *
   * @param maxAge the maximum age
   * @return {@code true} if the authentication has expired and {@code false} otherwise
   */
  public boolean isExpired(final @NonNull Duration maxAge) {
    return this.started.plus(Objects.requireNonNull(maxAge, "maxAge must not be null")).isBefore(Instant.now());
  }

  /**
   * Turns the state into the token that the flow resumes with.
   *
   * @return a {@link ResumedAuthenticationToken}
   * @throws IllegalStateException if the module's controller has not delivered an outcome
   */
  public @NonNull ResumedAuthenticationToken toResumedToken() {
    if (this.error != null) {
      return new ResumedAuthenticationToken(this.redirectToken, this.error);
    }
    if (this.result != null) {
      return new ResumedAuthenticationToken(this.redirectToken, this.result);
    }
    throw new IllegalStateException("The authentication '%s' has no outcome".formatted(this.getAuthnId()));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "%s, started: %s, completed: %s".formatted(this.redirectToken, this.started, this.isCompleted());
  }

}
