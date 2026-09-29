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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * What the user brings back to the resume path: the authentication that was started, and either what the module's
 * controller produced or the error it reported.
 *
 * @author Martin Lindström
 */
public class ResumedAuthenticationToken implements Authentication {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The redirect token that started the authentication. */
  private final RedirectForAuthenticationToken redirectToken;

  /** What the module's controller produced, or {@code null} if the authentication failed. */
  private final Authentication authnToken;

  /** The error that the module's controller reported, or {@code null} if the authentication succeeded. */
  private final AuthenticationErrorException error;

  /** The servlet request that the user returned in. */
  private transient HttpServletRequest servletRequest;

  /**
   * Constructor for an authentication that succeeded.
   *
   * @param redirectToken the redirect token that started the authentication
   * @param authnToken what the module's controller produced
   */
  public ResumedAuthenticationToken(final @Nonnull RedirectForAuthenticationToken redirectToken,
      final @Nonnull Authentication authnToken) {
    this.redirectToken = Objects.requireNonNull(redirectToken, "redirectToken must not be null");
    this.authnToken = Objects.requireNonNull(authnToken, "authnToken must not be null");
    this.error = null;
  }

  /**
   * Constructor for an authentication that failed.
   *
   * @param redirectToken the redirect token that started the authentication
   * @param error the error that the module's controller reported
   */
  public ResumedAuthenticationToken(final @Nonnull RedirectForAuthenticationToken redirectToken,
      final @Nonnull AuthenticationErrorException error) {
    this.redirectToken = Objects.requireNonNull(redirectToken, "redirectToken must not be null");
    this.authnToken = null;
    this.error = Objects.requireNonNull(error, "error must not be null");
  }

  /**
   * Gets the identifier of the authentication.
   *
   * @return the identifier of the authentication
   */
  public @Nonnull String getAuthnId() {
    return this.redirectToken.getAuthnId();
  }

  /**
   * Gets the protocol that the authentication was started for. It is what tells the protocol filters which of them
   * should continue the flow.
   *
   * @return the protocol
   */
  public @Nonnull AuthenticationProtocol getProtocol() {
    return this.redirectToken.getProtocol();
  }

  /**
   * Gets what the provider was given when the authentication was started.
   *
   * @return the authentication input token
   */
  public @Nonnull UserAuthenticationInputToken getAuthnInputToken() {
    return this.redirectToken.getAuthnInputToken();
  }

  /**
   * Gets the authentication contexts that could be used, in the requester's order of preference.
   *
   * @return the authentication context URIs, possibly empty
   */
  public @Nonnull List<String> getAuthnContextUris() {
    return this.redirectToken.getAuthnContextUris();
  }

  /**
   * Gets the redirect token that started the authentication.
   *
   * @return the redirect token
   */
  public @Nonnull RedirectForAuthenticationToken getRedirectToken() {
    return this.redirectToken;
  }

  /**
   * Gets what the module's controller produced.
   *
   * @return the authentication token, or {@code null} if the authentication failed
   */
  public @Nullable Authentication getAuthnToken() {
    return this.authnToken;
  }

  /**
   * Gets the error that the module's controller reported.
   *
   * @return the error, or {@code null} if the authentication succeeded
   */
  public @Nullable AuthenticationErrorException getError() {
    return this.error;
  }

  /**
   * Predicate telling whether the authentication failed.
   *
   * @return {@code true} if the token carries an error and {@code false} otherwise
   */
  public boolean isError() {
    return this.error != null;
  }

  /**
   * Gets the servlet request that the user returned in.
   *
   * @return the servlet request, or {@code null} if it is not available
   */
  public @Nullable HttpServletRequest getServletRequest() {
    return this.servletRequest;
  }

  /**
   * Assigns the servlet request that the user returned in.
   *
   * @param servletRequest the servlet request
   */
  public void setServletRequest(final @Nullable HttpServletRequest servletRequest) {
    this.servletRequest = servletRequest;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String getName() {
    return this.authnToken != null ? this.authnToken.getName() : this.redirectToken.getName();
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<? extends GrantedAuthority> getAuthorities() {
    return this.authnToken != null ? this.authnToken.getAuthorities() : List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Object getCredentials() {
    return this.authnToken != null ? this.authnToken.getCredentials() : null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Object getDetails() {
    return this.authnToken != null ? this.authnToken.getDetails() : null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Object getPrincipal() {
    return this.authnToken != null ? this.authnToken.getPrincipal() : this.redirectToken.getPrincipal();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAuthenticated() {
    return this.authnToken != null && this.authnToken.isAuthenticated();
  }

  /**
   * Must not be called, and throws {@link IllegalArgumentException}.
   */
  @Override
  public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException(
        "setAuthenticated on " + this.getClass().getSimpleName() + " must not be called");
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String toString() {
    return this.error != null
        ? "%s, error: '%s'".formatted(this.redirectToken, this.error.getDescription())
        : this.redirectToken.toString();
  }

}
