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
package se.swedenconnect.spring.authnserver.authentication;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * The result of a user authentication. It is an {@link Authentication} token holding an {@link AuthenticatedUser}, and
 * it is what the SAML and OpenID Connect layers translate into an assertion or a set of tokens.
 * <p>
 * The object is stored in the user session so that it can be reused for single sign-on, also by the other protocol.
 * Everything it holds therefore survives Java serialization.
 * </p>
 *
 * @author Martin Lindström
 */
public class UserAuthentication extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The authenticated user. */
  private final AuthenticatedUser user;

  /** Tracking of all the times this authentication result has been used. */
  private final AuthenticationUsageTrack usageTrack = new AuthenticationUsageTrack();

  /** Whether the result may be reused for single sign-on. */
  private boolean reuseForSso = true;

  /** Protocol specific data about the request that the result was produced for. */
  private Serializable protocolRequestData;

  /** What the requester asked for. */
  private AuthenticationRequirements authnRequirements;

  /**
   * Constructor.
   *
   * @param user the authenticated user
   */
  public UserAuthentication(final @Nonnull AuthenticatedUser user) {
    super(List.of());
    this.user = Objects.requireNonNull(user, "user must not be null");
    this.setDetails(user);
    this.setAuthenticated(true);
  }

  /**
   * Maps to {@link #getAuthenticatedUser()}.
   */
  @Override
  public @Nonnull Object getPrincipal() {
    return this.user;
  }

  /**
   * Gets the authenticated user.
   *
   * @return the authenticated user
   */
  public @Nonnull AuthenticatedUser getAuthenticatedUser() {
    return this.user;
  }

  /**
   * Always returns the empty string.
   */
  @Override
  public @Nonnull Object getCredentials() {
    return "";
  }

  /**
   * Predicate telling whether the result may be reused for single sign-on. It may, unless a sign message was displayed
   * for the user, or unless it has been turned off with {@link #setReuseForSso(boolean)}.
   * <p>
   * A result where a sign message was displayed is never reusable. The Sweden Connect OpenID Connect profile, Section
   * 2.4, forbids saving a signature approval for single sign-on.
   * </p>
   * <p>
   * Even when the result is reusable the server may choose not to save it. When it is not reusable it is never saved.
   * </p>
   *
   * @return {@code true} if the result may be reused for single sign-on and {@code false} otherwise
   */
  public boolean isReuseForSso() {
    return this.reuseForSso && !this.user.isSignMessageDisplayed();
  }

  /**
   * Assigns whether the result may be reused for single sign-on. Defaults to {@code true}.
   * <p>
   * A result where a sign message was displayed for the user is never reusable. Assigning {@code true} for such a
   * result has no effect.
   * </p>
   *
   * @param reuseForSso whether the result may be reused for single sign-on
   */
  public void setReuseForSso(final boolean reuseForSso) {
    this.reuseForSso = reuseForSso;
  }

  /**
   * Gets the protocol specific data about the request that the result was produced for. The generic layer carries this
   * data along and never looks at it. The SAML layer keeps the authentication request token here.
   *
   * @return the protocol specific request data, or {@code null} if it is not set or has been cleared
   */
  public @Nullable Serializable getProtocolRequestData() {
    return this.protocolRequestData;
  }

  /**
   * Gets the protocol specific request data provided that it is of the supplied type.
   *
   * @param <T> the expected type
   * @param type the expected type
   * @return the protocol specific request data, or {@code null} if it is missing or of another type
   */
  public <T extends Serializable> @Nullable T getProtocolRequestData(final @Nonnull Class<T> type) {
    return type.isInstance(this.protocolRequestData) ? type.cast(this.protocolRequestData) : null;
  }

  /**
   * Assigns the protocol specific data about the request that the result was produced for.
   *
   * @param protocolRequestData the protocol specific request data
   */
  public void setProtocolRequestData(final @Nullable Serializable protocolRequestData) {
    this.protocolRequestData = protocolRequestData;
  }

  /**
   * Clears the protocol specific request data. This is done before the result is saved for single sign-on, since the
   * request it was produced for has been answered by then.
   */
  public void clearProtocolRequestData() {
    this.protocolRequestData = null;
  }

  /**
   * Gets what the requester asked for.
   *
   * @return the authentication requirements, or {@code null} if they are not set or have been cleared
   */
  public @Nullable AuthenticationRequirements getAuthnRequirements() {
    return this.authnRequirements;
  }

  /**
   * Assigns what the requester asked for.
   *
   * @param authnRequirements the authentication requirements
   */
  public void setAuthnRequirements(final @Nullable AuthenticationRequirements authnRequirements) {
    this.authnRequirements = authnRequirements;
  }

  /**
   * Clears the authentication requirements. This is done before the result is saved for single sign-on, since the
   * request they were deduced from has been answered by then.
   */
  public void clearAuthnRequirements() {
    this.authnRequirements = null;
  }

  /**
   * Registers a use of the authentication result. The first registration is the original authentication and gets the
   * authentication instant of the user. Later registrations get the current instant.
   *
   * @param protocol the protocol that the requester used
   * @param requester the requester, a SAML SP entityID or an OpenID Connect {@code client_id}
   * @param requestId the identifier of the request, the ID of the SAML {@code AuthnRequest}. OpenID Connect has no such
   *          identifier, so {@code null} is given for that protocol
   * @param requestedAttributes the identifiers of the generic attributes that the requester asked for
   */
  public void registerUse(final @Nonnull AuthenticationProtocol protocol, final @Nonnull String requester,
      final @Nullable String requestId, final @Nullable Collection<String> requestedAttributes) {
    final Instant instant = this.usageTrack.size() == 0 ? this.user.getAuthnInstant() : Instant.now();
    this.usageTrack.registerUse(new AuthenticationUse(protocol, requester, requestId, instant,
        requestedAttributes != null ? List.copyOf(requestedAttributes) : List.of()));
  }

  /**
   * Gets the tracking of all the times this authentication result has been used.
   *
   * @return an {@link AuthenticationUsageTrack}
   */
  public @Nonnull AuthenticationUsageTrack getUsageTrack() {
    return this.usageTrack;
  }

  /**
   * Predicate telling whether single sign-on was applied, that is, whether the result has been used more than once.
   *
   * @return {@code true} if single sign-on was applied and {@code false} otherwise
   */
  public boolean isSsoApplied() {
    return this.usageTrack.size() > 1;
  }

}
