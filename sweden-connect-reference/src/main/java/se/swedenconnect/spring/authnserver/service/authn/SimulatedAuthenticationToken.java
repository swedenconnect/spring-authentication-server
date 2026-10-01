/*
 * Copyright 2016-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.service.authn;

import java.io.Serial;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUser;

/**
 * What the simulated authentication delivers to the provider: the selected user and how the user was "authenticated".
 *
 * @author Martin Lindström
 */
public class SimulatedAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The selected user. */
  private final SimulatedUser user;

  /** The selected level of assurance URI. */
  private final String loa;

  /** The authentication instant. */
  private final Instant authnInstant;

  /** The IP address of the client. */
  private final String clientIpAddress;

  /** Whether the sign message was displayed. */
  private boolean signMessageDisplayed = false;

  /** The language of the displayed sign message. */
  private String signMessageLanguage;

  /**
   * Constructor.
   *
   * @param user the selected user
   * @param loa the selected level of assurance URI
   * @param authnInstant the authentication instant
   * @param clientIpAddress the IP address of the client
   */
  public SimulatedAuthenticationToken(final @NonNull SimulatedUser user, final @NonNull String loa,
      final @NonNull Instant authnInstant, final @NonNull String clientIpAddress) {
    super(List.of());
    this.user = Objects.requireNonNull(user, "user must not be null");
    this.loa = Objects.requireNonNull(loa, "loa must not be null");
    this.authnInstant = Objects.requireNonNull(authnInstant, "authnInstant must not be null");
    this.clientIpAddress = Objects.requireNonNull(clientIpAddress, "clientIpAddress must not be null");
    this.setDetails(user);
    this.setAuthenticated(true);
  }

  /**
   * Gets the selected user.
   *
   * @return the user
   */
  public @NonNull SimulatedUser getUser() {
    return this.user;
  }

  /**
   * Gets the selected level of assurance.
   *
   * @return the LoA URI
   */
  public @NonNull String getLoa() {
    return this.loa;
  }

  /**
   * Gets the authentication instant.
   *
   * @return the authentication instant
   */
  public @NonNull Instant getAuthnInstant() {
    return this.authnInstant;
  }

  /**
   * Gets the IP address of the client.
   *
   * @return the IP address
   */
  public @NonNull String getClientIpAddress() {
    return this.clientIpAddress;
  }

  /**
   * Tells whether the sign message was displayed.
   *
   * @return {@code true} if the sign message was displayed
   */
  public boolean isSignMessageDisplayed() {
    return this.signMessageDisplayed;
  }

  /**
   * Gets the language of the displayed sign message.
   *
   * @return the language tag, or {@code null} if the message has no language or no sign message was displayed
   */
  public @Nullable String getSignMessageLanguage() {
    return this.signMessageLanguage;
  }

  /**
   * Records that the sign message was displayed, and in which language.
   *
   * @param signMessageLanguage the language of the displayed message, or {@code null} if it has none
   */
  public void setSignMessageDisplayed(final @Nullable String signMessageLanguage) {
    this.signMessageDisplayed = true;
    this.signMessageLanguage = signMessageLanguage;
  }

  /**
   * Returns an empty string, since there are no credentials.
   */
  @Override
  public @NonNull Object getCredentials() {
    return "";
  }

  /**
   * Returns the {@link SimulatedUser}.
   */
  @Override
  public @NonNull Object getPrincipal() {
    return this.user;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj) || !(obj instanceof final SimulatedAuthenticationToken other)) {
      return false;
    }
    return this.loa.equals(other.loa) && this.authnInstant.equals(other.authnInstant)
        && this.clientIpAddress.equals(other.clientIpAddress)
        && this.signMessageDisplayed == other.signMessageDisplayed
        && Objects.equals(this.signMessageLanguage, other.signMessageLanguage);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.loa, this.authnInstant);
  }

}
