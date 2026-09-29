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
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;

/**
 * A user that has been authenticated, in a form that does not depend on the protocol that asked for the
 * authentication.
 * <p>
 * The user is described by its generic attributes. One of them is the primary attribute, and its value is the user
 * name. The object also records how the authentication was made: under which authentication context, when, from which
 * client address, and whether a sign message was displayed for the user.
 * </p>
 * <p>
 * A server that proxies the authentication to another service does not record the authenticating authority here. The
 * authentication step sets the {@link
 * se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers#AUTHENTICATION_PROVIDER} attribute instead.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthenticatedUser implements UserDetails {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The user attributes. */
  private final List<GenericAttribute<?>> attributes;

  /** The identifier of the primary attribute. */
  private final String primaryAttribute;

  /** The authentication context URI under which the user was authenticated. */
  private final String authnContextUri;

  /** The authentication instant. */
  private final Instant authnInstant;

  /** The IP address of the client that the user was authenticated from. */
  private final String clientIpAddress;

  /** Whether a sign message was displayed for the user. */
  private boolean signMessageDisplayed = false;

  /** The language of the sign message that was displayed. */
  private String signMessageLanguage;

  /**
   * Constructor.
   *
   * @param attributes the user attributes, must not be empty
   * @param primaryAttribute the identifier of the primary attribute, must appear among the attributes with a value
   * @param authnContextUri the authentication context URI under which the user was authenticated
   * @param authnInstant the authentication instant
   * @param clientIpAddress the IP address of the client that the user was authenticated from
   */
  public AuthenticatedUser(final @Nonnull Collection<GenericAttribute<?>> attributes,
      final @Nonnull String primaryAttribute, final @Nonnull String authnContextUri,
      final @Nonnull Instant authnInstant, final @Nonnull String clientIpAddress) {

    Objects.requireNonNull(attributes, "attributes must not be null");
    if (attributes.isEmpty()) {
      throw new IllegalArgumentException("attributes must not be empty");
    }
    this.attributes = List.copyOf(attributes);
    if (!StringUtils.hasText(primaryAttribute) || this.attributes.stream()
        .noneMatch(a -> Objects.equals(a.getIdentifier(), primaryAttribute) && !a.getValues().isEmpty())) {
      throw new IllegalArgumentException("primaryAttribute must be set and appear among the attributes");
    }
    this.primaryAttribute = primaryAttribute;
    if (!StringUtils.hasText(authnContextUri)) {
      throw new IllegalArgumentException("authnContextUri must be set and not empty");
    }
    this.authnContextUri = authnContextUri;
    this.authnInstant = Objects.requireNonNull(authnInstant, "authnInstant must not be null");
    if (!StringUtils.hasText(clientIpAddress)) {
      throw new IllegalArgumentException("clientIpAddress must be set and not empty");
    }
    this.clientIpAddress = clientIpAddress;
  }

  /**
   * Gets the user name, which is the first value of the primary attribute.
   *
   * @return the user name
   */
  @Override
  public @Nonnull String getUsername() {
    return String.valueOf(Objects.requireNonNull(this.getAttribute(this.primaryAttribute)).getValue());
  }

  /**
   * Gets all user attributes. The list is never empty.
   *
   * @return the user attributes
   */
  public @Nonnull List<GenericAttribute<?>> getAttributes() {
    return this.attributes;
  }

  /**
   * Gets a user attribute.
   *
   * @param identifier the attribute identifier
   * @return the attribute, or {@code null} if the user does not have it
   */
  public @Nullable GenericAttribute<?> getAttribute(final @Nonnull String identifier) {
    return this.attributes.stream()
        .filter(a -> Objects.equals(a.getIdentifier(), identifier))
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the identifier of the primary attribute.
   *
   * @return the identifier of the primary attribute
   */
  public @Nonnull String getPrimaryAttribute() {
    return this.primaryAttribute;
  }

  /**
   * Gets the authentication context URI under which the user was authenticated. Sweden Connect uses the same URIs as
   * SAML {@code AuthnContextClassRef} and as OpenID Connect {@code acr}.
   *
   * @return the authentication context URI
   */
  public @Nonnull String getAuthnContextUri() {
    return this.authnContextUri;
  }

  /**
   * Gets the authentication instant.
   *
   * @return the authentication instant
   */
  public @Nonnull Instant getAuthnInstant() {
    return this.authnInstant;
  }

  /**
   * Gets the IP address of the client that the user was authenticated from.
   *
   * @return the client IP address
   */
  public @Nonnull String getClientIpAddress() {
    return this.clientIpAddress;
  }

  /**
   * Predicate telling whether a sign message was displayed for the user.
   *
   * @return {@code true} if a sign message was displayed and {@code false} otherwise
   */
  public boolean isSignMessageDisplayed() {
    return this.signMessageDisplayed;
  }

  /**
   * Gets the language of the sign message that was displayed for the user. An OpenID Connect sign message may be given
   * in several languages, so the language of the message that was actually displayed is recorded.
   *
   * @return the language tag, or {@code null} if no sign message was displayed or the language is not known
   */
  public @Nullable String getSignMessageLanguage() {
    return this.signMessageLanguage;
  }

  /**
   * Records whether a sign message was displayed for the user, and in which language.
   *
   * @param signMessageDisplayed {@code true} if a sign message was displayed and {@code false} otherwise
   * @param language the language of the message that was displayed, may be {@code null} if it is not known. Ignored
   *          when {@code signMessageDisplayed} is {@code false}
   */
  public void setSignMessageDisplayed(final boolean signMessageDisplayed, final @Nullable String language) {
    this.signMessageDisplayed = signMessageDisplayed;
    this.signMessageLanguage = signMessageDisplayed ? language : null;
  }

  /**
   * Always returns an empty collection.
   */
  @Override
  public @Nonnull Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  /**
   * Always returns the empty string.
   */
  @Override
  public @Nonnull String getPassword() {
    return "";
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final AuthenticatedUser other)) {
      return false;
    }
    return this.signMessageDisplayed == other.signMessageDisplayed
        && Objects.equals(this.attributes, other.attributes)
        && Objects.equals(this.primaryAttribute, other.primaryAttribute)
        && Objects.equals(this.authnContextUri, other.authnContextUri)
        && Objects.equals(this.authnInstant, other.authnInstant)
        && Objects.equals(this.clientIpAddress, other.clientIpAddress)
        && Objects.equals(this.signMessageLanguage, other.signMessageLanguage);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.attributes, this.primaryAttribute, this.authnContextUri, this.authnInstant,
        this.clientIpAddress, this.signMessageDisplayed, this.signMessageLanguage);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(this.getUsername());
    sb.append(", authn-context=").append(this.authnContextUri);
    sb.append(", authn-instant=").append(this.authnInstant);
    sb.append(", client-ip=").append(this.clientIpAddress);
    if (this.signMessageDisplayed) {
      sb.append(", sign-message-displayed=true");
      if (this.signMessageLanguage != null) {
        sb.append(", sign-message-language=").append(this.signMessageLanguage);
      }
    }
    sb.append(", attributes=").append(this.attributes);
    return sb.toString();
  }

}
