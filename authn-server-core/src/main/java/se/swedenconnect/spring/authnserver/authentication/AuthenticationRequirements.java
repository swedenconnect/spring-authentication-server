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

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;

/**
 * What the requester asks for, in a form that does not depend on the protocol it used. It is what the user
 * authentication step works from.
 * <p>
 * A protocol may ask for more than this. A protocol module therefore extends this class, see the SAML subtype that adds
 * the declared entity categories and the SADRequest.
 * </p>
 * <p>
 * The object is carried by the authentication result, so it survives Java serialization.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthenticationRequirements implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Whether the user must be authenticated again even though an authentication could be reused. */
  private boolean forceAuthn = false;

  /** The maximum age of an authentication that may be reused. */
  private Duration maxAuthnAge;

  /** Whether the server must answer without interacting with the user. */
  private boolean passiveAuthn = false;

  /** Whether the user must be asked for consent. */
  private boolean consentRequired = false;

  /** The attributes that the requester asks for. */
  private List<GenericRequestedAttribute> requestedAttributes = List.of();

  /** The acceptable authentication context URIs, in the requester's order of preference. */
  private List<String> authnContextRequirements = List.of();

  /** The authentication providers that the requester asks for. */
  private List<String> requestedAuthnProviders = List.of();

  /** The parties that originally asked for the authentication. */
  private List<OriginalRequester> originalRequesters = List.of();

  /** The message that must be shown before the user approves a signature. */
  private GenericSignMessage signMessage;

  /** The message that the requester wants shown to the user. */
  private GenericUserMessage userMessage;

  /**
   * Default constructor.
   */
  public AuthenticationRequirements() {
  }

  /**
   * Copy constructor, for a protocol module that turns generic requirements into its own subtype.
   *
   * @param other the requirements to copy
   */
  protected AuthenticationRequirements(final @NonNull AuthenticationRequirements other) {
    Objects.requireNonNull(other, "other must not be null");
    this.forceAuthn = other.forceAuthn;
    this.maxAuthnAge = other.maxAuthnAge;
    this.passiveAuthn = other.passiveAuthn;
    this.consentRequired = other.consentRequired;
    this.requestedAttributes = other.requestedAttributes;
    this.authnContextRequirements = other.authnContextRequirements;
    this.requestedAuthnProviders = other.requestedAuthnProviders;
    this.originalRequesters = other.originalRequesters;
    this.signMessage = other.signMessage;
    this.userMessage = other.userMessage;
  }

  /**
   * Predicate telling whether the user must be authenticated again even though an authentication could have been
   * reused. It is SAML {@code ForceAuthn} and OpenID Connect {@code prompt=login}.
   * <p>
   * A maximum authentication age of zero means the same thing, see {@link #getMaxAuthnAge()}, so such a value also
   * makes this predicate return {@code true}.
   * </p>
   *
   * @return {@code true} if the user must be authenticated again and {@code false} otherwise
   */
  public boolean isForceAuthn() {
    return this.forceAuthn || this.maxAuthnAge != null && this.maxAuthnAge.isZero();
  }

  /**
   * Assigns whether the user must be authenticated again even though an authentication could be reused.
   *
   * @param forceAuthn {@code true} if the user must be authenticated again and {@code false} otherwise
   */
  public void setForceAuthn(final boolean forceAuthn) {
    this.forceAuthn = forceAuthn;
  }

  /**
   * Gets the maximum age of an authentication that may be reused. It is OpenID Connect {@code max_age}, and SAML has no
   * counterpart. A value of zero means the same as {@link #isForceAuthn()}.
   *
   * @return the maximum authentication age, or {@code null} if the requester did not state one
   */
  public @Nullable Duration getMaxAuthnAge() {
    return this.maxAuthnAge;
  }

  /**
   * Assigns the maximum age of an authentication that may be reused.
   *
   * @param maxAuthnAge the maximum authentication age, may be {@code null}
   */
  public void setMaxAuthnAge(final @Nullable Duration maxAuthnAge) {
    if (maxAuthnAge != null && maxAuthnAge.isNegative()) {
      throw new IllegalArgumentException("maxAuthnAge must not be negative");
    }
    this.maxAuthnAge = maxAuthnAge;
  }

  /**
   * Predicate telling whether the server must answer without interacting with the user. It is SAML {@code IsPassive}
   * and OpenID Connect {@code prompt=none}.
   *
   * @return {@code true} if the server must not interact with the user and {@code false} otherwise
   */
  public boolean isPassiveAuthn() {
    return this.passiveAuthn;
  }

  /**
   * Assigns whether the server must answer without interacting with the user.
   *
   * @param passiveAuthn {@code true} if the server must not interact with the user and {@code false} otherwise
   */
  public void setPassiveAuthn(final boolean passiveAuthn) {
    this.passiveAuthn = passiveAuthn;
  }

  /**
   * Predicate telling whether the user must be asked for consent. It is OpenID Connect {@code prompt=consent}, and
   * SAML has no counterpart.
   *
   * @return {@code true} if the user must be asked for consent and {@code false} otherwise
   */
  public boolean isConsentRequired() {
    return this.consentRequired;
  }

  /**
   * Assigns whether the user must be asked for consent.
   *
   * @param consentRequired {@code true} if the user must be asked for consent and {@code false} otherwise
   */
  public void setConsentRequired(final boolean consentRequired) {
    this.consentRequired = consentRequired;
  }

  /**
   * Gets the attributes that the requester asks for.
   * <p>
   * There is no separate notion of principal selection. A SAML {@code PrincipalSelection} extension, and an OpenID
   * Connect claims request that carries a value, become requested attributes with values that are not essential.
   * </p>
   *
   * @return the requested attributes, possibly empty
   */
  public @NonNull List<GenericRequestedAttribute> getRequestedAttributes() {
    return this.requestedAttributes;
  }

  /**
   * Assigns the attributes that the requester asks for.
   *
   * @param requestedAttributes the requested attributes, may be {@code null}
   */
  public void setRequestedAttributes(final @Nullable Collection<GenericRequestedAttribute> requestedAttributes) {
    this.requestedAttributes = requestedAttributes != null ? List.copyOf(requestedAttributes) : List.of();
  }

  /**
   * Gets the acceptable authentication context URIs, in the requester's order of preference. It is the SAML
   * {@code AuthnContextClassRef} elements of {@code RequestedAuthnContext}, and OpenID Connect {@code acr_values},
   * which is ordered by preference. Sweden Connect uses the same URIs in both protocols.
   *
   * @return the acceptable authentication context URIs, possibly empty
   */
  public @NonNull List<String> getAuthnContextRequirements() {
    return this.authnContextRequirements;
  }

  /**
   * Assigns the acceptable authentication context URIs, in the requester's order of preference.
   *
   * @param authnContextRequirements the acceptable authentication context URIs, may be {@code null}
   */
  public void setAuthnContextRequirements(final @Nullable Collection<String> authnContextRequirements) {
    this.authnContextRequirements =
        authnContextRequirements != null ? List.copyOf(authnContextRequirements) : List.of();
  }

  /**
   * Gets the authentication providers that the requester asks for. It is the SAML {@code <saml2p:IDPList>} under
   * {@code <saml2p:Scoping>}, and the OpenID Connect {@code authnProvider} request parameter, which allows one value.
   *
   * @return the requested authentication providers, possibly empty
   */
  public @NonNull List<String> getRequestedAuthnProviders() {
    return this.requestedAuthnProviders;
  }

  /**
   * Assigns the authentication providers that the requester asks for.
   *
   * @param requestedAuthnProviders the requested authentication providers, may be {@code null}
   */
  public void setRequestedAuthnProviders(final @Nullable Collection<String> requestedAuthnProviders) {
    this.requestedAuthnProviders = requestedAuthnProviders != null ? List.copyOf(requestedAuthnProviders) : List.of();
  }

  /**
   * Gets the parties that originally asked for the authentication, passed on by a requester that acts as a proxy.
   *
   * @return the original requesters, possibly empty
   */
  public @NonNull List<OriginalRequester> getOriginalRequesters() {
    return this.originalRequesters;
  }

  /**
   * Assigns the parties that originally asked for the authentication.
   *
   * @param originalRequesters the original requesters, may be {@code null}
   */
  public void setOriginalRequesters(final @Nullable Collection<OriginalRequester> originalRequesters) {
    this.originalRequesters = originalRequesters != null ? List.copyOf(originalRequesters) : List.of();
  }

  /**
   * Gets the message that must be shown before the user approves a signature.
   *
   * @return the sign message, or {@code null} if the requester did not send one
   */
  public @Nullable GenericSignMessage getSignMessage() {
    return this.signMessage;
  }

  /**
   * Assigns the message that must be shown before the user approves a signature.
   *
   * @param signMessage the sign message, may be {@code null}
   */
  public void setSignMessage(final @Nullable GenericSignMessage signMessage) {
    this.signMessage = signMessage;
  }

  /**
   * Gets the message that the requester wants shown to the user together with the authentication.
   *
   * @return the user message, or {@code null} if the requester did not send one
   */
  public @Nullable GenericUserMessage getUserMessage() {
    return this.userMessage;
  }

  /**
   * Assigns the message that the requester wants shown to the user together with the authentication.
   *
   * @param userMessage the user message, may be {@code null}
   */
  public void setUserMessage(final @Nullable GenericUserMessage userMessage) {
    this.userMessage = userMessage;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || this.getClass() != obj.getClass()) {
      return false;
    }
    final AuthenticationRequirements other = (AuthenticationRequirements) obj;
    return this.forceAuthn == other.forceAuthn
        && this.passiveAuthn == other.passiveAuthn
        && this.consentRequired == other.consentRequired
        && Objects.equals(this.maxAuthnAge, other.maxAuthnAge)
        && Objects.equals(this.requestedAttributes, other.requestedAttributes)
        && Objects.equals(this.authnContextRequirements, other.authnContextRequirements)
        && Objects.equals(this.requestedAuthnProviders, other.requestedAuthnProviders)
        && Objects.equals(this.originalRequesters, other.originalRequesters)
        && Objects.equals(this.signMessage, other.signMessage)
        && Objects.equals(this.userMessage, other.userMessage);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.forceAuthn, this.maxAuthnAge, this.passiveAuthn, this.consentRequired,
        this.requestedAttributes, this.authnContextRequirements, this.requestedAuthnProviders, this.originalRequesters,
        this.signMessage, this.userMessage);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("force-authn=").append(this.isForceAuthn());
    if (this.maxAuthnAge != null) {
      sb.append(", max-authn-age=").append(this.maxAuthnAge);
    }
    sb.append(", passive-authn=").append(this.passiveAuthn);
    sb.append(", consent-required=").append(this.consentRequired);
    if (!this.authnContextRequirements.isEmpty()) {
      sb.append(", authn-context-requirements=").append(this.authnContextRequirements);
    }
    if (!this.requestedAttributes.isEmpty()) {
      sb.append(", requested-attributes=").append(this.requestedAttributes);
    }
    if (!this.requestedAuthnProviders.isEmpty()) {
      sb.append(", requested-authn-providers=").append(this.requestedAuthnProviders);
    }
    if (!this.originalRequesters.isEmpty()) {
      sb.append(", original-requesters=").append(this.originalRequesters);
    }
    if (this.signMessage != null) {
      sb.append(", ").append(this.signMessage);
    }
    if (this.userMessage != null) {
      sb.append(", ").append(this.userMessage);
    }
    return sb.toString();
  }

}
