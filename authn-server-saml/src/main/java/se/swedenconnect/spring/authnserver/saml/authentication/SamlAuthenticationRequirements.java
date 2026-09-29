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
package se.swedenconnect.spring.authnserver.saml.authentication;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;

/**
 * The authentication requirements of a SAML request. It adds what only SAML has: the entity categories that the Service
 * Provider declares in its metadata, and the {@code SADRequest} extension.
 *
 * @author Martin Lindström
 */
public class SamlAuthenticationRequirements extends AuthenticationRequirements {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The entity categories that the Service Provider declares. */
  private List<String> entityCategories = List.of();

  /** The SADRequest extension. */
  private SadRequestExtension sadRequestExtension;

  /**
   * Default constructor.
   */
  public SamlAuthenticationRequirements() {
  }

  /**
   * Constructor setting up the SAML requirements from generic requirements.
   *
   * @param requirements the generic requirements
   */
  public SamlAuthenticationRequirements(final @Nonnull AuthenticationRequirements requirements) {
    super(requirements);
  }

  /**
   * Gets the entity categories that the Service Provider declares in its metadata. Within the Swedish eID Framework
   * this is the preferred way of telling the Identity Provider which attributes the Service Provider needs.
   *
   * @return the declared entity categories, possibly empty
   */
  public @Nonnull List<String> getEntityCategories() {
    return this.entityCategories;
  }

  /**
   * Assigns the entity categories that the Service Provider declares in its metadata.
   *
   * @param entityCategories the declared entity categories, may be {@code null}
   */
  public void setEntityCategories(final @Nullable Collection<String> entityCategories) {
    this.entityCategories = entityCategories != null ? List.copyOf(entityCategories) : List.of();
  }

  /**
   * Gets the {@code SADRequest} extension, which only a signature service sends.
   *
   * @return the SADRequest extension, or {@code null} if the request did not carry one
   */
  public @Nullable SadRequestExtension getSadRequestExtension() {
    return this.sadRequestExtension;
  }

  /**
   * Assigns the {@code SADRequest} extension.
   *
   * @param sadRequestExtension the SADRequest extension, may be {@code null}
   */
  public void setSadRequestExtension(final @Nullable SadRequestExtension sadRequestExtension) {
    this.sadRequestExtension = sadRequestExtension;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (!super.equals(obj)) {
      return false;
    }
    final SamlAuthenticationRequirements other = (SamlAuthenticationRequirements) obj;
    return Objects.equals(this.entityCategories, other.entityCategories)
        && Objects.equals(this.sadRequestExtension, other.sadRequestExtension);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.entityCategories, this.sadRequestExtension);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(super.toString());
    if (!this.entityCategories.isEmpty()) {
      sb.append(", entity-categories=").append(this.entityCategories);
    }
    if (this.sadRequestExtension != null) {
      sb.append(", sad-request=[").append(this.sadRequestExtension).append(']');
    }
    return sb.toString();
  }

}
