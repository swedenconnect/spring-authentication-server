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
package se.swedenconnect.spring.authnserver.saml.attributes;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;

/**
 * A requested attribute as it appears in SAML, given as the OpenSAML {@link Attribute} together with the "required"
 * flag.
 * <p>
 * The SAML side has two representations of a requested attribute, the one from Service Provider metadata,
 * {@link RequestedAttribute}, and the eIDAS one,
 * {@link se.swedenconnect.opensaml.eidas.ext.RequestedAttribute}. The latter extends the former, so
 * {@link #of(RequestedAttribute)} accepts both.
 * </p>
 *
 * @param attribute the OpenSAML attribute
 * @param required whether the requester requires the attribute
 * @author Martin Lindström
 */
public record SamlRequestedAttribute(@Nonnull Attribute attribute, boolean required) {

  /**
   * Constructor.
   *
   * @param attribute the OpenSAML attribute
   * @param required whether the requester requires the attribute
   */
  public SamlRequestedAttribute {
    Objects.requireNonNull(attribute, "attribute must not be null");
  }

  /**
   * Creates a {@code SamlRequestedAttribute} from an OpenSAML requested attribute. Both the requested attribute of
   * SAML metadata and the eIDAS requested attribute are accepted.
   *
   * @param requestedAttribute the requested attribute
   * @return a {@link SamlRequestedAttribute}
   */
  public static @Nonnull SamlRequestedAttribute of(final @Nonnull RequestedAttribute requestedAttribute) {
    Objects.requireNonNull(requestedAttribute, "requestedAttribute must not be null");
    return new SamlRequestedAttribute(requestedAttribute,
        requestedAttribute.isRequired() != null && requestedAttribute.isRequired());
  }

  /**
   * Creates a {@code SamlRequestedAttribute} that is not required from an attribute name.
   *
   * @param name the SAML attribute name
   * @return a {@link SamlRequestedAttribute}
   */
  public static @Nonnull SamlRequestedAttribute of(final @Nonnull String name) {
    return new SamlRequestedAttribute(SamlAttributeValues.createAttribute(name, null, List.of()), false);
  }

  /**
   * Creates a {@code SamlRequestedAttribute} that carries no values.
   *
   * @param name the SAML attribute name
   * @param friendlyName the attribute friendly name, may be {@code null}
   * @param required whether the requester requires the attribute
   * @return a {@link SamlRequestedAttribute}
   */
  public static @Nonnull SamlRequestedAttribute of(final @Nonnull String name, final @Nullable String friendlyName,
      final boolean required) {
    return of(name, friendlyName, required, List.of());
  }

  /**
   * Creates a {@code SamlRequestedAttribute}.
   *
   * @param name the SAML attribute name
   * @param friendlyName the attribute friendly name, may be {@code null}
   * @param required whether the requester requires the attribute
   * @param values the values that the requester will accept
   * @return a {@link SamlRequestedAttribute}
   */
  public static @Nonnull SamlRequestedAttribute of(final @Nonnull String name, final @Nullable String friendlyName,
      final boolean required, final @Nonnull List<String> values) {
    return new SamlRequestedAttribute(SamlAttributeValues.createAttribute(name, friendlyName, values), required);
  }

  /**
   * Gets the SAML attribute name.
   *
   * @return the attribute name
   */
  public @Nonnull String name() {
    return this.attribute.getName();
  }

  /**
   * Gets the values that the requester will accept. Requested attributes usually carry no values.
   *
   * @return the values in string form, possibly empty
   */
  public @Nonnull List<String> stringValues() {
    return SamlAttributeValues.getStringValues(this.attribute);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s, required=%s".formatted(this.name(), this.required);
  }

}
