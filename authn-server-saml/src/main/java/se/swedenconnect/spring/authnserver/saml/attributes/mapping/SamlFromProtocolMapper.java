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
package se.swedenconnect.spring.authnserver.saml.attributes.mapping;

import jakarta.annotation.Nonnull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.attributes.AttributeValues;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Maps one SAML attribute name into one or more generic requested attributes. The values that the requester supplied,
 * if any, are carried over to every resulting requested attribute.
 *
 * @author Martin Lindström
 */
public class SamlFromProtocolMapper implements FromProtocolAttributeMapper<SamlRequestedAttribute> {

  /** The SAML attribute name that this mapper handles. */
  private final String name;

  /** The generic attribute identifiers that the SAML attribute maps to. */
  private final List<String> identifiers;

  /**
   * Constructor.
   *
   * @param name the SAML attribute name
   * @param identifiers the generic attribute identifiers that the SAML attribute maps to
   */
  public SamlFromProtocolMapper(final @Nonnull String name, final @Nonnull String... identifiers) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.identifiers = List.of(identifiers);
    if (this.identifiers.isEmpty()) {
      throw new IllegalArgumentException("At least one attribute identifier must be given");
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedNames() {
    return List.of(this.name);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<GenericRequestedAttribute> map(final @Nonnull List<SamlRequestedAttribute> inputs,
      final @Nonnull FromProtocolMappingContext<SamlRequestedAttribute> context) {

    boolean required = false;
    final List<String> values = new ArrayList<>();
    for (final SamlRequestedAttribute input : inputs) {
      required = required || input.required();
      for (final String value : input.stringValues()) {
        if (!values.contains(value)) {
          values.add(value);
        }
      }
    }
    final boolean essential = required;
    return this.identifiers.stream()
        .map(identifier -> new GenericRequestedAttribute(identifier, essential,
            values.stream()
                .map(v -> AttributeValues.fromString(v, identifier, context.getDefinitions()))
                .toList(),
            null))
        .toList();
  }

  /**
   * Gets the generic attribute identifiers that this mapper produces.
   *
   * @return the attribute identifiers
   */
  public @Nonnull List<String> getIdentifiers() {
    return this.identifiers;
  }

}
