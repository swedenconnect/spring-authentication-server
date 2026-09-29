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
package se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping;

import jakarta.annotation.Nonnull;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeTemplate;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeValues;

/**
 * Maps one generic attribute into one eIDAS attribute, keeping all values.
 *
 * @author Martin Lindström
 */
public class EidasToProtocolMapper implements ToProtocolAttributeMapper<Attribute> {

  /** The generic attribute identifier that this mapper handles. */
  private final String identifier;

  /** The eIDAS attribute to produce. */
  private final EidasAttributeTemplate template;

  /**
   * Constructor.
   *
   * @param identifier the generic attribute identifier
   * @param template the eIDAS attribute to produce
   */
  public EidasToProtocolMapper(final @Nonnull String identifier, final @Nonnull EidasAttributeTemplate template) {
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    this.template = Objects.requireNonNull(template, "template must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedIdentifiers() {
    return List.of(this.identifier);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<Attribute> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context) {
    final List<Serializable> values = new ArrayList<>();
    for (final GenericAttribute<? extends Serializable> attribute : attributes) {
      for (final Serializable value : attribute.getValues()) {
        if (!values.contains(value)) {
          values.add(value);
        }
      }
    }
    final Attribute attribute = EidasAttributeValues.createAttribute(this.template, values);
    return attribute != null ? List.of(attribute) : List.of();
  }

  /**
   * Gets the eIDAS attribute that this mapper produces.
   *
   * @return an {@link EidasAttributeTemplate}
   */
  public @Nonnull EidasAttributeTemplate getTemplate() {
    return this.template;
  }

}
