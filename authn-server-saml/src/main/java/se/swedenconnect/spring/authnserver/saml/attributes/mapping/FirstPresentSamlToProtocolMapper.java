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

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;

/**
 * Maps several generic attributes into one SAML attribute, using the first of the attributes that holds a value.
 * <p>
 * This is how a Swedish personal identity number and a coordination number both become the SAML attribute
 * {@code personalIdentityNumber}, and how the {@code c} attribute is taken from the country, and from the eIDAS
 * country when no country is present.
 * </p>
 *
 * @author Martin Lindström
 */
public class FirstPresentSamlToProtocolMapper implements ToProtocolAttributeMapper<Attribute> {

  /** The generic attribute identifiers in order of precedence. */
  private final List<String> identifiers;

  /** The template of the SAML attribute to produce. */
  private final AttributeTemplate template;

  /**
   * Constructor.
   *
   * @param template the template of the SAML attribute to produce
   * @param identifiers the generic attribute identifiers, in order of precedence
   */
  public FirstPresentSamlToProtocolMapper(final @Nonnull AttributeTemplate template,
      final @Nonnull String... identifiers) {
    this.template = Objects.requireNonNull(template, "template must not be null");
    this.identifiers = List.of(identifiers);
    if (this.identifiers.isEmpty()) {
      throw new IllegalArgumentException("At least one attribute identifier must be given");
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedIdentifiers() {
    return this.identifiers;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<Attribute> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context) {
    for (final String identifier : this.identifiers) {
      final GenericAttribute<? extends Serializable> attribute = attributes.stream()
          .filter(a -> a.getIdentifier().equals(identifier))
          .findFirst()
          .orElse(null);
      if (attribute != null) {
        return List.of(SamlAttributeValues.createAttribute(this.template.getName(), this.template.getFriendlyName(),
            attribute.getValues().stream().map(SamlAttributeValues::toSamlStringValue).toList()));
      }
    }
    return List.of();
  }

}
