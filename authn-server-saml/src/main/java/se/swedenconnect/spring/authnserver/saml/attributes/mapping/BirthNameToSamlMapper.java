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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;

/**
 * Maps the generic birth name attributes into the SAML {@code birthName} attribute.
 * <p>
 * The full birth name is used when it is present. Otherwise the parts are joined with a space, in the order given
 * name, middle name and family name, and parts that are missing are skipped.
 * </p>
 *
 * @author Martin Lindström
 */
public class BirthNameToSamlMapper implements ToProtocolAttributeMapper<Attribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.BIRTH_NAME, AttributeIdentifiers.BIRTH_GIVEN_NAME,
        AttributeIdentifiers.BIRTH_MIDDLE_NAME, AttributeIdentifiers.BIRTH_FAMILY_NAME);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<Attribute> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {

    String birthName = context.getStringValue(AttributeIdentifiers.BIRTH_NAME);
    if (birthName == null) {
      final List<String> parts = new ArrayList<>();
      for (final String identifier : List.of(AttributeIdentifiers.BIRTH_GIVEN_NAME,
          AttributeIdentifiers.BIRTH_MIDDLE_NAME, AttributeIdentifiers.BIRTH_FAMILY_NAME)) {
        final String part = context.getStringValue(identifier);
        if (part != null && !part.isBlank()) {
          parts.add(part);
        }
      }
      birthName = !parts.isEmpty() ? String.join(" ", parts) : null;
    }
    if (birthName == null) {
      return List.of();
    }
    return List.of(SamlAttributeValues.createAttribute(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_BIRTH_NAME, List.of(birthName)));
  }

}
