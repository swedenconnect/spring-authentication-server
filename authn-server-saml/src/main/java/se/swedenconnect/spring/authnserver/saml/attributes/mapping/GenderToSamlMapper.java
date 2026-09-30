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
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;

/**
 * Maps the generic gender attribute into the SAML {@code gender} attribute, turning {@code female} into {@code F},
 * {@code male} into {@code M} and {@code u} into {@code U}.
 *
 * @author Martin Lindström
 */
public class GenderToSamlMapper implements ToProtocolAttributeMapper<Attribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.GENDER);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<Attribute> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {
    final String value = toSamlValue(String.valueOf(attributes.get(0).getValue()));
    if (value == null) {
      return List.of();
    }
    return List.of(SamlAttributeValues.createAttribute(AttributeConstants.ATTRIBUTE_NAME_GENDER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GENDER, List.of(value)));
  }

  /**
   * Converts a generic gender value into the SAML form.
   *
   * @param value the generic value
   * @return the SAML value, or {@code null} if the generic value is not one of {@code female}, {@code male} and
   *     {@code u}
   */
  public static @Nullable String toSamlValue(final @Nullable String value) {
    if (value == null) {
      return null;
    }
    return switch (value.toLowerCase()) {
      case "male" -> "M";
      case "female" -> "F";
      case "u" -> "U";
      default -> null;
    };
  }

}
