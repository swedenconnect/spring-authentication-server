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

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Maps the SAML {@code gender} attribute into the generic gender attribute.
 * <p>
 * The generic attribute uses the OpenID Connect values, so the SAML values {@code M} and {@code F}, in either case,
 * become {@code male} and {@code female}. The SAML value {@code U} is kept as {@code u}.
 * </p>
 *
 * @author Martin Lindström
 */
public class GenderFromSamlMapper implements FromProtocolAttributeMapper<SamlRequestedAttribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedNames() {
    return List.of(AttributeConstants.ATTRIBUTE_NAME_GENDER);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<GenericRequestedAttribute> map(final @NonNull List<SamlRequestedAttribute> inputs,
      final @NonNull FromProtocolMappingContext<SamlRequestedAttribute> context) {

    final boolean essential = inputs.stream().anyMatch(SamlRequestedAttribute::required);
    final List<String> values = inputs.stream()
        .flatMap(i -> i.stringValues().stream())
        .map(GenderFromSamlMapper::toGenericValue)
        .filter(java.util.Objects::nonNull)
        .distinct()
        .toList();
    return List.of(new GenericRequestedAttribute(AttributeIdentifiers.GENDER, essential, values, null));
  }

  /**
   * Converts a SAML gender value into the generic form.
   *
   * @param value the SAML value
   * @return the generic value, or {@code null} if the SAML value is not one of {@code M}, {@code F} and {@code U}
   */
  public static @Nullable String toGenericValue(final @Nullable String value) {
    if (value == null) {
      return null;
    }
    return switch (value.toUpperCase()) {
      case "M" -> "male";
      case "F" -> "female";
      case "U" -> "u";
      default -> null;
    };
  }

}
