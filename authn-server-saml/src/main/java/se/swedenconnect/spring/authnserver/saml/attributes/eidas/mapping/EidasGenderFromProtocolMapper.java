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

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeValues;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasNaturalPersonAttributes;

/**
 * Maps the eIDAS {@code Gender} attribute into the generic gender attribute, turning the eIDAS values {@code Male},
 * {@code Female} and {@code Unspecified} into {@code male}, {@code female} and {@code u}.
 *
 * @author Martin Lindström
 */
public class EidasGenderFromProtocolMapper implements FromProtocolAttributeMapper<SamlRequestedAttribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedNames() {
    return List.of(EidasNaturalPersonAttributes.GENDER.name());
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<GenericRequestedAttribute> map(final @NonNull List<SamlRequestedAttribute> inputs,
      final @NonNull FromProtocolMappingContext<SamlRequestedAttribute> context) {

    final boolean essential = inputs.stream().anyMatch(SamlRequestedAttribute::required);
    final List<String> values = inputs.stream()
        .flatMap(i -> i.stringValues().stream())
        .map(EidasAttributeValues::fromGender)
        .filter(Objects::nonNull)
        .distinct()
        .toList();
    return List.of(new GenericRequestedAttribute(AttributeIdentifiers.GENDER, essential, values, null));
  }

}
