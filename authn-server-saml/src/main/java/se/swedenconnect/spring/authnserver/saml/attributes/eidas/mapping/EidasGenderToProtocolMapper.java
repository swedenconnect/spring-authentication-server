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

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeValues;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasNaturalPersonAttributes;

/**
 * Maps the generic gender attribute into the eIDAS {@code Gender} attribute, turning {@code female}, {@code male} and
 * {@code u} into {@code Female}, {@code Male} and {@code Unspecified}.
 * <p>
 * Unlike the Swedish eID Framework, eIDAS has a value for an unspecified gender, so nothing is lost here.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasGenderToProtocolMapper implements ToProtocolAttributeMapper<Attribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.GENDER);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<Attribute> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {
    final Attribute attribute = EidasAttributeValues.createAttribute(
        EidasNaturalPersonAttributes.GENDER, List.of(String.valueOf(attributes.get(0).getValue())));
    return attribute != null ? List.of(attribute) : List.of();
  }

}
