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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.EidasNaturalPersonAddress;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;

/**
 * Maps the generic eIDAS address attributes into the SAML {@code eidasNaturalPersonAddress} attribute.
 *
 * @author Martin Lindström
 */
public class EidasAddressToSamlMapper implements ToProtocolAttributeMapper<Attribute> {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return EidasNaturalPersonAddress.getIdentifiers();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<Attribute> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {

    final Map<String, String> parts = new LinkedHashMap<>();
    for (final GenericAttribute<? extends Serializable> attribute : attributes) {
      parts.put(attribute.getIdentifier(), String.valueOf(attribute.getValue()));
    }
    final String value = EidasNaturalPersonAddress.format(parts);
    if (value == null) {
      return List.of();
    }
    return List.of(SamlAttributeValues.createAttribute(
        AttributeConstants.ATTRIBUTE_NAME_EIDAS_NATURAL_PERSON_ADDRESS,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_EIDAS_NATURAL_PERSON_ADDRESS, List.of(value)));
  }

}
