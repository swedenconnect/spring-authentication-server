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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.EidasNaturalPersonAddress;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Maps an attribute holding an eIDAS natural person address into the generic attributes for the parts of that
 * address. A request for the address is a request for every part of it, and a value, should the requester supply one,
 * is split into the parts it holds.
 * <p>
 * The same address reaches us under two names, as {@code eidasNaturalPersonAddress} in the Swedish eID Framework and
 * as {@code CurrentAddress} in eIDAS, so the name is given to the constructor.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasAddressFromProtocolMapper implements FromProtocolAttributeMapper<SamlRequestedAttribute> {

  /** The attribute name that this mapper handles. */
  private final String name;

  /**
   * Constructor.
   *
   * @param name the attribute name holding the eIDAS natural person address
   */
  public EidasAddressFromProtocolMapper(final @NonNull String name) {
    this.name = Objects.requireNonNull(name, "name must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedNames() {
    return List.of(this.name);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<GenericRequestedAttribute> map(final @NonNull List<SamlRequestedAttribute> inputs,
      final @NonNull FromProtocolMappingContext<SamlRequestedAttribute> context) {

    final boolean essential = inputs.stream().anyMatch(SamlRequestedAttribute::required);
    final List<String> values = inputs.stream()
        .flatMap(i -> i.stringValues().stream())
        .toList();

    if (values.isEmpty()) {
      return EidasNaturalPersonAddress.getIdentifiers().stream()
          .map(identifier -> GenericRequestedAttribute.of(identifier, essential))
          .toList();
    }
    final List<GenericRequestedAttribute> result = new ArrayList<>();
    for (final String value : values) {
      for (final Map.Entry<String, String> part : EidasNaturalPersonAddress.parse(value).entrySet()) {
        result.add(new GenericRequestedAttribute(part.getKey(), essential, List.of(part.getValue()), null));
      }
    }
    return result;
  }

}
