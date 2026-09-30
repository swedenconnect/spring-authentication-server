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
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.SwedishIdentityNumbers;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Maps a SAML attribute holding a Swedish civic registration number into the two generic attributes that the number
 * may be, the personal identity number and the coordination number.
 * <p>
 * SAML uses one attribute for both kinds of number, so a request for it is a request for both. When the requester
 * supplies values, each value is examined, see {@link SwedishIdentityNumbers}, and only the attribute that the value
 * belongs to is requested.
 * </p>
 *
 * @author Martin Lindström
 */
public class IdentityNumberFromSamlMapper implements FromProtocolAttributeMapper<SamlRequestedAttribute> {

  /** The SAML attribute name that this mapper handles. */
  private final String name;

  /** The generic attribute identifier for a personal identity number. */
  private final String personalIdentityNumberIdentifier;

  /** The generic attribute identifier for a coordination number. */
  private final String coordinationNumberIdentifier;

  /**
   * Constructor.
   *
   * @param name the SAML attribute name
   * @param personalIdentityNumberIdentifier the generic attribute identifier for a personal identity number
   * @param coordinationNumberIdentifier the generic attribute identifier for a coordination number
   */
  public IdentityNumberFromSamlMapper(final @NonNull String name,
      final @NonNull String personalIdentityNumberIdentifier,
      final @NonNull String coordinationNumberIdentifier) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.personalIdentityNumberIdentifier =
        Objects.requireNonNull(personalIdentityNumberIdentifier, "personalIdentityNumberIdentifier must not be null");
    this.coordinationNumberIdentifier =
        Objects.requireNonNull(coordinationNumberIdentifier, "coordinationNumberIdentifier must not be null");
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
    final boolean valuesEssential = inputs.stream().anyMatch(SamlRequestedAttribute::requiredValues);
    final List<String> values = inputs.stream()
        .flatMap(i -> i.stringValues().stream())
        .distinct()
        .toList();

    if (values.isEmpty()) {
      return List.of(
          GenericRequestedAttribute.of(this.personalIdentityNumberIdentifier, essential),
          GenericRequestedAttribute.of(this.coordinationNumberIdentifier, essential));
    }

    final List<String> personalIdentityNumbers = new ArrayList<>();
    final List<String> coordinationNumbers = new ArrayList<>();
    for (final String value : values) {
      if (SwedishIdentityNumbers.isCoordinationNumber(value)) {
        coordinationNumbers.add(value);
      }
      else {
        personalIdentityNumbers.add(value);
      }
    }
    final List<GenericRequestedAttribute> result = new ArrayList<>();
    if (!personalIdentityNumbers.isEmpty()) {
      result.add(new GenericRequestedAttribute(
          this.personalIdentityNumberIdentifier, essential, personalIdentityNumbers, valuesEssential, null));
    }
    if (!coordinationNumbers.isEmpty()) {
      result.add(new GenericRequestedAttribute(
          this.coordinationNumberIdentifier, essential, coordinationNumbers, valuesEssential, null));
    }
    return result;
  }

}
