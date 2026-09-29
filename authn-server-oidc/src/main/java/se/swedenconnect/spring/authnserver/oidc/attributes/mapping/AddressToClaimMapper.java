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
package se.swedenconnect.spring.authnserver.oidc.attributes.mapping;

import jakarta.annotation.Nonnull;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps the generic address attributes into the OpenID Connect {@code address} claim.
 * <p>
 * The street address and the post office box both go into {@code street_address}, which OpenID Connect Core allows to
 * hold several lines. When both are present they are written on a line each, the street address first.
 * </p>
 *
 * @author Martin Lindström
 */
public class AddressToClaimMapper implements ToProtocolAttributeMapper<UserClaim> {

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.FORMATTED_ADDRESS, AttributeIdentifiers.STREET_ADDRESS,
        AttributeIdentifiers.POST_OFFICE_BOX, AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.LOCALITY,
        AttributeIdentifiers.REGION, AttributeIdentifiers.COUNTRY);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<UserClaim> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context) {

    final Address address = new Address();
    setIfPresent(context.getStringValue(AttributeIdentifiers.FORMATTED_ADDRESS), address::setFormatted);
    setIfPresent(context.getStringValue(AttributeIdentifiers.POSTAL_CODE), address::setPostalCode);
    setIfPresent(context.getStringValue(AttributeIdentifiers.LOCALITY), address::setLocality);
    setIfPresent(context.getStringValue(AttributeIdentifiers.REGION), address::setRegion);
    setIfPresent(context.getStringValue(AttributeIdentifiers.COUNTRY), address::setCountry);

    final List<String> streetLines = new ArrayList<>();
    for (final String identifier : List.of(AttributeIdentifiers.STREET_ADDRESS,
        AttributeIdentifiers.POST_OFFICE_BOX)) {
      final String line = context.getStringValue(identifier);
      if (line != null && !line.isBlank()) {
        streetLines.add(line);
      }
    }
    if (!streetLines.isEmpty()) {
      address.setStreetAddress(String.join("\n", streetLines));
    }
    if (address.toJSONObject().isEmpty()) {
      return List.of();
    }
    return List.of(UserClaim.of(PersonClaims.ADDRESS_CLAIM_NAME, address));
  }

  /**
   * Calls the supplied setter when the value is present.
   *
   * @param value the value
   * @param setter the setter to call
   */
  private static void setIfPresent(final String value, final java.util.function.Consumer<String> setter) {
    if (value != null && !value.isBlank()) {
      setter.accept(value);
    }
  }

}
