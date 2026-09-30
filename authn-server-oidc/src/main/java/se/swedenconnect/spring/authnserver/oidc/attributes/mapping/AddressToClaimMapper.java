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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps the generic address attributes into the OpenID Connect {@code address} claim.
 * <p>
 * The street address and the post office box both go into {@code street_address}, which OpenID Connect Core allows to
 * hold several lines. When both are present they are written on a line each, the street address first.
 * </p>
 * <p>
 * The parts of the eIDAS address are released here too, as the OpenID Connect Claims and Scopes Specification for
 * Sweden Connect, Appendix A, maps the eIDAS {@code CurrentAddress} to the {@code address} claim. When a generic
 * address attribute and an eIDAS part would fill the same field of the claim, the generic attribute wins. The two sets
 * are never mixed within one field.
 * </p>
 *
 * @author Martin Lindström
 */
public class AddressToClaimMapper implements ToClaimMapper {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.FORMATTED_ADDRESS, AttributeIdentifiers.STREET_ADDRESS,
        AttributeIdentifiers.POST_OFFICE_BOX, AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.LOCALITY,
        AttributeIdentifiers.REGION, AttributeIdentifiers.COUNTRY,
        AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX, AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR,
        AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME, AttributeIdentifiers.EIDAS_ADDRESS_AREA,
        AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME,
        AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE,
        AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE, AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getClaimNames(final @NonNull String identifier) {
    return this.getSupportedIdentifiers().contains(identifier) ? List.of(PersonClaims.ADDRESS_CLAIM_NAME) : List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<UserClaim> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {

    final Address address = new Address();
    setIfPresent(context.getStringValue(AttributeIdentifiers.FORMATTED_ADDRESS), address::setFormatted);
    setIfPresent(first(context, AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE),
        address::setPostalCode);
    setIfPresent(first(context, AttributeIdentifiers.LOCALITY, AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME),
        address::setLocality);
    setIfPresent(
        first(context, AttributeIdentifiers.REGION, AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE),
        address::setRegion);
    setIfPresent(
        first(context, AttributeIdentifiers.COUNTRY, AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE),
        address::setCountry);

    final List<String> streetLines = genericStreetLines(context);
    if (streetLines.isEmpty()) {
      streetLines.addAll(eidasStreetLines(context));
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
   * Gets the lines of {@code street_address} that the generic address attributes give: the street address and the post
   * office box, in that order.
   *
   * @param context the mapping context
   * @return the lines, possibly empty
   */
  private static @NonNull List<String> genericStreetLines(final @NonNull ToProtocolMappingContext context) {
    final List<String> lines = new ArrayList<>();
    addIfPresent(lines, context.getStringValue(AttributeIdentifiers.STREET_ADDRESS));
    addIfPresent(lines, context.getStringValue(AttributeIdentifiers.POST_OFFICE_BOX));
    return lines;
  }

  /**
   * Gets the lines of {@code street_address} that the parts of the eIDAS address give: the locator name, the
   * thoroughfare with its locator designator, the address area and the post office box, in that order.
   *
   * @param context the mapping context
   * @return the lines, possibly empty
   */
  private static @NonNull List<String> eidasStreetLines(final @NonNull ToProtocolMappingContext context) {
    final List<String> lines = new ArrayList<>();
    addIfPresent(lines, context.getStringValue(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME));

    final String thoroughfare = context.getStringValue(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE);
    final String locatorDesignator = context.getStringValue(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR);
    if (hasText(thoroughfare) && hasText(locatorDesignator)) {
      lines.add(thoroughfare + " " + locatorDesignator);
    }
    else {
      addIfPresent(lines, thoroughfare);
      addIfPresent(lines, locatorDesignator);
    }

    addIfPresent(lines, context.getStringValue(AttributeIdentifiers.EIDAS_ADDRESS_AREA));
    addIfPresent(lines, context.getStringValue(AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX));
    return lines;
  }

  /**
   * Gets the value of the first of the supplied attributes that is present. The generic address attributes are given
   * before their eIDAS counterparts, so that they take precedence.
   *
   * @param context the mapping context
   * @param identifiers the attribute identifiers, in order of precedence
   * @return the value, or {@code null} if none of the attributes is present
   */
  private static @Nullable String first(final @NonNull ToProtocolMappingContext context,
      final @NonNull String... identifiers) {
    for (final String identifier : identifiers) {
      final String value = context.getStringValue(identifier);
      if (hasText(value)) {
        return value;
      }
    }
    return null;
  }

  /**
   * Adds the value to the list of lines when it is present.
   *
   * @param lines the lines
   * @param value the value
   */
  private static void addIfPresent(final @NonNull List<String> lines, final @Nullable String value) {
    if (hasText(value)) {
      lines.add(value);
    }
  }

  /**
   * Calls the supplied setter when the value is present.
   *
   * @param value the value
   * @param setter the setter to call
   */
  private static void setIfPresent(final @Nullable String value, final @NonNull Consumer<String> setter) {
    if (hasText(value)) {
      setter.accept(value);
    }
  }

  /**
   * Predicate telling whether the value holds anything.
   *
   * @param value the value
   * @return {@code true} if the value holds anything and {@code false} otherwise
   */
  private static boolean hasText(final @Nullable String value) {
    return value != null && !value.isBlank();
  }

}
