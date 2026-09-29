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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import net.minidev.json.JSONObject;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps the generic place of birth attributes into the {@code place_of_birth} claim of OpenID Connect for Identity
 * Assurance, which has the fields {@code country}, {@code region} and {@code locality}.
 * <p>
 * When the only thing known is the free text place of birth it is sent as {@code locality}.
 * </p>
 *
 * @author Martin Lindström
 */
public class PlaceOfBirthToClaimMapper implements ToProtocolAttributeMapper<UserClaim> {

  /** The {@code country} field of the claim. */
  public static final String COUNTRY_FIELD = "country";

  /** The {@code region} field of the claim. */
  public static final String REGION_FIELD = "region";

  /** The {@code locality} field of the claim. */
  public static final String LOCALITY_FIELD = "locality";

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.PLACE_OF_BIRTH, AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY,
        AttributeIdentifiers.PLACE_OF_BIRTH_REGION, AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<UserClaim> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context) {

    final Map<String, Object> fields = new LinkedHashMap<>();
    put(fields, COUNTRY_FIELD, context.getStringValue(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY));
    put(fields, REGION_FIELD, context.getStringValue(AttributeIdentifiers.PLACE_OF_BIRTH_REGION));

    String locality = context.getStringValue(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY);
    if (locality == null && fields.isEmpty()) {
      locality = context.getStringValue(AttributeIdentifiers.PLACE_OF_BIRTH);
    }
    put(fields, LOCALITY_FIELD, locality);

    if (fields.isEmpty()) {
      return List.of();
    }
    return List.of(UserClaim.of(PersonClaims.PLACE_OF_BIRTH_CLAIM_NAME, new JSONObject(fields)));
  }

  /**
   * Adds a field when the value is present.
   *
   * @param fields the fields of the claim
   * @param field the field name
   * @param value the value
   */
  private static void put(final @Nonnull Map<String, Object> fields, final @Nonnull String field,
      final String value) {
    if (value != null && !value.isBlank()) {
      fields.put(field, value);
    }
  }

}
