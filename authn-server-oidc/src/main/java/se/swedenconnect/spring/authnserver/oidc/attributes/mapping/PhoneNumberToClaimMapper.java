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

import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps the generic telephone number and mobile number attributes into the {@code phone_number} and {@code msisdn}
 * claims.
 * <p>
 * The {@code phone_number} claim holds one value, and it is the first mobile number, or, when no mobile number is
 * known, the first telephone number. The {@code msisdn} claim holds the first mobile number.
 * </p>
 *
 * @author Martin Lindström
 */
public class PhoneNumberToClaimMapper implements ToProtocolAttributeMapper<UserClaim> {

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.TELEPHONE_NUMBER, AttributeIdentifiers.MOBILE_NUMBER);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<UserClaim> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context) {

    final String mobile = context.getStringValue(AttributeIdentifiers.MOBILE_NUMBER);
    final String telephone = context.getStringValue(AttributeIdentifiers.TELEPHONE_NUMBER);

    final List<UserClaim> claims = new ArrayList<>();
    final String phoneNumber = mobile != null ? mobile : telephone;
    if (phoneNumber != null) {
      claims.add(UserClaim.of(PersonClaims.PHONE_NUMBER_CLAIM_NAME, phoneNumber));
    }
    if (mobile != null) {
      claims.add(UserClaim.of(PersonClaims.MSISDN_CLAIM_NAME, mobile));
    }
    return claims;
  }

}
