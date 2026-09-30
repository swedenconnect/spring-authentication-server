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
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;

import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps the generic gender attribute into the {@code gender} claim.
 * <p>
 * OpenID Connect Core defines the values {@code female} and {@code male}, which is what the generic attribute uses.
 * The value {@code u}, which comes from the SAML value {@code U} for an unspecified gender, has no claim value and is
 * not released.
 * </p>
 *
 * @author Martin Lindström
 */
public class GenderToClaimMapper implements ToClaimMapper {

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(AttributeIdentifiers.GENDER);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getClaimNames(final @NonNull String identifier) {
    return AttributeIdentifiers.GENDER.equals(identifier) ? List.of(PersonClaims.GENDER_CLAIM_NAME) : List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<UserClaim> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {
    final String value = String.valueOf(attributes.get(0).getValue()).toLowerCase();
    if (!"female".equals(value) && !"male".equals(value)) {
      return List.of();
    }
    return List.of(UserClaim.of(PersonClaims.GENDER_CLAIM_NAME, value));
  }

}
