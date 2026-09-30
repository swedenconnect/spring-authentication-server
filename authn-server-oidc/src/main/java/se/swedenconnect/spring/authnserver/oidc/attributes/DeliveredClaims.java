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
package se.swedenconnect.spring.authnserver.oidc.attributes;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import net.minidev.json.JSONObject;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * The identity claims released for a request, split into those delivered in the ID token and those delivered from
 * the UserInfo endpoint.
 * <p>
 * Where a claim goes follows Section 4.2 of the Swedish OpenID Connect Profile, as the delivery target of the
 * requested attribute that it comes from says, see {@link ClaimDeliveryTarget}. A claim that more than one requested
 * attribute gives is delivered where any of them says. A claim that no requested attribute gives is not delivered at
 * all, since the profile forbids releasing identity claims that were not requested.
 * </p>
 *
 * @param idToken the claims for the ID token
 * @param userInfo the claims for the UserInfo endpoint
 * @author Martin Lindström
 */
public record DeliveredClaims(@NonNull JSONObject idToken, @NonNull JSONObject userInfo) {

  /**
   * Constructor.
   *
   * @param idToken the claims for the ID token
   * @param userInfo the claims for the UserInfo endpoint
   */
  public DeliveredClaims {
    Objects.requireNonNull(idToken, "idToken must not be null");
    Objects.requireNonNull(userInfo, "userInfo must not be null");
  }

  /**
   * Maps released attributes to claims and splits them by delivery target.
   *
   * @param released the released attributes
   * @param requested the requested attributes of the request, carrying the delivery targets
   * @param mapping the mapping between attributes and claims
   * @return the delivered claims
   */
  public static @NonNull DeliveredClaims of(final @NonNull List<GenericAttribute<? extends Serializable>> released,
      final @NonNull List<GenericRequestedAttribute> requested, final @NonNull OidcAttributeMapping mapping) {

    final JSONObject idToken = new JSONObject();
    final JSONObject userInfo = new JSONObject();
    for (final UserClaim claim : mapping.toClaims(released, requested)) {
      final ClaimDeliveryTarget target = getTarget(claim.name(), requested, mapping);
      if (target == null) {
        continue;
      }
      final Object value =
          claim.value() instanceof final ClaimsSet claimsSet ? claimsSet.toJSONObject() : claim.value();
      if (target.isIdToken()) {
        idToken.put(claim.name(), value);
      }
      if (target.isUserInfo()) {
        userInfo.put(claim.name(), value);
      }
    }
    return new DeliveredClaims(idToken, userInfo);
  }

  /**
   * Parses a JSON string holding claims, as stored.
   *
   * @param json the JSON string
   * @return the claims
   * @throws IllegalArgumentException for invalid JSON
   */
  public static @NonNull JSONObject parse(final @NonNull String json) {
    try {
      return new JSONObject(JSONObjectUtils.parse(json));
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException e) {
      throw new IllegalArgumentException("Invalid claims JSON", e);
    }
  }

  /**
   * Gets the combined delivery target of the requested attributes that give a claim.
   *
   * @param claimName the claim name
   * @param requested the requested attributes
   * @param mapping the mapping
   * @return the target, or {@code null} if no requested attribute gives the claim
   */
  private static @Nullable ClaimDeliveryTarget getTarget(final @NonNull String claimName,
      final @NonNull List<GenericRequestedAttribute> requested, final @NonNull OidcAttributeMapping mapping) {
    ClaimDeliveryTarget target = null;
    for (final GenericRequestedAttribute attribute : requested) {
      if (!mapping.getClaimNames(List.of(attribute.getIdentifier())).contains(claimName)) {
        continue;
      }
      final ClaimDeliveryTarget attributeTarget = Objects.requireNonNullElse(
          attribute.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class),
          ClaimDeliveryTarget.USER_INFO);
      target = target == null ? attributeTarget : target.combine(attributeTarget);
    }
    return target;
  }

}
