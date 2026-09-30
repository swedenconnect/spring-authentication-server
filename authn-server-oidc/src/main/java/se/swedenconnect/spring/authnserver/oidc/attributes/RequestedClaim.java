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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;

/**
 * A requested claim as it appears in OpenID Connect, given as the Nimbus {@link ClaimsSetRequest.Entry} together with
 * the section of the claims request parameter it was found in.
 *
 * @param entry the Nimbus claims request entry
 * @param target where the claim is to be delivered
 * @author Martin Lindström
 */
public record RequestedClaim(ClaimsSetRequest.@NonNull Entry entry, @NonNull ClaimDeliveryTarget target) {

  /**
   * Constructor.
   *
   * @param entry the Nimbus claims request entry
   * @param target where the claim is to be delivered
   */
  public RequestedClaim {
    Objects.requireNonNull(entry, "entry must not be null");
    Objects.requireNonNull(target, "target must not be null");
  }

  /**
   * Creates a requested claim for delivery from the UserInfo endpoint.
   *
   * @param claimName the claim name
   * @return a {@link RequestedClaim}
   */
  public static @NonNull RequestedClaim of(final @NonNull String claimName) {
    return new RequestedClaim(new ClaimsSetRequest.Entry(claimName), ClaimDeliveryTarget.USER_INFO);
  }

  /**
   * Gets the claim name.
   *
   * @return the claim name
   */
  public @NonNull String name() {
    return this.entry.getClaimName();
  }

  /**
   * Predicate telling whether the requester marked the claim as essential.
   *
   * @return {@code true} if the claim is essential and {@code false} otherwise
   */
  public boolean essential() {
    return ClaimRequirement.ESSENTIAL == this.entry.getClaimRequirement();
  }

  /**
   * Gets the values that the requester will accept, taken from the {@code value} and {@code values} members of the
   * claims request.
   *
   * @return the values in string form, possibly empty
   */
  public @NonNull List<String> stringValues() {
    final List<String> values = new ArrayList<>();
    final String value = asString(this.entry.getRawValue());
    if (value != null) {
      values.add(value);
    }
    final List<?> rawValues = this.entry.getValuesAsRawList();
    if (rawValues != null) {
      for (final Object rawValue : rawValues) {
        final String stringValue = asString(rawValue);
        if (stringValue != null && !values.contains(stringValue)) {
          values.add(stringValue);
        }
      }
    }
    return values;
  }

  /**
   * Converts a raw claims request value into a string.
   *
   * @param value the raw value
   * @return the value in string form, or {@code null} if there is no value
   */
  private static @Nullable String asString(final @Nullable Object value) {
    return value != null ? String.valueOf(value) : null;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s, essential=%s, target=%s".formatted(this.name(), this.essential(), this.target);
  }

}
