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

import jakarta.annotation.Nonnull;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import net.minidev.json.JSONObject;

/**
 * A claim about the user, given as the claim name and its value.
 * <p>
 * The value is of a type that Nimbus writes as JSON, so a {@link String}, a {@link Number}, a {@link Boolean}, a
 * {@link java.util.List} or a {@link JSONObject}. Claims that are objects, such as {@code address}, use the Nimbus
 * types, see {@link com.nimbusds.openid.connect.sdk.claims.Address}.
 * </p>
 *
 * @param name the claim name
 * @param value the claim value
 * @author Martin Lindström
 */
public record UserClaim(@Nonnull String name, @Nonnull Object value) {

  /**
   * Constructor.
   *
   * @param name the claim name
   * @param value the claim value
   */
  public UserClaim {
    Objects.requireNonNull(name, "name must not be null");
    Objects.requireNonNull(value, "value must not be null");
  }

  /**
   * Creates a claim.
   *
   * @param name the claim name
   * @param value the claim value
   * @return a {@link UserClaim}
   */
  public static @Nonnull UserClaim of(final @Nonnull String name, final @Nonnull Object value) {
    return new UserClaim(name, value);
  }

  /**
   * Merges two claims having the same name.
   * <p>
   * When both values are JSON objects their members are merged, and a member that the first claim already holds is
   * kept. Otherwise the first claim wins.
   * </p>
   *
   * @param first the first claim
   * @param second the second claim
   * @return the merged claim
   */
  public static @Nonnull UserClaim merge(final @Nonnull UserClaim first, final @Nonnull UserClaim second) {
    final JSONObject firstObject = toJsonObject(first.value());
    final JSONObject secondObject = toJsonObject(second.value());
    if (firstObject == null || secondObject == null) {
      return first;
    }
    final Map<String, Object> merged = new LinkedHashMap<>(secondObject);
    merged.putAll(firstObject);
    return new UserClaim(first.name(), new JSONObject(merged));
  }

  /**
   * Gets the claim value as a JSON object.
   *
   * @param value the value
   * @return a {@link JSONObject}, or {@code null} if the value is not an object
   */
  private static JSONObject toJsonObject(final @Nonnull Object value) {
    if (value instanceof final JSONObject jsonObject) {
      return jsonObject;
    }
    if (value instanceof final ClaimsSet claimsSet) {
      return claimsSet.toJSONObject();
    }
    return null;
  }

  /**
   * Puts this claim into the supplied Nimbus claims set.
   *
   * @param claimsSet the claims set to add to
   */
  public void addTo(final @Nonnull ClaimsSet claimsSet) {
    claimsSet.setClaim(this.name, this.value);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s=%s".formatted(this.name, this.value);
  }

}
