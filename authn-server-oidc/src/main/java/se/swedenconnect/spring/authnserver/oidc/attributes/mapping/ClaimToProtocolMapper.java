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
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * Maps one generic attribute into one claim.
 * <p>
 * A claim that holds a single value takes the first value of the attribute. A claim that holds an array takes them
 * all. Dates are written as {@code YYYY-MM-DD} and instants as seconds since epoch, which is what the claim
 * definitions call for.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClaimToProtocolMapper implements ToClaimMapper {

  /** The date formatter used for date values. */
  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

  /** The generic attribute identifier that this mapper handles. */
  private final String identifier;

  /** The claim name to produce. */
  private final String claimName;

  /** Whether the claim holds an array of values. */
  private final boolean array;

  /**
   * Constructor for a claim holding a single value.
   *
   * @param identifier the generic attribute identifier
   * @param claimName the claim name
   */
  public ClaimToProtocolMapper(final @NonNull String identifier, final @NonNull String claimName) {
    this(identifier, claimName, false);
  }

  /**
   * Constructor.
   *
   * @param identifier the generic attribute identifier
   * @param claimName the claim name
   * @param array whether the claim holds an array of values
   */
  public ClaimToProtocolMapper(final @NonNull String identifier, final @NonNull String claimName,
      final boolean array) {
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    this.claimName = Objects.requireNonNull(claimName, "claimName must not be null");
    this.array = array;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getSupportedIdentifiers() {
    return List.of(this.identifier);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<String> getClaimNames(final @NonNull String identifier) {
    return this.identifier.equals(identifier) ? List.of(this.claimName) : List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<UserClaim> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @NonNull ToProtocolMappingContext context) {
    final GenericAttribute<? extends Serializable> attribute = attributes.get(0);
    if (this.array) {
      final List<Object> values = new ArrayList<>();
      attribute.getValues().forEach(v -> values.add(toClaimValue(v)));
      return List.of(UserClaim.of(this.claimName, values));
    }
    return List.of(UserClaim.of(this.claimName, toClaimValue(attribute.getValue())));
  }

  /**
   * Converts a generic attribute value into the form used in claims.
   *
   * @param value the value to convert
   * @return the claim value
   */
  public static @NonNull Object toClaimValue(final @NonNull Serializable value) {
    if (value instanceof final LocalDate date) {
      return DATE_FORMATTER.format(date);
    }
    if (value instanceof final Instant instant) {
      return instant.getEpochSecond();
    }
    if (value instanceof Boolean || value instanceof Number) {
      return value;
    }
    return String.valueOf(value);
  }

}
