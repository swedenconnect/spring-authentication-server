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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.attributes.AttributeValues;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.ClaimDeliveryTarget;
import se.swedenconnect.spring.authnserver.oidc.attributes.RequestedClaim;

/**
 * Maps one requested claim into one or more generic requested attributes.
 * <p>
 * The delivery target of the claim is carried over as protocol data, see {@link ClaimDeliveryTarget}. A claim that is
 * requested both in the ID token and from the UserInfo endpoint carries both targets.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClaimFromProtocolMapper implements FromProtocolAttributeMapper<RequestedClaim> {

  /** The claim name that this mapper handles. */
  private final String claimName;

  /** The generic attribute identifiers that the claim maps to. */
  private final List<String> identifiers;

  /** Whether the values of the claims request are dropped rather than carried over. */
  private final boolean ignoreValues;

  /**
   * Constructor.
   *
   * @param claimName the claim name
   * @param identifiers the generic attribute identifiers that the claim maps to
   */
  public ClaimFromProtocolMapper(final @Nonnull String claimName, final @Nonnull String... identifiers) {
    this(claimName, false, identifiers);
  }

  /**
   * Constructor.
   *
   * @param claimName the claim name
   * @param ignoreValues whether to drop the values of the claims request rather than carrying them over, which is
   *     what a claim whose value is an object calls for
   * @param identifiers the generic attribute identifiers that the claim maps to
   */
  public ClaimFromProtocolMapper(final @Nonnull String claimName, final boolean ignoreValues,
      final @Nonnull String... identifiers) {
    this.claimName = Objects.requireNonNull(claimName, "claimName must not be null");
    this.ignoreValues = ignoreValues;
    this.identifiers = List.of(identifiers);
    if (this.identifiers.isEmpty()) {
      throw new IllegalArgumentException("At least one attribute identifier must be given");
    }
  }

  /**
   * Creates a mapper that drops the values of the claims request. Use it for a claim whose value is an object, such
   * as {@code address}, where the value of the request says nothing about the values of the parts.
   *
   * @param claimName the claim name
   * @param identifiers the generic attribute identifiers that the claim maps to
   * @return a {@link ClaimFromProtocolMapper}
   */
  public static @Nonnull ClaimFromProtocolMapper withoutValues(final @Nonnull String claimName,
      final @Nonnull String... identifiers) {
    return new ClaimFromProtocolMapper(claimName, true, identifiers);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Collection<String> getSupportedNames() {
    return List.of(this.claimName);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<GenericRequestedAttribute> map(final @Nonnull List<RequestedClaim> inputs,
      final @Nonnull FromProtocolMappingContext<RequestedClaim> context) {

    final boolean essential = inputs.stream().anyMatch(RequestedClaim::essential);
    final ClaimDeliveryTarget target = deliveryTarget(inputs);
    final List<String> values = new ArrayList<>();
    if (!this.ignoreValues) {
      for (final RequestedClaim input : inputs) {
        for (final String value : input.stringValues()) {
          if (!values.contains(value)) {
            values.add(value);
          }
        }
      }
    }
    final Map<String, Serializable> protocolData = new LinkedHashMap<>();
    protocolData.put(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, target);

    final List<GenericRequestedAttribute> result = new ArrayList<>(this.identifiers.size());
    for (final String identifier : this.identifiers) {
      final List<Serializable> typedValues = new ArrayList<>(values.size());
      for (final String value : values) {
        typedValues.add(AttributeValues.fromString(value, identifier, context.getDefinitions()));
      }
      result.add(new GenericRequestedAttribute(identifier, essential, typedValues, protocolData));
    }
    return result;
  }

  /**
   * Gets the delivery target to use, which is the target covering every target of the supplied requested claims.
   *
   * @param inputs the requested claims
   * @return a {@link ClaimDeliveryTarget}
   */
  static @Nonnull ClaimDeliveryTarget deliveryTarget(final @Nonnull List<RequestedClaim> inputs) {
    return inputs.stream()
        .map(RequestedClaim::target)
        .reduce(ClaimDeliveryTarget::combine)
        .orElse(ClaimDeliveryTarget.USER_INFO);
  }

  /**
   * Gets the generic attribute identifiers that this mapper produces.
   *
   * @return the attribute identifiers
   */
  public @Nonnull List<String> getIdentifiers() {
    return this.identifiers;
  }

}
