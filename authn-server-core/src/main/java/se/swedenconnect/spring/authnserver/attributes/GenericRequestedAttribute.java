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
package se.swedenconnect.spring.authnserver.attributes;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A requested attribute in its protocol-neutral form.
 * <p>
 * A requested attribute states that the requester wants an attribute to be part of the authentication result. It may
 * be essential, meaning "required" in SAML and "essential" in OpenID Connect, and it may carry the values that the
 * requester will accept.
 * </p>
 * <p>
 * Protocol data is data that only the protocol layer understands. The generic layer carries it along and never looks
 * at it. The delivery target of an OpenID Connect claim, ID token or UserInfo, is such data.
 * </p>
 *
 * @author Martin Lindström
 */
public class GenericRequestedAttribute implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The attribute identifier. */
  private final String identifier;

  /** Whether the requester requires the attribute. */
  private final boolean essential;

  /** The values that the requester will accept, or an empty list. */
  private final List<? extends Serializable> requestedValues;

  /** Protocol specific data. */
  private final Map<String, Serializable> protocolData;

  /**
   * Constructor.
   *
   * @param identifier the attribute identifier, see {@link AttributeIdentifiers}
   * @param essential whether the requester requires the attribute
   * @param requestedValues the values that the requester will accept, may be {@code null}
   * @param protocolData protocol specific data, may be {@code null}
   */
  public GenericRequestedAttribute(final @NonNull String identifier, final boolean essential,
      final @Nullable List<? extends Serializable> requestedValues,
      final @Nullable Map<String, Serializable> protocolData) {
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    this.essential = essential;
    this.requestedValues = requestedValues != null ? List.copyOf(requestedValues) : List.of();
    this.protocolData = protocolData != null
        ? Collections.unmodifiableMap(new LinkedHashMap<>(protocolData))
        : Map.of();
  }

  /**
   * Creates a requested attribute that is not essential and carries no values.
   *
   * @param identifier the attribute identifier
   * @return a {@link GenericRequestedAttribute}
   */
  public static @NonNull GenericRequestedAttribute of(final @NonNull String identifier) {
    return new GenericRequestedAttribute(identifier, false, null, null);
  }

  /**
   * Creates a requested attribute that carries no values.
   *
   * @param identifier the attribute identifier
   * @param essential whether the requester requires the attribute
   * @return a {@link GenericRequestedAttribute}
   */
  public static @NonNull GenericRequestedAttribute of(final @NonNull String identifier, final boolean essential) {
    return new GenericRequestedAttribute(identifier, essential, null, null);
  }

  /**
   * Gets the attribute identifier.
   *
   * @return the attribute identifier
   */
  public @NonNull String getIdentifier() {
    return this.identifier;
  }

  /**
   * Predicate telling whether the requester requires the attribute.
   *
   * @return {@code true} if the attribute is essential and {@code false} otherwise
   */
  public boolean isEssential() {
    return this.essential;
  }

  /**
   * Gets the values that the requester will accept. Usually empty.
   *
   * @return the requested values, or an empty list
   */
  public @NonNull List<? extends Serializable> getRequestedValues() {
    return this.requestedValues;
  }

  /**
   * Gets all protocol specific data.
   *
   * @return a map of protocol specific data, possibly empty
   */
  public @NonNull Map<String, Serializable> getProtocolData() {
    return this.protocolData;
  }

  /**
   * Gets a piece of protocol specific data.
   *
   * @param <T> the expected type
   * @param key the key under which the data was stored
   * @param type the expected type
   * @return the data, or {@code null} if it is missing or of another type
   */
  public <T extends Serializable> @Nullable T getProtocolData(final @NonNull String key, final @NonNull Class<T> type) {
    final Serializable value = this.protocolData.get(key);
    return type.isInstance(value) ? type.cast(value) : null;
  }

  /**
   * Creates a copy of this requested attribute where the essential flag is the logical or of this attribute's flag
   * and the supplied one, and where the protocol data of both attributes is merged.
   * <p>
   * Protocol data of the supplied attribute replaces the data of this attribute, key by key, unless the data
   * implements {@link MergeableProtocolData} and so decides the result for its key itself.
   * </p>
   *
   * @param other the requested attribute to merge with
   * @return a merged {@link GenericRequestedAttribute}
   */
  public @NonNull GenericRequestedAttribute merge(final @NonNull GenericRequestedAttribute other) {
    if (!this.identifier.equals(other.identifier)) {
      throw new IllegalArgumentException("Can not merge requested attributes with different identifiers");
    }
    final Map<String, Serializable> data = new LinkedHashMap<>(this.protocolData);
    for (final Map.Entry<String, Serializable> entry : other.protocolData.entrySet()) {
      data.merge(entry.getKey(), entry.getValue(), (existing, added) ->
          existing instanceof final MergeableProtocolData mergeable ? mergeable.mergeWith(added) : added);
    }
    final List<? extends Serializable> values =
        !this.requestedValues.isEmpty() ? this.requestedValues : other.requestedValues;
    return new GenericRequestedAttribute(
        this.identifier, this.essential || other.essential, values, data);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final GenericRequestedAttribute other)) {
      return false;
    }
    return this.essential == other.essential
        && Objects.equals(this.identifier, other.identifier)
        && Objects.equals(this.requestedValues, other.requestedValues)
        && Objects.equals(this.protocolData, other.protocolData);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.identifier, this.essential, this.requestedValues, this.protocolData);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(this.identifier);
    sb.append(", essential=").append(this.essential);
    if (!this.requestedValues.isEmpty()) {
      sb.append(", values=").append(this.requestedValues);
    }
    if (!this.protocolData.isEmpty()) {
      sb.append(", protocol-data=").append(this.protocolData);
    }
    return sb.toString();
  }

}
