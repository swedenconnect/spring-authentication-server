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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A user attribute in its protocol-neutral form. The attribute has an identifier, see {@link AttributeIdentifiers},
 * and one or more values of the same Java type.
 * <p>
 * Values are {@link Serializable} since the authentication result is stored in the user session.
 * </p>
 *
 * @param <T> the type of the attribute values
 * @author Martin Lindström
 */
public class GenericAttribute<T extends Serializable> implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The attribute identifier. */
  private final String identifier;

  /** The attribute values. */
  private final List<T> values;

  /**
   * Constructor.
   *
   * @param identifier the attribute identifier, see {@link AttributeIdentifiers}
   * @param values the attribute values
   */
  public GenericAttribute(final @NonNull String identifier, final @NonNull List<T> values) {
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    Objects.requireNonNull(values, "values must not be null");
    if (values.isEmpty()) {
      throw new IllegalArgumentException("values must not be empty");
    }
    if (values.stream().anyMatch(Objects::isNull)) {
      throw new IllegalArgumentException("values must not contain null elements");
    }
    this.values = List.copyOf(values);
  }

  /**
   * Creates an attribute holding a single value.
   *
   * @param <T> the type of the attribute value
   * @param identifier the attribute identifier
   * @param value the attribute value
   * @return a {@link GenericAttribute}
   */
  public static <T extends Serializable> @NonNull GenericAttribute<T> of(
      final @NonNull String identifier, final @NonNull T value) {
    return new GenericAttribute<>(identifier, List.of(value));
  }

  /**
   * Creates an attribute holding the supplied values.
   *
   * @param <T> the type of the attribute values
   * @param identifier the attribute identifier
   * @param values the attribute values
   * @return a {@link GenericAttribute}
   */
  public static <T extends Serializable> @NonNull GenericAttribute<T> of(
      final @NonNull String identifier, final @NonNull List<T> values) {
    return new GenericAttribute<>(identifier, values);
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
   * Gets the attribute values. The list is never empty.
   *
   * @return the attribute values
   */
  public @NonNull List<T> getValues() {
    return this.values;
  }

  /**
   * Gets the first attribute value.
   *
   * @return the first attribute value
   */
  public @NonNull T getValue() {
    return this.values.get(0);
  }

  /**
   * Gets the attribute values as strings.
   *
   * @return the attribute values in string form
   */
  public @NonNull List<String> getStringValues() {
    final List<String> stringValues = new ArrayList<>(this.values.size());
    for (final T value : this.values) {
      stringValues.add(String.valueOf(value));
    }
    return stringValues;
  }

  /**
   * Gets the first attribute value provided that it is of the supplied type.
   *
   * @param <V> the requested type
   * @param type the requested type
   * @return the value, or {@code null} if the first value is not of the supplied type
   */
  public <V extends Serializable> @Nullable V getValue(final @NonNull Class<V> type) {
    final T value = this.getValue();
    return type.isInstance(value) ? type.cast(value) : null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final GenericAttribute<?> other)) {
      return false;
    }
    return Objects.equals(this.identifier, other.identifier) && Objects.equals(this.values, other.values);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.identifier, this.values);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.values.size() == 1
        ? "%s=%s".formatted(this.identifier, this.values.get(0))
        : "%s=%s".formatted(this.identifier, this.values);
  }

}
