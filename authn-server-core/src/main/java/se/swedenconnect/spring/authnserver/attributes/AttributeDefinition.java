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

import jakarta.annotation.Nonnull;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A description of a generic attribute that the library, or the application, knows about.
 *
 * @param identifier the attribute identifier, see {@link AttributeIdentifiers}
 * @param valueType the Java type of the attribute values
 * @param multiValued whether the attribute may hold more than one value
 * @param description a short description of the attribute
 * @author Martin Lindström
 */
public record AttributeDefinition(@Nonnull String identifier, @Nonnull Class<? extends Serializable> valueType,
    boolean multiValued, @Nonnull String description) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param identifier the attribute identifier, see {@link AttributeIdentifiers}
   * @param valueType the Java type of the attribute values
   * @param multiValued whether the attribute may hold more than one value
   * @param description a short description of the attribute
   */
  public AttributeDefinition {
    Objects.requireNonNull(identifier, "identifier must not be null");
    Objects.requireNonNull(valueType, "valueType must not be null");
    Objects.requireNonNull(description, "description must not be null");
  }

  /**
   * Creates a definition for a single-valued attribute holding string values.
   *
   * @param identifier the attribute identifier
   * @param description a short description of the attribute
   * @return an {@link AttributeDefinition}
   */
  public static @Nonnull AttributeDefinition ofString(final @Nonnull String identifier,
      final @Nonnull String description) {
    return new AttributeDefinition(identifier, String.class, false, description);
  }

  /**
   * Tells whether the supplied value is of the type that this definition declares.
   *
   * @param value the value to check
   * @return {@code true} if the value matches the declared value type and {@code false} otherwise
   */
  public boolean isValidValue(final @Nonnull Serializable value) {
    return this.valueType.isInstance(value);
  }

}
