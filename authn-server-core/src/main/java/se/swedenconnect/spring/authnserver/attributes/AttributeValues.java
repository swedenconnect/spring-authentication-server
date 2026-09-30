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

import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Conversion of attribute values between their string form and the Java type that an {@link AttributeDefinition}
 * declares.
 *
 * @author Martin Lindström
 */
public class AttributeValues {

  /**
   * Converts a value given as a string into the supplied type.
   * <p>
   * A date is read as {@code YYYY-MM-DD} and an instant as either seconds since epoch or an ISO-8601 timestamp. A
   * value that can not be converted is returned as the string it was.
   * </p>
   *
   * @param value the value to convert
   * @param type the type to convert it to
   * @return the converted value
   */
  public static @NonNull Serializable fromString(final @NonNull String value,
      final @Nullable Class<? extends Serializable> type) {
    if (type == null || type == String.class) {
      return value;
    }
    try {
      if (type == LocalDate.class) {
        return LocalDate.parse(value);
      }
      if (type == Instant.class) {
        try {
          return Instant.ofEpochSecond(Long.parseLong(value.trim()));
        }
        catch (final NumberFormatException e) {
          return Instant.parse(value);
        }
      }
      if (type == Boolean.class) {
        return Boolean.valueOf(value);
      }
      if (type == Integer.class) {
        return Integer.valueOf(value.trim());
      }
      if (type == Long.class) {
        return Long.valueOf(value.trim());
      }
    }
    catch (final DateTimeParseException | NumberFormatException e) {
      return value;
    }
    return value;
  }

  /**
   * Converts a value given as a string into the type that the definition for the supplied attribute identifier
   * declares. A value for an attribute that has no definition is returned as the string it was.
   *
   * @param value the value to convert
   * @param identifier the attribute identifier
   * @param definitions the attribute definitions
   * @return the converted value
   */
  public static @NonNull Serializable fromString(final @NonNull String value, final @NonNull String identifier,
      final @NonNull AttributeDefinitionRegistry definitions) {
    final AttributeDefinition definition = definitions.getDefinition(identifier);
    return fromString(value, definition != null ? definition.valueType() : null);
  }

  // Hidden constructor
  private AttributeValues() {
  }

}
