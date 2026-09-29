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
package se.swedenconnect.spring.authnserver.saml.attributes;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.eidas.ext.attributes.EidasAttributeValueType;
import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;

/**
 * Helpers for reading values from, and building, OpenSAML {@link Attribute} objects.
 *
 * @author Martin Lindström
 */
public class SamlAttributeValues {

  /** The date formatter used for date values. */
  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

  /**
   * Gets the values of the supplied attribute in string form.
   *
   * @param attribute the attribute
   * @return the values in string form, possibly empty
   */
  public static @Nonnull List<String> getStringValues(final @Nullable Attribute attribute) {
    if (attribute == null) {
      return List.of();
    }
    final List<String> values = new ArrayList<>();
    for (final XMLObject value : attribute.getAttributeValues()) {
      final String stringValue = toStringValue(value);
      if (stringValue != null) {
        values.add(stringValue);
      }
    }
    return values;
  }

  /**
   * Converts an OpenSAML attribute value into a string.
   * <p>
   * An eIDAS value that uses transliteration and states that it is not written in Latin script is dropped, as
   * Section 3.3.3 of the Attribute Specification for the Swedish eID Framework requires.
   * </p>
   *
   * @param value the value
   * @return the value in string form, or {@code null} if the value is dropped or can not be represented as a string
   */
  private static @Nullable String toStringValue(final @Nullable XMLObject value) {
    return switch (value) {
      case null -> null;
      case final TransliterationStringType transliteration ->
          Boolean.FALSE.equals(transliteration.getLatinScript()) ? null : transliteration.toStringValue();
      case final EidasAttributeValueType eidas -> eidas.toStringValue();
      case final XSString s -> s.getValue();
      case final XSBoolean b -> {
        final XSBooleanValue v = b.getValue();
        yield v != null ? String.valueOf(v.getValue()) : null;
      }
      case final XSInteger i -> i.getValue() != null ? String.valueOf(i.getValue()) : null;
      case final XSDateTime d -> d.getValue() != null ? d.getValue().toString() : null;
      case final XSBase64Binary b -> b.getValue();
      case final XSAny a -> a.getTextContent();
      default -> value.getDOM() != null ? value.getDOM().getTextContent() : null;
    };
  }

  /**
   * Converts a generic attribute value into the string form used in SAML attributes. Dates are written as
   * {@code YYYY-MM-DD} and instants in ISO-8601 form.
   *
   * @param value the value to convert
   * @return the value in string form
   */
  public static @Nonnull String toSamlStringValue(final @Nonnull Serializable value) {
    Objects.requireNonNull(value, "value must not be null");
    if (value instanceof final LocalDate date) {
      return DATE_FORMATTER.format(date);
    }
    if (value instanceof final Instant instant) {
      return instant.toString();
    }
    return String.valueOf(value);
  }

  /**
   * Creates an OpenSAML {@link Attribute}.
   *
   * @param name the attribute name
   * @param friendlyName the attribute friendly name, may be {@code null}
   * @param values the attribute values
   * @return an {@link Attribute}
   */
  public static @Nonnull Attribute createAttribute(final @Nonnull String name, final @Nullable String friendlyName,
      final @Nonnull List<String> values) {
    final AttributeBuilder builder = AttributeBuilder.builder(name)
        .friendlyName(friendlyName)
        .nameFormat(Attribute.URI_REFERENCE);
    if (!values.isEmpty()) {
      builder.value(values);
    }
    return builder.build();
  }

  /**
   * Merges two attributes having the same name by appending the values of the second attribute that the first one
   * does not already hold.
   *
   * @param first the first attribute
   * @param second the second attribute
   * @return an {@link Attribute} holding the values of both
   */
  public static @Nonnull Attribute merge(final @Nonnull Attribute first, final @Nonnull Attribute second) {
    final List<String> values = new ArrayList<>(getStringValues(first));
    for (final String value : getStringValues(second)) {
      if (!values.contains(value)) {
        values.add(value);
      }
    }
    final String friendlyName = first.getFriendlyName() != null ? first.getFriendlyName() : second.getFriendlyName();
    return createAttribute(first.getName(), friendlyName, values);
  }

  // Hidden constructor
  private SamlAttributeValues() {
  }

}
