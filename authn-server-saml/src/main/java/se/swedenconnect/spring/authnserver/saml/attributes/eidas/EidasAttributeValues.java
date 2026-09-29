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
package se.swedenconnect.spring.authnserver.saml.attributes.eidas;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeUtils;
import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderTypeEnumeration;

/**
 * Helpers for building the typed values of eIDAS attributes.
 * <p>
 * Reading values goes through
 * {@link se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues#getStringValues(Attribute)}, which
 * handles every eIDAS value type and drops values that are not written in Latin script.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasAttributeValues {

  /**
   * Creates an eIDAS attribute holding the supplied values.
   *
   * @param template the eIDAS attribute to create
   * @param values the values
   * @return an {@link Attribute}, or {@code null} if no value could be built
   */
  public static @Nullable Attribute createAttribute(final @Nonnull EidasAttributeTemplate template,
      final @Nonnull List<? extends Serializable> values) {
    Objects.requireNonNull(template, "template must not be null");
    final Attribute attribute = AttributeUtils.createAttribute(template.name(), template.friendlyName());
    for (final Serializable value : values) {
      final XMLObject valueObject = createValue(template, value);
      if (valueObject != null) {
        AttributeUtils.addAttributeValue(attribute, valueObject);
      }
    }
    return !attribute.getAttributeValues().isEmpty() ? attribute : null;
  }

  /**
   * Creates the value object of an eIDAS attribute.
   *
   * @param template the eIDAS attribute
   * @param value the value
   * @return an {@link XMLObject}, or {@code null} if the value does not fit the type of the attribute
   */
  public static @Nullable XMLObject createValue(final @Nonnull EidasAttributeTemplate template,
      final @Nonnull Serializable value) {
    final XMLObject valueObject =
        AttributeUtils.createAttributeValueObject(template.valueTypeName(), template.valueType());

    switch (valueObject) {
      case final DateOfBirthType dateOfBirth -> {
        final LocalDate date = toLocalDate(value);
        if (date == null) {
          return null;
        }
        dateOfBirth.setDate(date);
      }
      case final GenderType gender -> {
        final GenderTypeEnumeration genderValue = toGender(String.valueOf(value));
        if (genderValue == null) {
          return null;
        }
        gender.setGender(genderValue);
      }
      case final XSString string -> string.setValue(String.valueOf(value));
      default -> {
        return null;
      }
    }
    return valueObject;
  }

  /**
   * Converts a generic gender value into the eIDAS form.
   *
   * @param value the generic value, one of {@code female}, {@code male} and {@code u}
   * @return a {@link GenderTypeEnumeration}, or {@code null} if the value is not a known gender
   */
  public static @Nullable GenderTypeEnumeration toGender(final @Nullable String value) {
    if (value == null) {
      return null;
    }
    return switch (value.toLowerCase()) {
      case "male" -> GenderTypeEnumeration.MALE;
      case "female" -> GenderTypeEnumeration.FEMALE;
      case "u" -> GenderTypeEnumeration.UNSPECIFIED;
      default -> null;
    };
  }

  /**
   * Converts an eIDAS gender value into the generic form.
   *
   * @param value the eIDAS value, one of {@code Male}, {@code Female} and {@code Unspecified}
   * @return the generic value, or {@code null} if the value is not a known gender
   */
  public static @Nullable String fromGender(final @Nullable String value) {
    if (value == null) {
      return null;
    }
    if (GenderTypeEnumeration.MALE.getValue().equalsIgnoreCase(value)) {
      return "male";
    }
    if (GenderTypeEnumeration.FEMALE.getValue().equalsIgnoreCase(value)) {
      return "female";
    }
    if (GenderTypeEnumeration.UNSPECIFIED.getValue().equalsIgnoreCase(value)) {
      return "u";
    }
    return null;
  }

  /**
   * Reads a value as a date.
   *
   * @param value the value, a {@link LocalDate} or a string on the form {@code YYYY-MM-DD}
   * @return a {@link LocalDate}, or {@code null} if the value is not a date
   */
  private static @Nullable LocalDate toLocalDate(final @Nonnull Serializable value) {
    if (value instanceof final LocalDate date) {
      return date;
    }
    try {
      return LocalDate.parse(String.valueOf(value));
    }
    catch (final java.time.format.DateTimeParseException e) {
      return null;
    }
  }

  // Hidden constructor
  private EidasAttributeValues() {
  }

}
