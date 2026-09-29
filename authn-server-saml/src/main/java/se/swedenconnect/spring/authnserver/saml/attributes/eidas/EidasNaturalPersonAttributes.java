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

import java.util.List;

import org.opensaml.core.xml.schema.XSString;

import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants;
import se.swedenconnect.opensaml.eidas.ext.attributes.BirthNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CountryOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CountryOfResidenceType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentFamilyNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentGivenNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.NationalityType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PersonIdentifierType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PlaceOfBirthType;

/**
 * The eIDAS attributes for natural persons, as defined in Section 2.2 of the eIDAS SAML Attribute Profile.
 * <p>
 * The attributes for legal persons, for representatives and for eJustice are not supported.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasNaturalPersonAttributes {

  /** {@code PersonIdentifier} - the eIDAS uniqueness identifier of the person. */
  public static final EidasAttributeTemplate PERSON_IDENTIFIER = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME,
      PersonIdentifierType.TYPE_NAME, PersonIdentifierType.class);

  /** {@code CurrentFamilyName} - the current family name of the person. */
  public static final EidasAttributeTemplate CURRENT_FAMILY_NAME = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME,
      CurrentFamilyNameType.TYPE_NAME, CurrentFamilyNameType.class);

  /** {@code CurrentGivenName} - the current given name of the person. */
  public static final EidasAttributeTemplate CURRENT_GIVEN_NAME = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME,
      CurrentGivenNameType.TYPE_NAME, CurrentGivenNameType.class);

  /** {@code DateOfBirth} - the date of birth of the person. */
  public static final EidasAttributeTemplate DATE_OF_BIRTH = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
      DateOfBirthType.TYPE_NAME, DateOfBirthType.class);

  /** {@code BirthName} - the name of the person at the time of birth. */
  public static final EidasAttributeTemplate BIRTH_NAME = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME,
      BirthNameType.TYPE_NAME, BirthNameType.class);

  /** {@code PlaceOfBirth} - the place of birth of the person. */
  public static final EidasAttributeTemplate PLACE_OF_BIRTH = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
      PlaceOfBirthType.TYPE_NAME, PlaceOfBirthType.class);

  /** {@code CountryOfBirth} - the country of birth of the person. */
  public static final EidasAttributeTemplate COUNTRY_OF_BIRTH = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
      CountryOfBirthType.TYPE_NAME, CountryOfBirthType.class);

  /** {@code TownOfBirth} - the town of birth of the person. */
  public static final EidasAttributeTemplate TOWN_OF_BIRTH = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
      XSString.TYPE_NAME, XSString.class);

  /** {@code CurrentAddress} - the current address of the person. */
  public static final EidasAttributeTemplate CURRENT_ADDRESS = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME,
      CurrentAddressType.TYPE_NAME, CurrentAddressType.class);

  /** {@code Gender} - the gender of the person. */
  public static final EidasAttributeTemplate GENDER = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_GENDER_ATTRIBUTE_FRIENDLY_NAME,
      GenderType.TYPE_NAME, GenderType.class);

  /** {@code Nationality} - a nationality of the person. */
  public static final EidasAttributeTemplate NATIONALITY = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_FRIENDLY_NAME,
      NationalityType.TYPE_NAME, NationalityType.class);

  /** {@code CountryOfResidence} - the country of residence of the person. */
  public static final EidasAttributeTemplate COUNTRY_OF_RESIDENCE = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_FRIENDLY_NAME,
      CountryOfResidenceType.TYPE_NAME, CountryOfResidenceType.class);

  /** {@code PhoneNumber} - a telephone number of the person. */
  public static final EidasAttributeTemplate PHONE_NUMBER = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_PHONE_NUMBER_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_PHONE_NUMBER_ATTRIBUTE_FRIENDLY_NAME,
      XSString.TYPE_NAME, XSString.class);

  /** {@code EmailAddress} - an e-mail address of the person. */
  public static final EidasAttributeTemplate EMAIL_ADDRESS = new EidasAttributeTemplate(
      AttributeConstants.EIDAS_EMAIL_ADDRESS_ATTRIBUTE_NAME,
      AttributeConstants.EIDAS_EMAIL_ADDRESS_ATTRIBUTE_FRIENDLY_NAME,
      XSString.TYPE_NAME, XSString.class);

  /** All eIDAS natural person attributes. */
  private static final List<EidasAttributeTemplate> ALL = List.of(
      PERSON_IDENTIFIER, CURRENT_FAMILY_NAME, CURRENT_GIVEN_NAME, DATE_OF_BIRTH, BIRTH_NAME, PLACE_OF_BIRTH,
      COUNTRY_OF_BIRTH, TOWN_OF_BIRTH, CURRENT_ADDRESS, GENDER, NATIONALITY, COUNTRY_OF_RESIDENCE, PHONE_NUMBER,
      EMAIL_ADDRESS);

  /**
   * Gets all eIDAS natural person attributes.
   *
   * @return an immutable list of {@link EidasAttributeTemplate}s
   */
  public static @Nonnull List<EidasAttributeTemplate> getAll() {
    return ALL;
  }

  /**
   * Gets the template for the eIDAS attribute having the supplied name.
   *
   * @param name the eIDAS attribute name
   * @return an {@link EidasAttributeTemplate}, or {@code null} if the name is not an eIDAS natural person attribute
   */
  public static @Nullable EidasAttributeTemplate get(final @Nullable String name) {
    return ALL.stream()
        .filter(t -> t.name().equals(name))
        .findFirst()
        .orElse(null);
  }

  // Hidden constructor
  private EidasNaturalPersonAttributes() {
  }

}
