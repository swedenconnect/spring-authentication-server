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

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * The attribute definitions that the library ships with. The set is the union of the attributes of the Attribute
 * Specification for the Swedish eID Framework and the claims of the Swedish OpenID Connect profiles, the OpenID
 * Connect Core standard claims included.
 * <p>
 * Where the two protocols differ in granularity the finer representation is used. A Swedish personal identity number
 * and a coordination number are separate attributes, each part of the OpenID Connect {@code address} claim is an
 * attribute of its own, and so is each part of the eIDAS natural person address.
 * </p>
 *
 * @author Martin Lindström
 */
public class BuiltInAttributeDefinitions {

  /** The built-in definitions. */
  private static final List<AttributeDefinition> DEFINITIONS = List.of(
      new AttributeDefinition(AttributeIdentifiers.SURNAME, String.class, false,
          "Surname (family name)."),
      new AttributeDefinition(AttributeIdentifiers.GIVEN_NAME, String.class, false,
          "Given name."),
      new AttributeDefinition(AttributeIdentifiers.MIDDLE_NAME, String.class, false,
          "Middle name."),
      new AttributeDefinition(AttributeIdentifiers.DISPLAY_NAME, String.class, false,
          "Name in a preferred presentation format (display, or full, name)."),
      new AttributeDefinition(AttributeIdentifiers.NICKNAME, String.class, false,
          "Casual name that may or may not be the same as the given name."),
      new AttributeDefinition(AttributeIdentifiers.PREFERRED_USERNAME, String.class, false,
          "Shorthand name by which the user wishes to be referred to."),
      new AttributeDefinition(AttributeIdentifiers.BIRTH_NAME, String.class, false,
          "Full name of the user at the time of birth."),
      new AttributeDefinition(AttributeIdentifiers.BIRTH_FAMILY_NAME, String.class, false,
          "Family name of the user at the time of birth."),
      new AttributeDefinition(AttributeIdentifiers.BIRTH_GIVEN_NAME, String.class, false,
          "Given name of the user at the time of birth."),
      new AttributeDefinition(AttributeIdentifiers.BIRTH_MIDDLE_NAME, String.class, false,
          "Middle name of the user at the time of birth."),
      new AttributeDefinition(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, String.class, false,
          "Swedish personal identity number (\"personnummer\") according to SKV 704. Twelve digits without a hyphen."),
      new AttributeDefinition(AttributeIdentifiers.COORDINATION_NUMBER, String.class, false,
          "Swedish coordination number (\"samordningsnummer\") according to SKV 707. Twelve digits without a hyphen."),
      new AttributeDefinition(AttributeIdentifiers.COORDINATION_NUMBER_LEVEL, String.class, false,
          "Level of a coordination number. One of confirmed, probable or uncertain."),
      new AttributeDefinition(AttributeIdentifiers.PREVIOUS_PERSONAL_IDENTITY_NUMBER, String.class, false,
          "A personal identity number previously held by the user."),
      new AttributeDefinition(AttributeIdentifiers.PREVIOUS_COORDINATION_NUMBER, String.class, false,
          "A coordination number previously held by the user."),
      new AttributeDefinition(AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER, String.class, false,
          "A personal identity number obtained by binding an eIDAS identity to a Swedish identity."),
      new AttributeDefinition(AttributeIdentifiers.MAPPED_COORDINATION_NUMBER, String.class, false,
          "A coordination number obtained by binding an eIDAS identity to a Swedish identity."),
      new AttributeDefinition(AttributeIdentifiers.IDENTITY_BINDING, String.class, false,
          "Semicolon separated list of URIs identifying the binding processes used to obtain a mapped number."),
      new AttributeDefinition(AttributeIdentifiers.DATE_OF_BIRTH, LocalDate.class, false,
          "Date of birth."),
      new AttributeDefinition(AttributeIdentifiers.PLACE_OF_BIRTH, String.class, false,
          "Place of birth given as free text."),
      new AttributeDefinition(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY, String.class, false,
          "Country of birth."),
      new AttributeDefinition(AttributeIdentifiers.PLACE_OF_BIRTH_REGION, String.class, false,
          "State, province or region of birth."),
      new AttributeDefinition(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY, String.class, false,
          "City or town of birth."),
      new AttributeDefinition(AttributeIdentifiers.GENDER, String.class, false,
          "Gender of the user. One of female, male or u (unspecified)."),
      new AttributeDefinition(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP, String.class, true,
          "Country of citizenship given as an ISO 3166-1 alpha-2 country code."),
      new AttributeDefinition(AttributeIdentifiers.COUNTRY_OF_RESIDENCE, String.class, false,
          "Country of residence given as an ISO 3166-1 alpha-2 country code."),
      new AttributeDefinition(AttributeIdentifiers.FORMATTED_ADDRESS, String.class, false,
          "Full mailing address, formatted for display."),
      new AttributeDefinition(AttributeIdentifiers.STREET_ADDRESS, String.class, false,
          "Street address."),
      new AttributeDefinition(AttributeIdentifiers.POST_OFFICE_BOX, String.class, false,
          "Post office box."),
      new AttributeDefinition(AttributeIdentifiers.POSTAL_CODE, String.class, false,
          "Postal code."),
      new AttributeDefinition(AttributeIdentifiers.LOCALITY, String.class, false,
          "Locality (city or town)."),
      new AttributeDefinition(AttributeIdentifiers.REGION, String.class, false,
          "State, province or region."),
      new AttributeDefinition(AttributeIdentifiers.COUNTRY, String.class, false,
          "Country given as an ISO 3166-1 alpha-2 country code."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX, String.class, false,
          "Post office box of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, String.class, false,
          "Locator designator (such as a house number) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME, String.class, false,
          "Locator name (such as a building name) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_AREA, String.class, false,
          "Address area of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, String.class, false,
          "Thoroughfare (street name) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, String.class, false,
          "Post name (city or town) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE, String.class, false,
          "First administrative unit line (country) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE, String.class, false,
          "Second administrative unit line (region) of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE, String.class, false,
          "Post code of an eIDAS natural person address."),
      new AttributeDefinition(AttributeIdentifiers.TELEPHONE_NUMBER, String.class, true,
          "Telephone number."),
      new AttributeDefinition(AttributeIdentifiers.MOBILE_NUMBER, String.class, true,
          "Mobile telephone number."),
      new AttributeDefinition(AttributeIdentifiers.PHONE_NUMBER_VERIFIED, Boolean.class, false,
          "Whether the telephone number has been verified."),
      new AttributeDefinition(AttributeIdentifiers.EMAIL, String.class, true,
          "E-mail address."),
      new AttributeDefinition(AttributeIdentifiers.EMAIL_VERIFIED, Boolean.class, false,
          "Whether the e-mail address has been verified."),
      new AttributeDefinition(AttributeIdentifiers.ORGANIZATION_NAME, String.class, false,
          "Registered organization name."),
      new AttributeDefinition(AttributeIdentifiers.ORGANIZATIONAL_UNIT_NAME, String.class, true,
          "Organizational unit name."),
      new AttributeDefinition(AttributeIdentifiers.ORGANIZATION_IDENTIFIER, String.class, false,
          "Swedish organization number (\"organisationsnummer\") according to SKV 709. Ten digits without a hyphen."),
      new AttributeDefinition(AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION, String.class, true,
          "Personal identity at a Swedish organization on the form <personal-id>@<org-number>."),
      new AttributeDefinition(AttributeIdentifiers.PROFILE, String.class, false,
          "URL of the user profile page."),
      new AttributeDefinition(AttributeIdentifiers.PICTURE, String.class, false,
          "URL of the user profile picture."),
      new AttributeDefinition(AttributeIdentifiers.WEBSITE, String.class, false,
          "URL of the user web page or blog."),
      new AttributeDefinition(AttributeIdentifiers.ZONE_INFO, String.class, false,
          "Time zone of the user, for example Europe/Stockholm."),
      new AttributeDefinition(AttributeIdentifiers.LOCALE, String.class, false,
          "Locale of the user, for example sv-SE."),
      new AttributeDefinition(AttributeIdentifiers.UPDATED_AT, Instant.class, false,
          "Time when the user information was last updated."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER, String.class, false,
          "eIDAS uniqueness identifier for a natural person."),
      new AttributeDefinition(AttributeIdentifiers.EIDAS_COUNTRY, String.class, false,
          "The eIDAS member state that provided the identity of the user."),
      new AttributeDefinition(AttributeIdentifiers.PRID, String.class, false,
          "Provisional identifier issued by the Swedish eIDAS connector."),
      new AttributeDefinition(AttributeIdentifiers.PRID_PERSISTENCE, String.class, false,
          "Expected persistence of the provisional identifier. One of A, B or C."),
      new AttributeDefinition(AttributeIdentifiers.USER_CERTIFICATE, String.class, false,
          "Base64 encoding of a certificate presented by the user during authentication."),
      new AttributeDefinition(AttributeIdentifiers.USER_SIGNATURE, String.class, false,
          "Base64 encoding of a signature produced by the user during authentication."),
      new AttributeDefinition(AttributeIdentifiers.AUTHENTICATION_EVIDENCE, String.class, false,
          "Base64 encoding of evidence about the authentication, such as an OCSP response or an assertion."),
      new AttributeDefinition(AttributeIdentifiers.CREDENTIAL_VALID_FROM, Instant.class, false,
          "Start time of the validity of the credential used during authentication."),
      new AttributeDefinition(AttributeIdentifiers.CREDENTIAL_VALID_TO, Instant.class, false,
          "End time of the validity of the credential used during authentication."),
      new AttributeDefinition(AttributeIdentifiers.DEVICE_IP, String.class, false,
          "IP address of the device holding the credential used during authentication."),
      new AttributeDefinition(AttributeIdentifiers.AUTHENTICATION_PROVIDER, String.class, false,
          "Identity of the provider, or mechanism, that authenticated the user."),
      new AttributeDefinition(AttributeIdentifiers.TRANSACTION_IDENTIFIER, String.class, false,
          "Transaction identifier for the authentication event."),
      new AttributeDefinition(AttributeIdentifiers.SAD, String.class, false,
          "Signature activation data required by signature services."),
      new AttributeDefinition(AttributeIdentifiers.SIGN_MESSAGE_DIGEST, String.class, false,
          "Proof that a sign message was displayed to the user."),
      new AttributeDefinition(AttributeIdentifiers.AUTH_CONTEXT_PARAMS, String.class, false,
          "Key-value pairs from the authentication process, defined by the issuing entity."),
      new AttributeDefinition(AttributeIdentifiers.EMPLOYEE_HSA_ID, String.class, false,
          "HSA-ID. Person identifier used by Swedish health care organizations."));

  /**
   * Gets the attribute definitions that the library ships with.
   *
   * @return an immutable list of {@link AttributeDefinition}s
   */
  public static @Nonnull List<AttributeDefinition> getDefinitions() {
    return DEFINITIONS;
  }

  // Hidden constructor
  private BuiltInAttributeDefinitions() {
  }

}
