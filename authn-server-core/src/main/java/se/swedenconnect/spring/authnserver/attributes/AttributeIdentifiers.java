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

/**
 * Identifiers for the generic attributes that the library knows about.
 * <p>
 * An identifier is the prefix {@value #PREFIX} followed by a kebab-case name, for example
 * {@code attribute.personal-identity-number}. Applications that introduce attributes of their own follow the same
 * pattern.
 * </p>
 *
 * @author Martin Lindström
 */
public class AttributeIdentifiers {

  /** The prefix for all generic attribute identifiers. */
  public static final String PREFIX = "attribute.";

  /** Surname (family name). */
  public static final String SURNAME = PREFIX + "surname";

  /** Given name. */
  public static final String GIVEN_NAME = PREFIX + "given-name";

  /** Middle name. */
  public static final String MIDDLE_NAME = PREFIX + "middle-name";

  /** Name in a preferred presentation format (display, or full, name). */
  public static final String DISPLAY_NAME = PREFIX + "display-name";

  /** Casual name that may or may not be the same as the given name. */
  public static final String NICKNAME = PREFIX + "nickname";

  /** Shorthand name by which the user wishes to be referred to. */
  public static final String PREFERRED_USERNAME = PREFIX + "preferred-username";

  /** Full name of the user at the time of birth. */
  public static final String BIRTH_NAME = PREFIX + "birth-name";

  /** Family name of the user at the time of birth. */
  public static final String BIRTH_FAMILY_NAME = PREFIX + "birth-family-name";

  /** Given name of the user at the time of birth. */
  public static final String BIRTH_GIVEN_NAME = PREFIX + "birth-given-name";

  /** Middle name of the user at the time of birth. */
  public static final String BIRTH_MIDDLE_NAME = PREFIX + "birth-middle-name";

  /** Swedish personal identity number ("personnummer") according to SKV 704. Twelve digits without a hyphen. */
  public static final String PERSONAL_IDENTITY_NUMBER = PREFIX + "personal-identity-number";

  /** Swedish coordination number ("samordningsnummer") according to SKV 707. Twelve digits without a hyphen. */
  public static final String COORDINATION_NUMBER = PREFIX + "coordination-number";

  /** Level of a coordination number. One of {@code confirmed}, {@code probable} or {@code uncertain}. */
  public static final String COORDINATION_NUMBER_LEVEL = PREFIX + "coordination-number-level";

  /** A personal identity number previously held by the user. */
  public static final String PREVIOUS_PERSONAL_IDENTITY_NUMBER = PREFIX + "previous-personal-identity-number";

  /** A coordination number previously held by the user. */
  public static final String PREVIOUS_COORDINATION_NUMBER = PREFIX + "previous-coordination-number";

  /** A personal identity number obtained by binding an eIDAS identity to a Swedish identity. */
  public static final String MAPPED_PERSONAL_IDENTITY_NUMBER = PREFIX + "mapped-personal-identity-number";

  /** A coordination number obtained by binding an eIDAS identity to a Swedish identity. */
  public static final String MAPPED_COORDINATION_NUMBER = PREFIX + "mapped-coordination-number";

  /** Semicolon separated list of URIs identifying the binding processes used to obtain a mapped identity number. */
  public static final String IDENTITY_BINDING = PREFIX + "identity-binding";

  /** Date of birth. */
  public static final String DATE_OF_BIRTH = PREFIX + "date-of-birth";

  /** Place of birth given as free text. */
  public static final String PLACE_OF_BIRTH = PREFIX + "place-of-birth";

  /** Country of birth. */
  public static final String PLACE_OF_BIRTH_COUNTRY = PREFIX + "place-of-birth-country";

  /** State, province or region of birth. */
  public static final String PLACE_OF_BIRTH_REGION = PREFIX + "place-of-birth-region";

  /** City or town of birth. */
  public static final String PLACE_OF_BIRTH_LOCALITY = PREFIX + "place-of-birth-locality";

  /** Gender of the user. One of {@code female}, {@code male} or {@code u} (unspecified). */
  public static final String GENDER = PREFIX + "gender";

  /** Country of citizenship given as an ISO 3166-1 alpha-2 country code. */
  public static final String COUNTRY_OF_CITIZENSHIP = PREFIX + "country-of-citizenship";

  /** Country of residence given as an ISO 3166-1 alpha-2 country code. */
  public static final String COUNTRY_OF_RESIDENCE = PREFIX + "country-of-residence";

  /** Full mailing address, formatted for display. */
  public static final String FORMATTED_ADDRESS = PREFIX + "formatted-address";

  /** Street address. */
  public static final String STREET_ADDRESS = PREFIX + "street-address";

  /** Post office box. */
  public static final String POST_OFFICE_BOX = PREFIX + "post-office-box";

  /** Postal code. */
  public static final String POSTAL_CODE = PREFIX + "postal-code";

  /** Locality (city or town). */
  public static final String LOCALITY = PREFIX + "locality";

  /** State, province or region. */
  public static final String REGION = PREFIX + "region";

  /** Country given as an ISO 3166-1 alpha-2 country code. */
  public static final String COUNTRY = PREFIX + "country";

  /** Post office box of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_PO_BOX = PREFIX + "eidas-address-po-box";

  /** Locator designator (such as a house number) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_LOCATOR_DESIGNATOR = PREFIX + "eidas-address-locator-designator";

  /** Locator name (such as a building name) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_LOCATOR_NAME = PREFIX + "eidas-address-locator-name";

  /** Address area of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_AREA = PREFIX + "eidas-address-area";

  /** Thoroughfare (street name) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_THOROUGHFARE = PREFIX + "eidas-address-thoroughfare";

  /** Post name (city or town) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_POST_NAME = PREFIX + "eidas-address-post-name";

  /** First administrative unit line (country) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE = PREFIX + "eidas-address-admin-unit-first-line";

  /** Second administrative unit line (region) of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE = PREFIX + "eidas-address-admin-unit-second-line";

  /** Post code of an eIDAS natural person address. */
  public static final String EIDAS_ADDRESS_POST_CODE = PREFIX + "eidas-address-post-code";

  /** Telephone number. */
  public static final String TELEPHONE_NUMBER = PREFIX + "telephone-number";

  /** Mobile telephone number. */
  public static final String MOBILE_NUMBER = PREFIX + "mobile-number";

  /** Whether the telephone number has been verified. */
  public static final String PHONE_NUMBER_VERIFIED = PREFIX + "phone-number-verified";

  /** E-mail address. */
  public static final String EMAIL = PREFIX + "email";

  /** Whether the e-mail address has been verified. */
  public static final String EMAIL_VERIFIED = PREFIX + "email-verified";

  /** Registered organization name. */
  public static final String ORGANIZATION_NAME = PREFIX + "organization-name";

  /** Organizational unit name. */
  public static final String ORGANIZATIONAL_UNIT_NAME = PREFIX + "organizational-unit-name";

  /** Swedish organization number ("organisationsnummer") according to SKV 709. Ten digits without a hyphen. */
  public static final String ORGANIZATION_IDENTIFIER = PREFIX + "organization-identifier";

  /** Personal identity at a Swedish organization on the form {@code <personal-id>@<org-number>}. */
  public static final String ORGANIZATIONAL_AFFILIATION = PREFIX + "organizational-affiliation";

  /** URL of the user profile page. */
  public static final String PROFILE = PREFIX + "profile";

  /** URL of the user profile picture. */
  public static final String PICTURE = PREFIX + "picture";

  /** URL of the user web page or blog. */
  public static final String WEBSITE = PREFIX + "website";

  /** Time zone of the user, for example {@code Europe/Stockholm}. */
  public static final String ZONE_INFO = PREFIX + "zone-info";

  /** Locale of the user, for example {@code sv-SE}. */
  public static final String LOCALE = PREFIX + "locale";

  /** Time when the user information was last updated. */
  public static final String UPDATED_AT = PREFIX + "updated-at";

  /** eIDAS uniqueness identifier for a natural person. */
  public static final String EIDAS_PERSON_IDENTIFIER = PREFIX + "eidas-person-identifier";

  /** The eIDAS member state that provided the identity of the user. */
  public static final String EIDAS_COUNTRY = PREFIX + "eidas-country";

  /** Provisional identifier issued by the Swedish eIDAS connector. */
  public static final String PRID = PREFIX + "prid";

  /** Expected persistence of the provisional identifier. One of {@code A}, {@code B} or {@code C}. */
  public static final String PRID_PERSISTENCE = PREFIX + "prid-persistence";

  /** Base64 encoding of a certificate presented by the user during authentication. */
  public static final String USER_CERTIFICATE = PREFIX + "user-certificate";

  /** Base64 encoding of a signature produced by the user during authentication. */
  public static final String USER_SIGNATURE = PREFIX + "user-signature";

  /** Base64 encoding of evidence about the authentication, such as a signature, an OCSP response or an assertion. */
  public static final String AUTHENTICATION_EVIDENCE = PREFIX + "authentication-evidence";

  /** Start time of the validity of the credential used during authentication. */
  public static final String CREDENTIAL_VALID_FROM = PREFIX + "credential-valid-from";

  /** End time of the validity of the credential used during authentication. */
  public static final String CREDENTIAL_VALID_TO = PREFIX + "credential-valid-to";

  /** IP address of the device holding the credential used during authentication. */
  public static final String DEVICE_IP = PREFIX + "device-ip";

  /** Identity of the provider, or mechanism, that authenticated the user. */
  public static final String AUTHENTICATION_PROVIDER = PREFIX + "authentication-provider";

  /** Transaction identifier for the authentication event. */
  public static final String TRANSACTION_IDENTIFIER = PREFIX + "transaction-identifier";

  /** Signature activation data required by signature services. */
  public static final String SAD = PREFIX + "sad";

  /** Proof that a sign message was displayed to the user. */
  public static final String SIGN_MESSAGE_DIGEST = PREFIX + "sign-message-digest";

  /** Key-value pairs from the authentication process, defined by the issuing entity. */
  public static final String AUTH_CONTEXT_PARAMS = PREFIX + "auth-context-params";

  /** HSA-ID. Person identifier used by Swedish health care organizations. */
  public static final String EMPLOYEE_HSA_ID = PREFIX + "employee-hsa-id";

  // Hidden constructor
  private AttributeIdentifiers() {
  }

}
