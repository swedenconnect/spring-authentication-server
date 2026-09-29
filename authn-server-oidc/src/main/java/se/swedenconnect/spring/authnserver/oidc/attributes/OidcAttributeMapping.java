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
package se.swedenconnect.spring.authnserver.oidc.attributes;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.oidc.nimbus.claims.ClaimConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.DefaultAttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.AddressToClaimMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimFromProtocolMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimToProtocolMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.GenderToClaimMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.PhoneNumberToClaimMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.PlaceOfBirthToClaimMapper;

/**
 * The mapping between the protocol-neutral attribute model and OpenID Connect claims.
 * <p>
 * The built-in mappers implement OpenID Connect Core, the Claims and Scopes Specification for the Swedish OpenID
 * Connect Profile and the OpenID Connect Claims and Scopes Specification for Sweden Connect. An application adds
 * mappers of its own, or replaces a built-in mapper, by registering with {@link #getFromProtocolMapping()} and
 * {@link #getToProtocolMapping()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcAttributeMapping {

  /** Maps requested claims into the generic form. */
  private final FromProtocolAttributeMapping<RequestedClaim> fromProtocolMapping;

  /** Maps generic attributes into claims. */
  private final ToProtocolAttributeMapping<UserClaim> toProtocolMapping;

  /**
   * Default constructor using the built-in attribute definitions and the built-in mappers.
   */
  public OidcAttributeMapping() {
    this(new DefaultAttributeDefinitionRegistry(), true);
  }

  /**
   * Constructor using the built-in mappers.
   *
   * @param definitions the attribute definitions to use
   */
  public OidcAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions) {
    this(definitions, true);
  }

  /**
   * Constructor.
   *
   * @param definitions the attribute definitions to use
   * @param registerBuiltInMappers whether to register the built-in mappers
   */
  public OidcAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions,
      final boolean registerBuiltInMappers) {
    Objects.requireNonNull(definitions, "definitions must not be null");
    this.fromProtocolMapping = new FromProtocolAttributeMapping<>(definitions, RequestedClaim::name);
    this.toProtocolMapping = new ToProtocolAttributeMapping<>(definitions, UserClaim::name, UserClaim::merge);
    if (registerBuiltInMappers) {
      this.fromProtocolMapping.registerAll(getBuiltInFromProtocolMappers());
      this.toProtocolMapping.registerAll(getBuiltInToProtocolMappers());
    }
  }

  /**
   * Maps requested claims into the generic form.
   *
   * @param requestedClaims the requested claims
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGeneric(final @Nonnull List<RequestedClaim> requestedClaims) {
    return this.fromProtocolMapping.map(requestedClaims);
  }

  /**
   * Maps the claims of a claims request parameter into the generic form. The section that a claim was requested in
   * decides its delivery target.
   *
   * @param claimsRequest the claims request, may be {@code null}
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGenericFromClaimsRequest(
      final @Nullable OIDCClaimsRequest claimsRequest) {
    if (claimsRequest == null) {
      return List.of();
    }
    final List<RequestedClaim> requestedClaims = new ArrayList<>();
    addEntries(requestedClaims, claimsRequest.getIDTokenClaimsRequest(), ClaimDeliveryTarget.ID_TOKEN);
    addEntries(requestedClaims, claimsRequest.getUserInfoClaimsRequest(), ClaimDeliveryTarget.USER_INFO);
    return this.toGeneric(requestedClaims);
  }

  /**
   * Maps generic attributes into claims.
   *
   * @param attributes the attributes to map
   * @param requestedAttributes the requested attributes of the operation, may be {@code null}
   * @return the claims
   */
  public @Nonnull List<UserClaim> toClaims(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nullable List<GenericRequestedAttribute> requestedAttributes) {
    return this.toProtocolMapping.map(attributes, requestedAttributes);
  }

  /**
   * Gets the mapping from requested claims into the generic form. Use it to register mappers of your own.
   *
   * @return a {@link FromProtocolAttributeMapping}
   */
  public @Nonnull FromProtocolAttributeMapping<RequestedClaim> getFromProtocolMapping() {
    return this.fromProtocolMapping;
  }

  /**
   * Gets the mapping from generic attributes into claims. Use it to register mappers of your own.
   *
   * @return a {@link ToProtocolAttributeMapping}
   */
  public @Nonnull ToProtocolAttributeMapping<UserClaim> getToProtocolMapping() {
    return this.toProtocolMapping;
  }

  /**
   * Adds the entries of a claims set request to the list of requested claims.
   *
   * @param requestedClaims the list to add to
   * @param claimsSetRequest the claims set request, may be {@code null}
   * @param target the delivery target
   */
  private static void addEntries(final @Nonnull List<RequestedClaim> requestedClaims,
      final @Nullable ClaimsSetRequest claimsSetRequest, final @Nonnull ClaimDeliveryTarget target) {
    if (claimsSetRequest == null) {
      return;
    }
    for (final ClaimsSetRequest.Entry entry : claimsSetRequest.getEntries()) {
      requestedClaims.add(new RequestedClaim(entry, target));
    }
  }

  /**
   * Gets the built-in mappers from requested claims into the generic form.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<FromProtocolAttributeMapper<RequestedClaim>> getBuiltInFromProtocolMappers() {
    final List<FromProtocolAttributeMapper<RequestedClaim>> mappers = new ArrayList<>();

    // OpenID Connect Core standard claims.
    //
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.NAME_CLAIM_NAME, AttributeIdentifiers.DISPLAY_NAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.FAMILY_NAME_CLAIM_NAME, AttributeIdentifiers.SURNAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.GIVEN_NAME_CLAIM_NAME, AttributeIdentifiers.GIVEN_NAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.MIDDLE_NAME_CLAIM_NAME, AttributeIdentifiers.MIDDLE_NAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.NICKNAME_CLAIM_NAME, AttributeIdentifiers.NICKNAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.PREFERRED_USERNAME_CLAIM_NAME,
        AttributeIdentifiers.PREFERRED_USERNAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.PROFILE_CLAIM_NAME, AttributeIdentifiers.PROFILE));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.PICTURE_CLAIM_NAME, AttributeIdentifiers.PICTURE));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.WEBSITE_CLAIM_NAME, AttributeIdentifiers.WEBSITE));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.EMAIL_CLAIM_NAME, AttributeIdentifiers.EMAIL));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.EMAIL_VERIFIED_CLAIM_NAME,
        AttributeIdentifiers.EMAIL_VERIFIED));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.GENDER_CLAIM_NAME, AttributeIdentifiers.GENDER));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.BIRTHDATE_CLAIM_NAME, AttributeIdentifiers.DATE_OF_BIRTH));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.ZONEINFO_CLAIM_NAME, AttributeIdentifiers.ZONE_INFO));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.LOCALE_CLAIM_NAME, AttributeIdentifiers.LOCALE));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.PHONE_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.TELEPHONE_NUMBER, AttributeIdentifiers.MOBILE_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.PHONE_NUMBER_VERIFIED_CLAIM_NAME,
        AttributeIdentifiers.PHONE_NUMBER_VERIFIED));
    mappers.add(ClaimFromProtocolMapper.withoutValues(PersonClaims.ADDRESS_CLAIM_NAME,
        AttributeIdentifiers.FORMATTED_ADDRESS, AttributeIdentifiers.STREET_ADDRESS,
        AttributeIdentifiers.POST_OFFICE_BOX, AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.LOCALITY,
        AttributeIdentifiers.REGION, AttributeIdentifiers.COUNTRY,
        AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX, AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR,
        AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME, AttributeIdentifiers.EIDAS_ADDRESS_AREA,
        AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME,
        AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE,
        AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE, AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.UPDATED_AT_CLAIM_NAME, AttributeIdentifiers.UPDATED_AT));

    // Claims from OpenID Connect for Identity Assurance and RFC 8417.
    //
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.BIRTH_FAMILY_NAME_CLAIM_NAME,
        AttributeIdentifiers.BIRTH_FAMILY_NAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.BIRTH_GIVEN_NAME_CLAIM_NAME,
        AttributeIdentifiers.BIRTH_GIVEN_NAME));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.BIRTH_MIDDLE_NAME_CLAIM_NAME,
        AttributeIdentifiers.BIRTH_MIDDLE_NAME));
    mappers.add(ClaimFromProtocolMapper.withoutValues(PersonClaims.PLACE_OF_BIRTH_CLAIM_NAME,
        AttributeIdentifiers.PLACE_OF_BIRTH, AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY,
        AttributeIdentifiers.PLACE_OF_BIRTH_REGION, AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.NATIONALITIES_CLAIM_NAME,
        AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP));
    mappers.add(new ClaimFromProtocolMapper(PersonClaims.MSISDN_CLAIM_NAME, AttributeIdentifiers.MOBILE_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.TXN_CLAIM_NAME,
        AttributeIdentifiers.TRANSACTION_IDENTIFIER));

    // Claims of the Swedish OpenID Connect profile.
    //
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.COORDINATION_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.COORDINATION_NUMBER_LEVEL_CLAIM_NAME,
        AttributeIdentifiers.COORDINATION_NUMBER_LEVEL));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.PREVIOUS_COORDINATION_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.PREVIOUS_COORDINATION_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.ORGANIZATION_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.ORGANIZATION_IDENTIFIER));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.ORGANIZATIONAL_AFFILIATION_CLAIM_NAME,
        AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.ORGANIZATION_NAME_CLAIM_NAME,
        AttributeIdentifiers.ORGANIZATION_NAME));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.ORGANIZATIONAL_UNIT_NAME_CLAIM_NAME,
        AttributeIdentifiers.ORGANIZATIONAL_UNIT_NAME));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.USER_CERTIFICATE_CLAIM_NAME,
        AttributeIdentifiers.USER_CERTIFICATE));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.USER_SIGNATURE_CLAIM_NAME,
        AttributeIdentifiers.USER_SIGNATURE));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.CREDENTIALS_VALID_FROM_CLAIM_NAME,
        AttributeIdentifiers.CREDENTIAL_VALID_FROM));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.CREDENTIALS_VALID_TO_CLAIM_NAME,
        AttributeIdentifiers.CREDENTIAL_VALID_TO));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.DEVICE_IP_CLAIM_NAME, AttributeIdentifiers.DEVICE_IP));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.AUTHENTICATION_EVIDENCE_CLAIM_NAME,
        AttributeIdentifiers.AUTHENTICATION_EVIDENCE));
    mappers.add(new ClaimFromProtocolMapper(ClaimConstants.AUTHENTICATION_PROVIDER_CLAIM_NAME,
        AttributeIdentifiers.AUTHENTICATION_PROVIDER));

    // Claims of the Sweden Connect OpenID Connect profile.
    //
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.PRID_CLAIM_NAME, AttributeIdentifiers.PRID));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.PRID_PERSISTENCE_CLAIM_NAME,
        AttributeIdentifiers.PRID_PERSISTENCE));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.MAPPED_PERSONAL_IDENTITY_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.MAPPED_COORDINATION_NUMBER_CLAIM_NAME,
        AttributeIdentifiers.MAPPED_COORDINATION_NUMBER));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.IDENTITY_BINDING_CLAIM_NAME,
        AttributeIdentifiers.IDENTITY_BINDING));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.EIDAS_PERSON_IDENTIFIER_CLAIM_NAME,
        AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER));
    mappers.add(new ClaimFromProtocolMapper(OidcClaimConstants.EIDAS_COUNTRY_CLAIM_NAME,
        AttributeIdentifiers.EIDAS_COUNTRY));

    return mappers;
  }

  /**
   * Gets the built-in mappers from generic attributes into claims.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<ToProtocolAttributeMapper<UserClaim>> getBuiltInToProtocolMappers() {
    final List<ToProtocolAttributeMapper<UserClaim>> mappers = new ArrayList<>();

    // OpenID Connect Core standard claims.
    //
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.DISPLAY_NAME, PersonClaims.NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.SURNAME, PersonClaims.FAMILY_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.GIVEN_NAME, PersonClaims.GIVEN_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.MIDDLE_NAME, PersonClaims.MIDDLE_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.NICKNAME, PersonClaims.NICKNAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PREFERRED_USERNAME,
        PersonClaims.PREFERRED_USERNAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PROFILE, PersonClaims.PROFILE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PICTURE, PersonClaims.PICTURE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.WEBSITE, PersonClaims.WEBSITE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.EMAIL, PersonClaims.EMAIL_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.EMAIL_VERIFIED,
        PersonClaims.EMAIL_VERIFIED_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.DATE_OF_BIRTH, PersonClaims.BIRTHDATE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.ZONE_INFO, PersonClaims.ZONEINFO_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.LOCALE, PersonClaims.LOCALE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PHONE_NUMBER_VERIFIED,
        PersonClaims.PHONE_NUMBER_VERIFIED_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.UPDATED_AT, PersonClaims.UPDATED_AT_CLAIM_NAME));

    // Claims from OpenID Connect for Identity Assurance and RFC 8417.
    //
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.BIRTH_FAMILY_NAME,
        PersonClaims.BIRTH_FAMILY_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.BIRTH_GIVEN_NAME,
        PersonClaims.BIRTH_GIVEN_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.BIRTH_MIDDLE_NAME,
        PersonClaims.BIRTH_MIDDLE_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP,
        PersonClaims.NATIONALITIES_CLAIM_NAME, true));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.TRANSACTION_IDENTIFIER,
        OidcClaimConstants.TXN_CLAIM_NAME));

    // Claims of the Swedish OpenID Connect profile.
    //
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
        ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.COORDINATION_NUMBER,
        ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.COORDINATION_NUMBER_LEVEL,
        ClaimConstants.COORDINATION_NUMBER_LEVEL_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PREVIOUS_COORDINATION_NUMBER,
        ClaimConstants.PREVIOUS_COORDINATION_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.ORGANIZATION_IDENTIFIER,
        ClaimConstants.ORGANIZATION_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION,
        ClaimConstants.ORGANIZATIONAL_AFFILIATION_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.ORGANIZATION_NAME,
        ClaimConstants.ORGANIZATION_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.ORGANIZATIONAL_UNIT_NAME,
        ClaimConstants.ORGANIZATIONAL_UNIT_NAME_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.USER_CERTIFICATE,
        ClaimConstants.USER_CERTIFICATE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.USER_SIGNATURE,
        ClaimConstants.USER_SIGNATURE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.CREDENTIAL_VALID_FROM,
        ClaimConstants.CREDENTIALS_VALID_FROM_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.CREDENTIAL_VALID_TO,
        ClaimConstants.CREDENTIALS_VALID_TO_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.DEVICE_IP, ClaimConstants.DEVICE_IP_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.AUTHENTICATION_EVIDENCE,
        ClaimConstants.AUTHENTICATION_EVIDENCE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.AUTHENTICATION_PROVIDER,
        ClaimConstants.AUTHENTICATION_PROVIDER_CLAIM_NAME));

    // Claims of the Sweden Connect OpenID Connect profile.
    //
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PRID, OidcClaimConstants.PRID_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.PRID_PERSISTENCE,
        OidcClaimConstants.PRID_PERSISTENCE_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER,
        OidcClaimConstants.MAPPED_PERSONAL_IDENTITY_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.MAPPED_COORDINATION_NUMBER,
        OidcClaimConstants.MAPPED_COORDINATION_NUMBER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.IDENTITY_BINDING,
        OidcClaimConstants.IDENTITY_BINDING_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER,
        OidcClaimConstants.EIDAS_PERSON_IDENTIFIER_CLAIM_NAME));
    mappers.add(new ClaimToProtocolMapper(AttributeIdentifiers.EIDAS_COUNTRY,
        OidcClaimConstants.EIDAS_COUNTRY_CLAIM_NAME));

    // Claims that are built from more than one attribute, or where the value decides the result.
    //
    mappers.add(new GenderToClaimMapper());
    mappers.add(new PhoneNumberToClaimMapper());
    mappers.add(new AddressToClaimMapper());
    mappers.add(new PlaceOfBirthToClaimMapper());

    return mappers;
  }

}
