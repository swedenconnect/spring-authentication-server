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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.DefaultAttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.BirthNameToSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.EidasAddressFromProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.EidasAddressToSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.FirstPresentSamlToProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.GenderFromSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.GenderToSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.IdentityNumberFromSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.PlaceOfBirthToSamlMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.SamlFromProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.SamlToProtocolMapper;

/**
 * The mapping between the protocol-neutral attribute model and SAML attributes.
 * <p>
 * The built-in mappers implement the Attribute Specification for the Swedish eID Framework. An application adds
 * mappers of its own, or replaces a built-in mapper, by registering with
 * {@link #getFromProtocolMapping()} and {@link #getToProtocolMapping()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class SamlAttributeMapping {

  /** Maps SAML requested attributes into the generic form. */
  private final FromProtocolAttributeMapping<SamlRequestedAttribute> fromProtocolMapping;

  /** Maps generic attributes into SAML attributes. */
  private final ToProtocolAttributeMapping<Attribute> toProtocolMapping;

  /**
   * Default constructor using the built-in attribute definitions and the built-in mappers.
   */
  public SamlAttributeMapping() {
    this(new DefaultAttributeDefinitionRegistry(), true);
  }

  /**
   * Constructor using the built-in mappers.
   *
   * @param definitions the attribute definitions to use
   */
  public SamlAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions) {
    this(definitions, true);
  }

  /**
   * Constructor.
   *
   * @param definitions the attribute definitions to use
   * @param registerBuiltInMappers whether to register the built-in mappers
   */
  public SamlAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions,
      final boolean registerBuiltInMappers) {
    Objects.requireNonNull(definitions, "definitions must not be null");
    this.fromProtocolMapping = new FromProtocolAttributeMapping<>(definitions, SamlRequestedAttribute::name);
    this.toProtocolMapping = new ToProtocolAttributeMapping<>(definitions, Attribute::getName,
        SamlAttributeValues::merge);
    if (registerBuiltInMappers) {
      this.fromProtocolMapping.registerAll(getBuiltInFromProtocolMappers());
      this.toProtocolMapping.registerAll(getBuiltInToProtocolMappers());
    }
  }

  /**
   * Maps SAML requested attributes, from an authentication request or from metadata, into the generic form.
   *
   * @param requestedAttributes the SAML requested attributes
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGeneric(
      final @Nonnull List<SamlRequestedAttribute> requestedAttributes) {
    return this.fromProtocolMapping.map(requestedAttributes);
  }

  /**
   * Maps SAML requested attributes into the generic form. Both the requested attribute of SAML metadata and the eIDAS
   * requested attribute are accepted.
   *
   * @param requestedAttributes the SAML requested attributes
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGenericFromRequestedAttributes(
      final @Nonnull List<? extends RequestedAttribute> requestedAttributes) {
    final List<SamlRequestedAttribute> inputs = new ArrayList<>(requestedAttributes.size());
    requestedAttributes.forEach(a -> inputs.add(SamlRequestedAttribute.of(a)));
    return this.toGeneric(inputs);
  }

  /**
   * Maps generic attributes into SAML attributes.
   *
   * @param attributes the attributes to map
   * @param requestedAttributes the requested attributes of the operation, may be {@code null}
   * @return the SAML attributes
   */
  public @Nonnull List<Attribute> toSaml(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nullable List<GenericRequestedAttribute> requestedAttributes) {
    return this.toProtocolMapping.map(attributes, requestedAttributes);
  }

  /**
   * Gets the mapping from SAML requested attributes into the generic form. Use it to register mappers of your own.
   *
   * @return a {@link FromProtocolAttributeMapping}
   */
  public @Nonnull FromProtocolAttributeMapping<SamlRequestedAttribute> getFromProtocolMapping() {
    return this.fromProtocolMapping;
  }

  /**
   * Gets the mapping from generic attributes into SAML attributes. Use it to register mappers of your own.
   *
   * @return a {@link ToProtocolAttributeMapping}
   */
  public @Nonnull ToProtocolAttributeMapping<Attribute> getToProtocolMapping() {
    return this.toProtocolMapping;
  }

  /**
   * Gets the built-in mappers from SAML requested attributes into the generic form.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<FromProtocolAttributeMapper<SamlRequestedAttribute>> getBuiltInFromProtocolMappers() {
    final List<FromProtocolAttributeMapper<SamlRequestedAttribute>> mappers = new ArrayList<>();

    // One SAML attribute, one generic attribute.
    //
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_SN, AttributeIdentifiers.SURNAME);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, AttributeIdentifiers.GIVEN_NAME);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME, AttributeIdentifiers.DISPLAY_NAME);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, AttributeIdentifiers.DATE_OF_BIRTH);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_STREET, AttributeIdentifiers.STREET_ADDRESS);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_POST_OFFICE_BOX, AttributeIdentifiers.POST_OFFICE_BOX);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_POSTAL_CODE, AttributeIdentifiers.POSTAL_CODE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_L, AttributeIdentifiers.LOCALITY);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_C, AttributeIdentifiers.COUNTRY);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_COUNTRY_OF_CITIZENSHIP,
        AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_COUNTRY_OF_RESIDENCE,
        AttributeIdentifiers.COUNTRY_OF_RESIDENCE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_TELEPHONE_NUMBER, AttributeIdentifiers.TELEPHONE_NUMBER);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_MOBILE, AttributeIdentifiers.MOBILE_NUMBER);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_MAIL, AttributeIdentifiers.EMAIL);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_O, AttributeIdentifiers.ORGANIZATION_NAME);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_OU, AttributeIdentifiers.ORGANIZATIONAL_UNIT_NAME);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_ORGANIZATION_IDENTIFIER,
        AttributeIdentifiers.ORGANIZATION_IDENTIFIER);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_ORG_AFFILIATION,
        AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_TRANSACTION_IDENTIFIER,
        AttributeIdentifiers.TRANSACTION_IDENTIFIER);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_AUTH_CONTEXT_PARAMS, AttributeIdentifiers.AUTH_CONTEXT_PARAMS);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_USER_CERTIFICATE, AttributeIdentifiers.USER_CERTIFICATE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_USER_SIGNATURE, AttributeIdentifiers.USER_SIGNATURE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_AUTH_SERVER_SIGNATURE,
        AttributeIdentifiers.AUTHENTICATION_EVIDENCE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_SAD, AttributeIdentifiers.SAD);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST, AttributeIdentifiers.SIGN_MESSAGE_DIGEST);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_PRID, AttributeIdentifiers.PRID);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_PRID_PERSISTENCE, AttributeIdentifiers.PRID_PERSISTENCE);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER_BINDING,
        AttributeIdentifiers.IDENTITY_BINDING);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_EIDAS_PERSON_IDENTIFIER,
        AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER);
    simple(mappers, AttributeConstants.ATTRIBUTE_NAME_EMPLOYEE_HSA_ID, AttributeIdentifiers.EMPLOYEE_HSA_ID);

    // One SAML attribute, several generic attributes.
    //
    mappers.add(new SamlFromProtocolMapper(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME,
        AttributeIdentifiers.BIRTH_NAME, AttributeIdentifiers.BIRTH_FAMILY_NAME,
        AttributeIdentifiers.BIRTH_GIVEN_NAME, AttributeIdentifiers.BIRTH_MIDDLE_NAME));
    mappers.add(new SamlFromProtocolMapper(AttributeConstants.ATTRIBUTE_NAME_PLACE_OF_BIRTH,
        AttributeIdentifiers.PLACE_OF_BIRTH, AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY,
        AttributeIdentifiers.PLACE_OF_BIRTH_REGION, AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY));

    // Civic registration numbers, where the SAML attribute may be either kind of number.
    //
    mappers.add(new IdentityNumberFromSamlMapper(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.COORDINATION_NUMBER));
    mappers.add(new IdentityNumberFromSamlMapper(AttributeConstants.ATTRIBUTE_NAME_PREVIOUS_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.PREVIOUS_PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.PREVIOUS_COORDINATION_NUMBER));
    mappers.add(new IdentityNumberFromSamlMapper(AttributeConstants.ATTRIBUTE_NAME_MAPPED_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.MAPPED_COORDINATION_NUMBER));

    mappers.add(new GenderFromSamlMapper());
    mappers.add(new EidasAddressFromProtocolMapper(
        AttributeConstants.ATTRIBUTE_NAME_EIDAS_NATURAL_PERSON_ADDRESS));

    return mappers;
  }

  /**
   * Gets the built-in mappers from generic attributes into SAML attributes.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<ToProtocolAttributeMapper<Attribute>> getBuiltInToProtocolMappers() {
    final List<ToProtocolAttributeMapper<Attribute>> mappers = new ArrayList<>();

    // One generic attribute, one SAML attribute.
    //
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.SURNAME,
        AttributeConstants.ATTRIBUTE_TEMPLATE_SN));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.GIVEN_NAME,
        AttributeConstants.ATTRIBUTE_TEMPLATE_GIVEN_NAME));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.DISPLAY_NAME,
        AttributeConstants.ATTRIBUTE_TEMPLATE_DISPLAY_NAME));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.DATE_OF_BIRTH,
        AttributeConstants.ATTRIBUTE_TEMPLATE_DATE_OF_BIRTH));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.STREET_ADDRESS,
        AttributeConstants.ATTRIBUTE_TEMPLATE_STREET));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.POST_OFFICE_BOX,
        AttributeConstants.ATTRIBUTE_TEMPLATE_POST_OFFICE_BOX));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.POSTAL_CODE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_POSTAL_CODE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.LOCALITY,
        AttributeConstants.ATTRIBUTE_TEMPLATE_L));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP,
        AttributeConstants.ATTRIBUTE_TEMPLATE_COUNTRY_OF_CITIZENSHIP));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.COUNTRY_OF_RESIDENCE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_COUNTRY_OF_RESIDENCE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.TELEPHONE_NUMBER,
        AttributeConstants.ATTRIBUTE_TEMPLATE_TELEPHONE_NUMBER));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.MOBILE_NUMBER,
        AttributeConstants.ATTRIBUTE_TEMPLATE_MOBILE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.EMAIL,
        AttributeConstants.ATTRIBUTE_TEMPLATE_MAIL));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.ORGANIZATION_NAME,
        AttributeConstants.ATTRIBUTE_TEMPLATE_O));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.ORGANIZATIONAL_UNIT_NAME,
        AttributeConstants.ATTRIBUTE_TEMPLATE_OU));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.ORGANIZATION_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_TEMPLATE_ORGANIZATION_IDENTIFIER));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION,
        AttributeConstants.ATTRIBUTE_TEMPLATE_ORG_AFFILIATION));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.TRANSACTION_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_TEMPLATE_TRANSACTION_IDENTIFIER));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.AUTH_CONTEXT_PARAMS,
        AttributeConstants.ATTRIBUTE_TEMPLATE_AUTH_CONTEXT_PARAMS));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.USER_CERTIFICATE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_USER_CERTIFICATE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.USER_SIGNATURE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_USER_SIGNATURE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.AUTHENTICATION_EVIDENCE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_AUTH_SERVER_SIGNATURE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.SAD,
        AttributeConstants.ATTRIBUTE_TEMPLATE_SAD));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.SIGN_MESSAGE_DIGEST,
        AttributeConstants.ATTRIBUTE_TEMPLATE_SIGNMESSAGE_DIGEST));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.PRID,
        AttributeConstants.ATTRIBUTE_TEMPLATE_PRID));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.PRID_PERSISTENCE,
        AttributeConstants.ATTRIBUTE_TEMPLATE_PRID_PERSISTENCE));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.IDENTITY_BINDING,
        AttributeConstants.ATTRIBUTE_TEMPLATE_PERSONAL_IDENTITY_NUMBER_BINDING));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_TEMPLATE_EIDAS_PERSON_IDENTIFIER));
    mappers.add(new SamlToProtocolMapper(AttributeIdentifiers.EMPLOYEE_HSA_ID,
        AttributeConstants.ATTRIBUTE_TEMPLATE_EMPLOYEE_HSA_ID));

    // Several generic attributes, one SAML attribute, where the first attribute that holds a value is used.
    //
    mappers.add(new FirstPresentSamlToProtocolMapper(AttributeConstants.ATTRIBUTE_TEMPLATE_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.COORDINATION_NUMBER));
    mappers.add(new FirstPresentSamlToProtocolMapper(
        AttributeConstants.ATTRIBUTE_TEMPLATE_PREVIOUS_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.PREVIOUS_PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.PREVIOUS_COORDINATION_NUMBER));
    mappers.add(new FirstPresentSamlToProtocolMapper(
        AttributeConstants.ATTRIBUTE_TEMPLATE_MAPPED_PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.MAPPED_COORDINATION_NUMBER));
    mappers.add(new FirstPresentSamlToProtocolMapper(AttributeConstants.ATTRIBUTE_TEMPLATE_C,
        AttributeIdentifiers.COUNTRY, AttributeIdentifiers.EIDAS_COUNTRY));

    mappers.add(new GenderToSamlMapper());
    mappers.add(new BirthNameToSamlMapper());
    mappers.add(new PlaceOfBirthToSamlMapper());
    mappers.add(new EidasAddressToSamlMapper());

    return mappers;
  }

  /**
   * Adds a mapper for a SAML attribute that maps to exactly one generic attribute.
   *
   * @param mappers the list to add to
   * @param name the SAML attribute name
   * @param identifier the generic attribute identifier
   */
  private static void simple(final @Nonnull List<FromProtocolAttributeMapper<SamlRequestedAttribute>> mappers,
      final @Nonnull String name, final @Nonnull String identifier) {
    mappers.add(new SamlFromProtocolMapper(name, identifier));
  }

}
