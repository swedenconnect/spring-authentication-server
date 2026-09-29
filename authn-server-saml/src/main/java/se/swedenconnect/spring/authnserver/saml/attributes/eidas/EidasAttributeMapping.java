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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.DefaultAttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping.EidasAddressToProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping.EidasGenderFromProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping.EidasGenderToProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping.EidasToProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.EidasAddressFromProtocolMapper;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.SamlFromProtocolMapper;

/**
 * The mapping between the protocol-neutral attribute model and the eIDAS attributes for natural persons.
 * <p>
 * This is what an eIDAS Proxy Service uses. It reads the requested attributes of an eIDAS authentication request and
 * produces the eIDAS attributes of the assertion it issues. A server that speaks the Swedish eID Framework instead
 * uses {@link se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping}, and the two are kept apart
 * because the same generic attribute maps to a different attribute in each of them.
 * </p>
 * <p>
 * Only the attributes for natural persons are supported, see {@link EidasNaturalPersonAttributes}. There is no
 * OpenID Connect counterpart to this mapping, since eIDAS attributes belong to SAML.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasAttributeMapping {

  /** Maps eIDAS requested attributes into the generic form. */
  private final FromProtocolAttributeMapping<SamlRequestedAttribute> fromProtocolMapping;

  /** Maps generic attributes into eIDAS attributes. */
  private final ToProtocolAttributeMapping<Attribute> toProtocolMapping;

  /**
   * Default constructor using the built-in attribute definitions and the built-in mappers.
   */
  public EidasAttributeMapping() {
    this(new DefaultAttributeDefinitionRegistry(), true);
  }

  /**
   * Constructor using the built-in mappers.
   *
   * @param definitions the attribute definitions to use
   */
  public EidasAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions) {
    this(definitions, true);
  }

  /**
   * Constructor.
   *
   * @param definitions the attribute definitions to use
   * @param registerBuiltInMappers whether to register the built-in mappers
   */
  public EidasAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions,
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
   * Maps eIDAS requested attributes into the generic form.
   *
   * @param requestedAttributes the eIDAS requested attributes
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGeneric(
      final @Nonnull List<SamlRequestedAttribute> requestedAttributes) {
    return this.fromProtocolMapping.map(requestedAttributes);
  }

  /**
   * Maps the requested attributes of the eIDAS {@code RequestedAttributes} extension into the generic form.
   *
   * @param requestedAttributes the eIDAS requested attributes
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> toGenericFromRequestedAttributes(
      final @Nonnull List<? extends RequestedAttribute> requestedAttributes) {
    final List<SamlRequestedAttribute> inputs = new ArrayList<>(requestedAttributes.size());
    requestedAttributes.forEach(a -> inputs.add(SamlRequestedAttribute.of(a)));
    return this.toGeneric(inputs);
  }

  /**
   * Maps generic attributes into eIDAS attributes.
   *
   * @param attributes the attributes to map
   * @param requestedAttributes the requested attributes of the operation, may be {@code null}
   * @return the eIDAS attributes
   */
  public @Nonnull List<Attribute> toEidas(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nullable List<GenericRequestedAttribute> requestedAttributes) {
    return this.toProtocolMapping.map(attributes, requestedAttributes);
  }

  /**
   * Gets the mapping from eIDAS requested attributes into the generic form. Use it to register mappers of your own.
   *
   * @return a {@link FromProtocolAttributeMapping}
   */
  public @Nonnull FromProtocolAttributeMapping<SamlRequestedAttribute> getFromProtocolMapping() {
    return this.fromProtocolMapping;
  }

  /**
   * Gets the mapping from generic attributes into eIDAS attributes. Use it to register mappers of your own.
   *
   * @return a {@link ToProtocolAttributeMapping}
   */
  public @Nonnull ToProtocolAttributeMapping<Attribute> getToProtocolMapping() {
    return this.toProtocolMapping;
  }

  /**
   * Gets the built-in mappers from eIDAS requested attributes into the generic form.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<FromProtocolAttributeMapper<SamlRequestedAttribute>> getBuiltInFromProtocolMappers() {
    final List<FromProtocolAttributeMapper<SamlRequestedAttribute>> mappers = new ArrayList<>();

    // One eIDAS attribute, one generic attribute.
    //
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.PERSON_IDENTIFIER.name(),
        AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.CURRENT_FAMILY_NAME.name(),
        AttributeIdentifiers.SURNAME));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.CURRENT_GIVEN_NAME.name(),
        AttributeIdentifiers.GIVEN_NAME));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.DATE_OF_BIRTH.name(),
        AttributeIdentifiers.DATE_OF_BIRTH));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.BIRTH_NAME.name(),
        AttributeIdentifiers.BIRTH_NAME));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.PLACE_OF_BIRTH.name(),
        AttributeIdentifiers.PLACE_OF_BIRTH));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.COUNTRY_OF_BIRTH.name(),
        AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.TOWN_OF_BIRTH.name(),
        AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.NATIONALITY.name(),
        AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.COUNTRY_OF_RESIDENCE.name(),
        AttributeIdentifiers.COUNTRY_OF_RESIDENCE));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.PHONE_NUMBER.name(),
        AttributeIdentifiers.TELEPHONE_NUMBER));
    mappers.add(new SamlFromProtocolMapper(EidasNaturalPersonAttributes.EMAIL_ADDRESS.name(),
        AttributeIdentifiers.EMAIL));

    // The address becomes the nine attributes that its parts are, and the gender values need converting.
    //
    mappers.add(new EidasAddressFromProtocolMapper(EidasNaturalPersonAttributes.CURRENT_ADDRESS.name()));
    mappers.add(new EidasGenderFromProtocolMapper());

    return mappers;
  }

  /**
   * Gets the built-in mappers from generic attributes into eIDAS attributes.
   *
   * @return the built-in mappers
   */
  public static @Nonnull List<ToProtocolAttributeMapper<Attribute>> getBuiltInToProtocolMappers() {
    final List<ToProtocolAttributeMapper<Attribute>> mappers = new ArrayList<>();

    // One generic attribute, one eIDAS attribute.
    //
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER,
        EidasNaturalPersonAttributes.PERSON_IDENTIFIER));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.SURNAME,
        EidasNaturalPersonAttributes.CURRENT_FAMILY_NAME));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.GIVEN_NAME,
        EidasNaturalPersonAttributes.CURRENT_GIVEN_NAME));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.DATE_OF_BIRTH,
        EidasNaturalPersonAttributes.DATE_OF_BIRTH));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.BIRTH_NAME,
        EidasNaturalPersonAttributes.BIRTH_NAME));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.PLACE_OF_BIRTH,
        EidasNaturalPersonAttributes.PLACE_OF_BIRTH));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY,
        EidasNaturalPersonAttributes.COUNTRY_OF_BIRTH));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY,
        EidasNaturalPersonAttributes.TOWN_OF_BIRTH));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP,
        EidasNaturalPersonAttributes.NATIONALITY));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.COUNTRY_OF_RESIDENCE,
        EidasNaturalPersonAttributes.COUNTRY_OF_RESIDENCE));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.TELEPHONE_NUMBER,
        EidasNaturalPersonAttributes.PHONE_NUMBER));
    mappers.add(new EidasToProtocolMapper(AttributeIdentifiers.EMAIL,
        EidasNaturalPersonAttributes.EMAIL_ADDRESS));

    // The address is built from the nine attributes that its parts are, and the gender values need converting.
    //
    mappers.add(new EidasAddressToProtocolMapper());
    mappers.add(new EidasGenderToProtocolMapper());

    return mappers;
  }

}
