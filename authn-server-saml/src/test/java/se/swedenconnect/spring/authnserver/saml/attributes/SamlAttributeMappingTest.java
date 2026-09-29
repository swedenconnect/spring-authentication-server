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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;

import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;

/**
 * Tests for {@link SamlAttributeMapping}.
 *
 * @author Martin Lindström
 */
class SamlAttributeMappingTest extends OpenSamlTestBase {

  private SamlAttributeMapping mapping;

  @BeforeEach
  void setup() {
    this.mapping = new SamlAttributeMapping();
  }

  /**
   * Creates a SAML requested attribute of the metadata kind.
   *
   * @param name the attribute name
   * @param required whether the attribute is required
   * @param values the values, if any
   * @return a {@link RequestedAttribute}
   */
  private static RequestedAttribute requested(final String name, final boolean required, final String... values) {
    final RequestedAttribute attribute = (RequestedAttribute) XMLObjectProviderRegistrySupport
        .getBuilderFactory()
        .getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME)
        .buildObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
    attribute.setName(name);
    attribute.setNameFormat(Attribute.URI_REFERENCE);
    attribute.setIsRequired(required);
    for (final String value : values) {
      final XSString stringValue = (XSString) XMLObjectProviderRegistrySupport.getBuilderFactory()
          .getBuilder(XSString.TYPE_NAME)
          .buildObject(Attribute.DEFAULT_ELEMENT_NAME.getNamespaceURI(), "AttributeValue", "saml2");
      stringValue.setValue(value);
      attribute.getAttributeValues().add(stringValue);
    }
    return attribute;
  }

  private List<String> identifiers(final List<GenericRequestedAttribute> attributes) {
    return attributes.stream().map(GenericRequestedAttribute::getIdentifier).toList();
  }

  private Attribute find(final List<Attribute> attributes, final String name) {
    return attributes.stream().filter(a -> a.getName().equals(name)).findFirst().orElse(null);
  }

  // ---- From SAML ----

  @Test
  void aSimpleRequestedAttributeIsMapped() {
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_SN, true)));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.SURNAME);
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getRequestedValues()).isEmpty();
    });
  }

  @Test
  void aRequestedPersonalIdentityNumberBecomesBothKindsOfNumber() {
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, true)));

    assertThat(this.identifiers(result)).containsExactlyInAnyOrder(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.COORDINATION_NUMBER);
  }

  @Test
  void aRequestedIdentityNumberWithAValueBecomesTheKindThatTheValueIs() {
    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(List.of(
        requested(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, false, "195006262546")))))
        .containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);

    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(List.of(
        requested(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, false, "197010632391")))))
        .containsExactly(AttributeIdentifiers.COORDINATION_NUMBER);
  }

  @Test
  void aRequestedBirthNameBecomesTheFullNameAndItsParts() {
    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME, false)))))
        .containsExactlyInAnyOrder(AttributeIdentifiers.BIRTH_NAME, AttributeIdentifiers.BIRTH_FAMILY_NAME,
            AttributeIdentifiers.BIRTH_GIVEN_NAME, AttributeIdentifiers.BIRTH_MIDDLE_NAME);
  }

  @Test
  void aRequestedEidasAddressBecomesAllItsParts() {
    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_EIDAS_NATURAL_PERSON_ADDRESS, false)))))
        .hasSize(9)
        .contains(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE);
  }

  @Test
  void aRequestedAttributeThatNoMapperHandlesIsLeftOut() {
    assertThat(this.mapping.toGenericFromRequestedAttributes(
        List.of(requested("urn:oid:1.2.3.4.5", true)))).isEmpty();
  }

  @Test
  void theSameAttributeRequestedTwiceIsEssentialIfOneOfThemSaidSo() {
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(List.of(
        requested(AttributeConstants.ATTRIBUTE_NAME_SN, false),
        requested(AttributeConstants.ATTRIBUTE_NAME_SN, true)));
    assertThat(result).singleElement().matches(GenericRequestedAttribute::isEssential);
  }

  @Test
  void aRequestedDateOfBirthValueBecomesADate() {
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, false, "1950-06-26")));
    assertThat(result).singleElement()
        .extracting(a -> a.getRequestedValues().get(0))
        .isEqualTo(LocalDate.of(1950, 6, 26));
  }

  @Test
  void aRequestedGenderValueIsConverted() {
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(
        List.of(requested(AttributeConstants.ATTRIBUTE_NAME_GENDER, false, "M")));
    assertThat(result).singleElement()
        .extracting(a -> a.getRequestedValues().get(0))
        .isEqualTo("male");
  }

  // ---- To SAML ----

  @Test
  void aSimpleAttributeIsMapped() {
    final List<Attribute> result = this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Lindeman")), null);
    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getName()).isEqualTo(AttributeConstants.ATTRIBUTE_NAME_SN);
      assertThat(a.getFriendlyName()).isEqualTo(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN);
      assertThat(SamlAttributeValues.getStringValues(a)).containsExactly("Lindeman");
    });
  }

  @Test
  void aMultiValuedAttributeKeepsAllValues() {
    final List<Attribute> result = this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.EMAIL, List.of("a@example.com", "b@example.com"))), null);
    assertThat(SamlAttributeValues.getStringValues(result.get(0)))
        .containsExactly("a@example.com", "b@example.com");
  }

  @Test
  void aDateIsWrittenInIsoForm() {
    final List<Attribute> result = this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, LocalDate.of(1950, 6, 26))), null);
    assertThat(SamlAttributeValues.getStringValues(result.get(0))).containsExactly("1950-06-26");
  }

  @Test
  void eitherKindOfIdentityNumberIsReleasedAsPersonalIdentityNumber() {
    assertThat(SamlAttributeValues.getStringValues(this.find(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.COORDINATION_NUMBER, "197010632391")), null),
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)))
        .containsExactly("197010632391");

    assertThat(SamlAttributeValues.getStringValues(this.find(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "195006262546")), null),
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)))
        .containsExactly("195006262546");
  }

  @Test
  void thePersonalIdentityNumberWinsOverTheCoordinationNumber() {
    final List<Attribute> result = this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "195006262546"),
        GenericAttribute.of(AttributeIdentifiers.COORDINATION_NUMBER, "197010632391")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)))
        .containsExactly("195006262546");
  }

  @Test
  void theFullBirthNameIsUsedWhenItIsKnown() {
    final List<Attribute> result = this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.BIRTH_NAME, "Valfrid Danielsson"),
        GenericAttribute.of(AttributeIdentifiers.BIRTH_FAMILY_NAME, "Danielsson")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME)))
        .containsExactly("Valfrid Danielsson");
  }

  @Test
  void theBirthNamePartsAreJoinedWhenTheFullNameIsMissing() {
    final List<Attribute> result = this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.BIRTH_FAMILY_NAME, "Danielsson"),
        GenericAttribute.of(AttributeIdentifiers.BIRTH_GIVEN_NAME, "Valfrid")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME)))
        .containsExactly("Valfrid Danielsson");
  }

  @Test
  void thePlaceOfBirthPartsAreJoinedWhenTheFreeTextIsMissing() {
    final List<Attribute> result = this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY, "SE"),
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY, "Stockholm")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, AttributeConstants.ATTRIBUTE_NAME_PLACE_OF_BIRTH)))
        .containsExactly("Stockholm, SE");
  }

  @Test
  void theCountryIsTakenFromTheEidasCountryWhenNoCountryIsKnown() {
    assertThat(SamlAttributeValues.getStringValues(this.find(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.EIDAS_COUNTRY, "NO")), null),
        AttributeConstants.ATTRIBUTE_NAME_C)))
        .containsExactly("NO");

    assertThat(SamlAttributeValues.getStringValues(this.find(this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.COUNTRY, "SE"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_COUNTRY, "NO")), null),
        AttributeConstants.ATTRIBUTE_NAME_C)))
        .containsExactly("SE");
  }

  @Test
  void theGenderValueIsConverted() {
    assertThat(SamlAttributeValues.getStringValues(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "female")), null).get(0)))
        .containsExactly("F");
    assertThat(SamlAttributeValues.getStringValues(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "u")), null).get(0)))
        .containsExactly("U");
    assertThat(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "unknown-value")), null)).isEmpty();
  }

  @Test
  void theEidasAddressPartsBecomeOneAttribute() {
    final List<Attribute> result = this.mapping.toSaml(List.of(
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, "22")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, AttributeConstants.ATTRIBUTE_NAME_EIDAS_NATURAL_PERSON_ADDRESS)))
        .containsExactly("LocatorDesignator=22;PostName=London");
  }

  @Test
  void anAttributeThatNoMapperHandlesIsLeftOut() {
    assertThat(this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.NICKNAME, "Valle")), null)).isEmpty();
    assertThat(this.mapping.toSaml(
        List.of(GenericAttribute.of("attribute.employee-number", "4711")), null)).isEmpty();
  }

  @Test
  void anApplicationCanReplaceABuiltInMapper() {
    final AttributeTemplate template = new AttributeTemplate("urn:oid:1.2.3.4", "employeeNumber");
    this.mapping.getToProtocolMapping().register(new ToProtocolAttributeMapper<Attribute>() {

      @Override
      public Collection<String> getSupportedIdentifiers() {
        return List.of(AttributeIdentifiers.SURNAME);
      }

      @Override
      public List<Attribute> map(final List<GenericAttribute<? extends Serializable>> attributes,
          final ToProtocolMappingContext context) {
        return List.of(SamlAttributeValues.createAttribute(template.getName(), template.getFriendlyName(),
            List.of(attributes.get(0).getStringValues().get(0).toUpperCase())));
      }
    });

    final List<Attribute> result = this.mapping.toSaml(
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Lindeman")), null);
    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getName()).isEqualTo("urn:oid:1.2.3.4");
      assertThat(SamlAttributeValues.getStringValues(a)).containsExactly("LINDEMAN");
    });
  }

  @Test
  void anApplicationCanAddAMapperForAnAttributeOfItsOwn() {
    final AttributeTemplate template = new AttributeTemplate("urn:oid:1.2.3.4", "employeeNumber");
    this.mapping.getToProtocolMapping().register(
        new se.swedenconnect.spring.authnserver.saml.attributes.mapping.SamlToProtocolMapper(
            "attribute.employee-number", template));
    this.mapping.getFromProtocolMapping().register(
        new se.swedenconnect.spring.authnserver.saml.attributes.mapping.SamlFromProtocolMapper(
            "urn:oid:1.2.3.4", "attribute.employee-number"));

    assertThat(this.mapping.toSaml(
        List.of(GenericAttribute.of("attribute.employee-number", "4711")), null))
        .singleElement()
        .extracting(Attribute::getName)
        .isEqualTo("urn:oid:1.2.3.4");
    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(
        List.of(requested("urn:oid:1.2.3.4", true)))))
        .containsExactly("attribute.employee-number");
  }

}
