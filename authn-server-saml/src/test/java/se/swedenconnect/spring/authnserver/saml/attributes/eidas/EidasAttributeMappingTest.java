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

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.eidas.ext.RequestedAttribute;
import se.swedenconnect.opensaml.eidas.ext.RequestedAttributeTemplates;
import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeUtils;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderTypeEnumeration;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.mapping.EidasToProtocolMapper;

/**
 * Tests for {@link EidasAttributeMapping}.
 *
 * @author Martin Lindström
 */
class EidasAttributeMappingTest extends OpenSamlTestBase {

  private EidasAttributeMapping mapping;

  @BeforeEach
  void setup() {
    this.mapping = new EidasAttributeMapping();
  }

  private List<String> identifiers(final List<GenericRequestedAttribute> attributes) {
    return attributes.stream().map(GenericRequestedAttribute::getIdentifier).toList();
  }

  private Attribute find(final List<Attribute> attributes, final String name) {
    return attributes.stream().filter(a -> a.getName().equals(name)).findFirst().orElse(null);
  }

  private <T> T valueOf(final List<Attribute> attributes, final EidasAttributeTemplate template,
      final Class<T> type) {
    final Attribute attribute = this.find(attributes, template.name());
    assertThat(attribute).as("attribute %s", template.friendlyName()).isNotNull();
    return type.cast(attribute.getAttributeValues().get(0));
  }

  // ---- From eIDAS ----

  @Test
  void theRequestedAttributesOfTheMinimumDataSetAreMapped() {
    final List<RequestedAttribute> requested = List.of(
        RequestedAttributeTemplates.PERSON_IDENTIFIER(true, true),
        RequestedAttributeTemplates.CURRENT_FAMILY_NAME(true, true),
        RequestedAttributeTemplates.CURRENT_GIVEN_NAME(true, true),
        RequestedAttributeTemplates.DATE_OF_BIRTH(true, true));

    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(requested);
    assertThat(this.identifiers(result)).containsExactlyInAnyOrder(
        AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER, AttributeIdentifiers.SURNAME,
        AttributeIdentifiers.GIVEN_NAME, AttributeIdentifiers.DATE_OF_BIRTH);
    assertThat(result).allMatch(GenericRequestedAttribute::isEssential);
  }

  @Test
  void aRequestedCurrentAddressBecomesAllItsParts() {
    assertThat(this.identifiers(this.mapping.toGenericFromRequestedAttributes(
        List.of(RequestedAttributeTemplates.CURRENT_ADDRESS(false, false)))))
        .hasSize(9)
        .contains(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE);
  }

  @Test
  void anAttributeThatIsNotAnEidasNaturalPersonAttributeIsLeftOut() {
    // A legal person attribute is not supported.
    final RequestedAttribute legalPerson = RequestedAttributeTemplates.create(
        "http://eidas.europa.eu/attributes/legalperson/LegalName", "LegalName", Attribute.URI_REFERENCE, true);
    assertThat(this.mapping.toGenericFromRequestedAttributes(List.of(legalPerson))).isEmpty();
  }

  @Test
  void aSwedishEidAttributeIsLeftOut() {
    // This mapping speaks eIDAS only.
    assertThat(this.mapping.toGenericFromRequestedAttributes(
        List.of(RequestedAttributeTemplates.create("urn:oid:2.5.4.4", "sn", Attribute.URI_REFERENCE, true))))
        .isEmpty();
  }

  // ---- To eIDAS ----

  @Test
  void aNameBecomesATransliterationStringValue() {
    final List<Attribute> result = this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Onasis")), null);
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, EidasNaturalPersonAttributes.CURRENT_FAMILY_NAME.name())))
        .containsExactly("Onasis");
  }

  @Test
  void theDateOfBirthBecomesATypedDate() {
    final DateOfBirthType value = this.valueOf(
        this.mapping.toEidas(
            List.of(GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, LocalDate.of(1950, 6, 26))), null),
        EidasNaturalPersonAttributes.DATE_OF_BIRTH, DateOfBirthType.class);
    assertThat(value.getDate()).isEqualTo(LocalDate.of(1950, 6, 26));
  }

  @Test
  void theGenderBecomesTheEidasEnumeration() {
    assertThat(this.valueOf(this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "female")), null),
        EidasNaturalPersonAttributes.GENDER, GenderType.class).getGender())
        .isEqualTo(GenderTypeEnumeration.FEMALE);

    // eIDAS, unlike the Swedish eID Framework in OpenID Connect, has a value for an unspecified gender.
    assertThat(this.valueOf(this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "u")), null),
        EidasNaturalPersonAttributes.GENDER, GenderType.class).getGender())
        .isEqualTo(GenderTypeEnumeration.UNSPECIFIED);

    assertThat(this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "unknown-value")), null)).isEmpty();
  }

  @Test
  void theAddressPartsBecomeATypedCurrentAddress() {
    final CurrentAddressType address = this.valueOf(this.mapping.toEidas(List.of(
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, "22"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, "Arcacia Avenue"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE, "SW1A 1AA")), null),
        EidasNaturalPersonAttributes.CURRENT_ADDRESS, CurrentAddressType.class);

    assertThat(address.getLocatorDesignator()).isEqualTo("22");
    assertThat(address.getThoroughfare()).isEqualTo("Arcacia Avenue");
    assertThat(address.getPostName()).isEqualTo("London");
    assertThat(address.getPostCode()).isEqualTo("SW1A 1AA");
  }

  @Test
  void theNationalitiesKeepAllValues() {
    final Attribute attribute = this.find(this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP, List.of("SE", "NO"))), null),
        EidasNaturalPersonAttributes.NATIONALITY.name());
    assertThat(SamlAttributeValues.getStringValues(attribute)).containsExactly("SE", "NO");
  }

  @Test
  void theBirthPlacePartsBecomeSeparateEidasAttributes() {
    final List<Attribute> result = this.mapping.toEidas(List.of(
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH, "Stockholm, SE"),
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY, "SE"),
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY, "Stockholm")), null);

    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, EidasNaturalPersonAttributes.PLACE_OF_BIRTH.name())))
        .containsExactly("Stockholm, SE");
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, EidasNaturalPersonAttributes.COUNTRY_OF_BIRTH.name())))
        .containsExactly("SE");
    assertThat(SamlAttributeValues.getStringValues(
        this.find(result, EidasNaturalPersonAttributes.TOWN_OF_BIRTH.name())))
        .containsExactly("Stockholm");
  }

  @Test
  void anAttributeThatHasNoEidasCounterpartIsLeftOut() {
    assertThat(this.mapping.toEidas(List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "195006262546"),
        GenericAttribute.of(AttributeIdentifiers.ORGANIZATION_NAME, "Skatteverket"),
        GenericAttribute.of(AttributeIdentifiers.PRID, "NO:5068907693"),
        GenericAttribute.of(AttributeIdentifiers.DISPLAY_NAME, "Valfrid Lindeman")), null))
        .isEmpty();
  }

  @Test
  void aValueThatDoesNotFitTheTypeIsLeftOut() {
    assertThat(this.mapping.toEidas(
        List.of(GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, "not-a-date")), null)).isEmpty();
  }

  @Test
  void aRequestedAddressCarryingAValueIsSplitIntoItsParts() {
    final CurrentAddressType address =
        AttributeUtils.createAttributeValueObject(CurrentAddressType.TYPE_NAME, CurrentAddressType.class);
    address.setPostName("London");
    address.setPostCode("SW1A 1AA");

    final RequestedAttribute requested = RequestedAttributeTemplates.CURRENT_ADDRESS(true, true);
    requested.getAttributeValues().add(address);

    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromRequestedAttributes(List.of(requested));
    assertThat(result).hasSize(2);
    assertThat(result).anySatisfy(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME);
      assertThat(a.getRequestedValues()).isEqualTo(List.of("London"));
    });
    assertThat(result).anySatisfy(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE);
      assertThat(a.getRequestedValues()).isEqualTo(List.of("SW1A 1AA"));
    });
  }

  @Test
  void allFourteenNaturalPersonAttributesAreKnown() {
    assertThat(EidasNaturalPersonAttributes.getAll()).hasSize(14);
    assertThat(EidasNaturalPersonAttributes.get(EidasNaturalPersonAttributes.GENDER.name()))
        .isEqualTo(EidasNaturalPersonAttributes.GENDER);
    assertThat(EidasNaturalPersonAttributes.get("http://eidas.europa.eu/attributes/legalperson/LegalName")).isNull();
  }

  @Test
  void anApplicationCanAddAMapperForAnAttributeOfItsOwn() {
    final EidasAttributeTemplate template = new EidasAttributeTemplate(
        "http://example.com/attributes/naturalperson/EmployeeNumber", "EmployeeNumber",
        XSString.TYPE_NAME, XSString.class);
    this.mapping.getToProtocolMapping().register(
        new EidasToProtocolMapper("attribute.employee-number", template));

    assertThat(SamlAttributeValues.getStringValues(this.find(this.mapping.toEidas(
        List.of(GenericAttribute.of("attribute.employee-number", "4711")), null), template.name())))
        .containsExactly("4711");
  }

}
