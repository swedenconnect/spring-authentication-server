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

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants;
import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeUtils;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentFamilyNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;

/**
 * Tests for {@link SamlAttributeValues}.
 *
 * @author Martin Lindström
 */
class SamlAttributeValuesTest extends OpenSamlTestBase {

  /**
   * Creates an eIDAS family name value.
   *
   * @param name the name
   * @param latinScript the value of the {@code LatinScript} attribute, or {@code null} to leave it out
   * @return a {@link CurrentFamilyNameType}
   */
  private static CurrentFamilyNameType familyName(final String name, final Boolean latinScript) {
    final CurrentFamilyNameType value = AttributeUtils.createAttributeValueObject(
        CurrentFamilyNameType.TYPE_NAME, CurrentFamilyNameType.class);
    value.setValue(name);
    if (latinScript != null) {
      value.setLatinScript(latinScript);
    }
    return value;
  }

  private static Attribute attributeWith(final TransliterationStringType... values) {
    final Attribute attribute = AttributeUtils.createAttribute(
        AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
        AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME);
    for (final TransliterationStringType value : values) {
      AttributeUtils.addAttributeValue(attribute, value);
    }
    return attribute;
  }

  @Test
  void aValueThatIsNotLatinScriptIsDropped() {
    // Section 3.3.3 of the attribute specification: values with LatinScript false are not part of the result.
    assertThat(SamlAttributeValues.getStringValues(
        attributeWith(familyName("Γκούντης", false))))
        .isEmpty();
  }

  @Test
  void aLatinScriptValueIsKept() {
    assertThat(SamlAttributeValues.getStringValues(attributeWith(familyName("Onasis", true))))
        .containsExactly("Onasis");
  }

  @Test
  void aValueWithoutTheLatinScriptAttributeIsKept() {
    assertThat(SamlAttributeValues.getStringValues(attributeWith(familyName("Onasis", null))))
        .containsExactly("Onasis");
  }

  @Test
  void onlyTheLatinScriptValueSurvivesWhenBothAreGiven() {
    assertThat(SamlAttributeValues.getStringValues(attributeWith(
        familyName("Onasis", true),
        familyName("Γκούντης", false))))
        .containsExactly("Onasis");
  }

  @Test
  void plainStringValuesAreRead() {
    assertThat(SamlAttributeValues.getStringValues(
        SamlAttributeValues.createAttribute("urn:oid:2.5.4.4", "sn", List.of("Lindeman"))))
        .containsExactly("Lindeman");
  }

  @Test
  void noAttributeGivesNoValues() {
    assertThat(SamlAttributeValues.getStringValues(null)).isEmpty();
  }

}
