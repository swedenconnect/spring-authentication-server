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

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;

/**
 * Tests for {@link EidasNaturalPersonAddress}.
 *
 * @author Martin Lindström
 */
class EidasNaturalPersonAddressTest extends OpenSamlTestBase {

  /** The example from Section 3.3.3.1 of the attribute specification. */
  private static final String EXAMPLE =
      "LocatorDesignator=22;Thoroughfare=Arcacia%20Avenue;PostName=London;PostCode=SW1A%201AA";

  @Test
  void theExampleOfTheSpecificationIsParsed() {
    final Map<String, String> parts = EidasNaturalPersonAddress.parse(EXAMPLE);
    assertThat(parts).containsExactly(
        Map.entry(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, "22"),
        Map.entry(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, "Arcacia Avenue"),
        Map.entry(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London"),
        Map.entry(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE, "SW1A 1AA"));
  }

  @Test
  void theValueIsProducedByOpenSaml() {
    final Map<String, String> parts = new LinkedHashMap<>();
    parts.put(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE, "SW1A 1AA");
    parts.put(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, "Arcacia Avenue");
    parts.put(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, "22");
    parts.put(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London");

    // The pairs come out in the order of the eIDAS schema, whatever order they were put in.
    assertThat(EidasNaturalPersonAddress.format(parts)).isEqualTo(EXAMPLE);
  }

  @Test
  void allNineKeysAreKnown() {
    assertThat(EidasNaturalPersonAddress.getIdentifiers()).hasSize(9);
  }

  @Test
  void unknownKeysAndMalformedPairsAreIgnored() {
    assertThat(EidasNaturalPersonAddress.parse("Unknown=1;PostName=London;novalue;=2")).containsExactly(
        Map.entry(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London"));
    assertThat(EidasNaturalPersonAddress.format(Map.of("attribute.no-such-attribute", "x"))).isNull();
  }

  @Test
  void anEmptyValueGivesNothing() {
    assertThat(EidasNaturalPersonAddress.parse(null)).isEmpty();
    assertThat(EidasNaturalPersonAddress.parse("  ")).isEmpty();
    assertThat(EidasNaturalPersonAddress.format(Map.of())).isNull();
  }

}
