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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link GenericRequestedAttribute}.
 *
 * @author Martin Lindström
 */
class GenericRequestedAttributeTest {

  @Test
  void attributesWithDifferentIdentifiersCanNotBeMerged() {
    assertThatThrownBy(() -> GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME)
        .merge(GenericRequestedAttribute.of(AttributeIdentifiers.GIVEN_NAME)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theMergedAttributeIsEssentialIfAnyOfThemIs() {
    final GenericRequestedAttribute merged = GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME, false)
        .merge(GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME, true));

    assertThat(merged.isEssential()).isTrue();
  }

  @Test
  void theValuesOfTheFirstAttributeAreKept() {
    final GenericRequestedAttribute merged = new GenericRequestedAttribute(
        AttributeIdentifiers.SURNAME, false, List.of("Ekvall"), null)
        .merge(new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, List.of("Ek"), null));

    assertThat(merged.getRequestedValues()).isEqualTo(List.of("Ekvall"));
  }

  @Test
  void whetherTheValuesAreEssentialFollowsTheAttributeThatCarriesThem() {
    // A required attribute without values does not make voluntary values essential
    final GenericRequestedAttribute merged = GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME, true)
        .merge(new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, List.of("Ek"), null));
    assertThat(merged.isEssential()).isTrue();
    assertThat(merged.isRequestedValuesEssential()).isFalse();

    final GenericRequestedAttribute essentialValues =
        new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, true, List.of("Ek"), null)
            .merge(GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME, false));
    assertThat(essentialValues.isRequestedValuesEssential()).isTrue();
  }

  @Test
  void essentialValuesMakeTheAttributeEssentialAndNeedValues() {
    assertThat(new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, List.of("Ek"), true, null)
        .isEssential()).isTrue();
    final GenericRequestedAttribute noValues =
        new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, null, true, null);
    assertThat(noValues.isRequestedValuesEssential()).isFalse();
    assertThat(noValues.isEssential()).isFalse();
  }

  @Test
  void protocolDataIsReplacedUnlessItKnowsHowToMerge() {
    final GenericRequestedAttribute first = new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, null,
        Map.of("plain", "first", "mergeable", new Marks("a")));
    final GenericRequestedAttribute second = new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, null,
        Map.of("plain", "second", "mergeable", new Marks("b")));

    final GenericRequestedAttribute merged = first.merge(second);

    assertThat(merged.getProtocolData("plain", String.class)).isEqualTo("second");
    assertThat(merged.getProtocolData("mergeable", Marks.class)).isEqualTo(new Marks("ab"));
  }

  @Test
  void protocolDataOfOnlyOneOfThemIsKept() {
    final GenericRequestedAttribute merged =
        new GenericRequestedAttribute(AttributeIdentifiers.SURNAME, false, null, Map.of("only", new Marks("a")))
            .merge(GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME));

    assertThat(merged.getProtocolData("only", Marks.class)).isEqualTo(new Marks("a"));
  }

  /**
   * Protocol data that merges by appending.
   *
   * @param value the value
   */
  private record Marks(String value) implements MergeableProtocolData {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public @NonNull Serializable mergeWith(final @NonNull Serializable other) {
      return other instanceof final Marks marks ? new Marks(this.value + marks.value) : this;
    }
  }

}
