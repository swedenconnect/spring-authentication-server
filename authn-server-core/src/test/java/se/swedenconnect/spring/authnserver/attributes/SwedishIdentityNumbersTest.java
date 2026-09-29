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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for {@link SwedishIdentityNumbers}.
 *
 * @author Martin Lindström
 */
class SwedishIdentityNumbersTest {

  @ParameterizedTest
  @ValueSource(strings = { "195006262546", "198001019876" })
  void personalIdentityNumbersAreRecognized(final String number) {
    assertThat(SwedishIdentityNumbers.isPersonalIdentityNumber(number)).isTrue();
    assertThat(SwedishIdentityNumbers.isCoordinationNumber(number)).isFalse();
  }

  @ParameterizedTest
  @ValueSource(strings = { "195006862546", "196102910007", "200012610009", "197010632391" })
  void coordinationNumbersAreRecognized(final String number) {
    assertThat(SwedishIdentityNumbers.isCoordinationNumber(number)).isTrue();
    assertThat(SwedishIdentityNumbers.isPersonalIdentityNumber(number)).isFalse();
  }

  @Test
  void theDayBoundariesHold() {
    // Day 31 is the last day of a personal identity number and day 61 the first of a coordination number.
    assertThat(SwedishIdentityNumbers.isPersonalIdentityNumber("195006312546")).isTrue();
    assertThat(SwedishIdentityNumbers.isCoordinationNumber("195006612546")).isTrue();
    assertThat(SwedishIdentityNumbers.isCoordinationNumber("195006912546")).isTrue();

    // Days in between, and above, belong to neither.
    assertThat(SwedishIdentityNumbers.isPersonalIdentityNumber("195006452546")).isFalse();
    assertThat(SwedishIdentityNumbers.isCoordinationNumber("195006452546")).isFalse();
    assertThat(SwedishIdentityNumbers.isCoordinationNumber("195006922546")).isFalse();
  }

  @Test
  void malformedNumbersBelongToNeither() {
    final String[] malformed =
        { null, "", "5006262546", "19500626254", "1950062625461", "abcdefghijkl" };
    for (final String number : malformed) {
      assertThat(SwedishIdentityNumbers.isPersonalIdentityNumber(number)).isFalse();
      assertThat(SwedishIdentityNumbers.isCoordinationNumber(number)).isFalse();
    }
  }

}
