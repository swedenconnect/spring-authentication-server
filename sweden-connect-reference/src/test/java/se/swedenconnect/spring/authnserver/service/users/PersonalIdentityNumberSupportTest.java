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
package se.swedenconnect.spring.authnserver.service.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link PersonalIdentityNumberSupport}.
 *
 * @author Martin Lindström
 */
class PersonalIdentityNumberSupportTest {

  @Test
  void theBirthDateOfAPersonalIdentityNumber() {
    assertThat(PersonalIdentityNumberSupport.getBirthDate("197705232382")).isEqualTo(LocalDate.of(1977, 5, 23));
  }

  @Test
  void theBirthDateOfACoordinationNumber() {
    assertThat(PersonalIdentityNumberSupport.getBirthDate("197705832382")).isEqualTo(LocalDate.of(1977, 5, 23));
  }

  @Test
  void invalidNumbersAreRejected() {
    assertThatThrownBy(() -> PersonalIdentityNumberSupport.getBirthDate("7705232382"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PersonalIdentityNumberSupport.getBirthDate("197713232382"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PersonalIdentityNumberSupport.getBirthDate("1977ab232382"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void coordinationNumbersAreRecognized() {
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("197705832382")).isTrue();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("197705612382")).isTrue();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("197705602382")).isFalse();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("197705232382")).isFalse();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("7705832382")).isFalse();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber("197705xx2382")).isFalse();
    assertThat(PersonalIdentityNumberSupport.isCoordinationNumber(null)).isFalse();
  }

}
