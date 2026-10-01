/*
 * Copyright 2016-2026 Sweden Connect
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

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Support functions for handling Swedish personal identity numbers and coordination numbers.
 *
 * @author Martin Lindström
 */
public final class PersonalIdentityNumberSupport {

  /**
   * Tells whether the supplied number is a Swedish coordination number (samordningsnummer), that is, a 12-digit
   * number whose day of birth has 60 added to it.
   *
   * @param id the personal identity number
   * @return {@code true} if the number is a coordination number and {@code false} otherwise
   */
  public static boolean isCoordinationNumber(final @Nullable String id) {
    if (id == null || id.length() != 12) {
      return false;
    }
    try {
      final int day = Integer.parseInt(id.substring(6, 8));
      return day >= 61;
    }
    catch (final NumberFormatException e) {
      return false;
    }
  }

  /**
   * Gets the date of birth from a 12-digit Swedish personal identity number or coordination number.
   *
   * @param personalIdentityNumber the personal identity number
   * @return the date of birth
   * @throws IllegalArgumentException if the number does not hold a valid date
   */
  public static @NonNull LocalDate getBirthDate(final @NonNull String personalIdentityNumber) {
    Objects.requireNonNull(personalIdentityNumber, "personalIdentityNumber must not be null");
    if (personalIdentityNumber.length() != 12) {
      throw new IllegalArgumentException("A personal identity number must have 12 digits");
    }
    try {
      final int day = Integer.parseInt(personalIdentityNumber.substring(6, 8));
      return LocalDate.parse("%s-%s-%02d".formatted(personalIdentityNumber.substring(0, 4),
          personalIdentityNumber.substring(4, 6), day > 60 ? day - 60 : day));
    }
    catch (final NumberFormatException | DateTimeParseException e) {
      throw new IllegalArgumentException("Invalid personal identity number", e);
    }
  }

  // Hidden constructor
  private PersonalIdentityNumberSupport() {
  }

}
