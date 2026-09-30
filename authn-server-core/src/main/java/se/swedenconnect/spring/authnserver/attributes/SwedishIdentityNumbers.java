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

import org.jspecify.annotations.Nullable;

/**
 * Helper for telling a Swedish personal identity number ("personnummer") from a Swedish coordination number
 * ("samordningsnummer").
 * <p>
 * Both are twelve digits on the form {@code YYYYMMDDNNNC}. A coordination number is issued with the day of the month
 * increased by 60, see SKV 707, so a day in the range 61 to 91 identifies a coordination number and a day in the range
 * 1 to 31 a personal identity number, see SKV 704.
 * </p>
 * <p>
 * The methods look at the form of the number only. They do not verify the check digit and they do not say anything
 * about whether the number has been issued.
 * </p>
 *
 * @author Martin Lindström
 */
public class SwedishIdentityNumbers {

  /**
   * Tells whether the supplied number is a Swedish coordination number.
   *
   * @param number the number to check
   * @return {@code true} if the number is a coordination number and {@code false} otherwise
   */
  public static boolean isCoordinationNumber(final @Nullable String number) {
    final int day = dayOfMonth(number);
    return day >= 61 && day <= 91;
  }

  /**
   * Tells whether the supplied number is a Swedish personal identity number.
   *
   * @param number the number to check
   * @return {@code true} if the number is a personal identity number and {@code false} otherwise
   */
  public static boolean isPersonalIdentityNumber(final @Nullable String number) {
    final int day = dayOfMonth(number);
    return day >= 1 && day <= 31;
  }

  /**
   * Extracts the day field of a twelve digit identity number.
   *
   * @param number the number
   * @return the day field, or -1 if the supplied string is not twelve digits
   */
  private static int dayOfMonth(final @Nullable String number) {
    if (number == null || number.length() != 12) {
      return -1;
    }
    for (int i = 0; i < 12; i++) {
      if (!Character.isDigit(number.charAt(i))) {
        return -1;
      }
    }
    return Integer.parseInt(number.substring(6, 8));
  }

  // Hidden constructor
  private SwedishIdentityNumbers() {
  }

}
