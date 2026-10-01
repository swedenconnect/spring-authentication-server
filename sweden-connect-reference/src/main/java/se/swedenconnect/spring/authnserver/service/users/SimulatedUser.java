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

import java.io.Serial;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A simulated user: one of the users of {@code users.yml}, or a user that the tester has entered.
 *
 * @author Martin Lindström
 */
public class SimulatedUser implements Serializable, Comparable<SimulatedUser> {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Separates the fields of an encoded user. */
  private static final String FIELD_SEPARATOR = "#";

  /** Separates the users of an encoded list. */
  private static final String USER_SEPARATOR = ":::";

  /** The personal identity number. */
  private String personalNumber;

  /** The given name. */
  private String givenName;

  /** The surname. */
  private String surname;

  /** The display name. */
  private String displayName;

  /** The date of birth (YYYY-MM-DD). */
  private String dateOfBirth;

  /**
   * Gets the personal identity number.
   *
   * @return the personal identity number
   */
  public @Nullable String getPersonalNumber() {
    return this.personalNumber;
  }

  /**
   * Assigns the personal identity number.
   *
   * @param personalNumber the personal identity number
   */
  public void setPersonalNumber(final @Nullable String personalNumber) {
    this.personalNumber = personalNumber;
  }

  /**
   * Gets the given name.
   *
   * @return the given name
   */
  public @Nullable String getGivenName() {
    return this.givenName;
  }

  /**
   * Assigns the given name.
   *
   * @param givenName the given name
   */
  public void setGivenName(final @Nullable String givenName) {
    this.givenName = givenName;
  }

  /**
   * Gets the surname.
   *
   * @return the surname
   */
  public @Nullable String getSurname() {
    return this.surname;
  }

  /**
   * Assigns the surname.
   *
   * @param surname the surname
   */
  public void setSurname(final @Nullable String surname) {
    this.surname = surname;
  }

  /**
   * Gets the display name. If not assigned, it is the given name followed by the surname.
   *
   * @return the display name
   */
  public @NonNull String getDisplayName() {
    return this.displayName != null ? this.displayName : "%s %s".formatted(this.givenName, this.surname);
  }

  /**
   * Assigns the display name.
   *
   * @param displayName the display name
   */
  public void setDisplayName(final @Nullable String displayName) {
    this.displayName = displayName;
  }

  /**
   * Gets the date of birth (YYYY-MM-DD). If not assigned, it is derived from the personal identity number.
   *
   * @return the date of birth, or {@code null} if it is not assigned and cannot be derived
   */
  public @Nullable String getDateOfBirth() {
    if (this.dateOfBirth == null && this.personalNumber != null) {
      try {
        return PersonalIdentityNumberSupport.getBirthDate(this.personalNumber).toString();
      }
      catch (final IllegalArgumentException e) {
        return null;
      }
    }
    return this.dateOfBirth;
  }

  /**
   * Assigns the date of birth (YYYY-MM-DD).
   *
   * @param dateOfBirth the date of birth
   */
  public void setDateOfBirth(final @Nullable String dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
  }

  /**
   * Gets the text that the user picker shows for the user.
   *
   * @return the text to show
   */
  public @NonNull String toViewString() {
    return "%s (%s)".formatted(this.getDisplayName(), this.personalNumber);
  }

  /**
   * Users are sorted by surname, and users without a surname come last.
   */
  @Override
  public int compareTo(final @NonNull SimulatedUser o) {
    if (this.surname != null && o.surname != null) {
      return this.surname.compareTo(o.surname);
    }
    if (this.surname == null && o.surname == null) {
      return 0;
    }
    return this.surname == null ? 1 : -1;
  }

  /**
   * Encodes the user for a cookie.
   *
   * @return the encoded user
   */
  public @NonNull String encode() {
    return URLEncoder.encode(String.join(FIELD_SEPARATOR, this.personalNumber, this.givenName, this.surname,
        Objects.toString(this.getDateOfBirth(), "")), StandardCharsets.UTF_8);
  }

  /**
   * Encodes a list of users for a cookie.
   *
   * @param users the users
   * @return the encoded list
   */
  public static @NonNull String encodeList(final @NonNull List<SimulatedUser> users) {
    return String.join(USER_SEPARATOR, users.stream().map(SimulatedUser::encode).toList());
  }

  /**
   * Decodes a user that has been encoded with {@link #encode()}.
   *
   * @param encoded the encoded user
   * @return the user, or {@code null} if the string does not hold a valid user
   */
  public static @Nullable SimulatedUser parse(final @NonNull String encoded) {
    final String[] parts;
    try {
      parts = URLDecoder.decode(encoded, StandardCharsets.UTF_8).split(FIELD_SEPARATOR);
    }
    catch (final IllegalArgumentException e) {
      return null;
    }
    if (parts.length < 3 || !StringUtils.hasText(parts[0])) {
      return null;
    }
    final SimulatedUser user = new SimulatedUser();
    user.setPersonalNumber(parts[0]);
    user.setGivenName(parts[1]);
    user.setSurname(parts[2]);
    if (parts.length > 3 && StringUtils.hasText(parts[3])) {
      user.setDateOfBirth(parts[3]);
    }
    return user;
  }

  /**
   * Decodes a list of users that has been encoded with {@link #encodeList(List)}. Entries that are not valid are
   * left out.
   *
   * @param encoded the encoded list
   * @return the users
   */
  public static @NonNull List<SimulatedUser> parseList(final @NonNull String encoded) {
    final List<SimulatedUser> users = new ArrayList<>();
    if (!StringUtils.hasText(encoded)) {
      return users;
    }
    for (final String part : encoded.split(USER_SEPARATOR)) {
      final SimulatedUser user = parse(part);
      if (user != null) {
        users.add(user);
      }
    }
    return users;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.personalNumber);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || this.getClass() != obj.getClass()) {
      return false;
    }
    return Objects.equals(this.personalNumber, ((SimulatedUser) obj).personalNumber);
  }

}
