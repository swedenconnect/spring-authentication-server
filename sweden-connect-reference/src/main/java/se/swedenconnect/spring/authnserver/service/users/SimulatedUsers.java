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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

/**
 * The simulated users: the fixed users of {@code users.yml}, and the users that a tester has added, which are kept in a
 * cookie of the tester's browser.
 *
 * @author Martin Lindström
 */
public class SimulatedUsers {

  /** The maximum number of users that a tester may add. When more are added, the oldest is dropped. */
  public static final int MAX_SAVED_USERS = 40;

  /** The fixed users. */
  private final List<SimulatedUser> users;

  /**
   * Constructor.
   *
   * @param users the fixed users
   * @throws IllegalArgumentException if a user has no personal identity number, or two users have the same
   */
  public SimulatedUsers(final @NonNull Collection<SimulatedUser> users) {
    Objects.requireNonNull(users, "users must not be null");
    if (users.stream().anyMatch(u -> !StringUtils.hasText(u.getPersonalNumber()))) {
      throw new IllegalArgumentException("Every simulated user must have a personal number");
    }
    if (users.stream().map(SimulatedUser::getPersonalNumber).distinct().count() != users.size()) {
      throw new IllegalArgumentException("Two simulated users have the same personal number");
    }
    this.users = List.copyOf(users);
  }

  /**
   * Gets the fixed users.
   *
   * @return the fixed users
   */
  public @NonNull List<SimulatedUser> getUsers() {
    return this.users;
  }

  /**
   * Gets the fixed users together with the users that the tester has added, sorted by surname. A saved user with the
   * same personal identity number as a fixed user is left out.
   *
   * @param savedUsers the users that the tester has added
   * @return the users to choose among
   */
  public @NonNull List<SimulatedUser> getUsers(final @NonNull List<SimulatedUser> savedUsers) {
    final List<SimulatedUser> all = new ArrayList<>(this.users);
    savedUsers.stream()
        .filter(s -> !all.contains(s))
        .forEach(all::add);
    Collections.sort(all);
    return all;
  }

  /**
   * Finds a user, among the fixed users and then among the users that the tester has added.
   *
   * @param personalNumber the personal identity number of the user
   * @param savedUsers the users that the tester has added
   * @return the user, or {@code null} if there is no such user
   */
  public @Nullable SimulatedUser findUser(final @Nullable String personalNumber,
      final @NonNull List<SimulatedUser> savedUsers) {
    if (personalNumber == null) {
      return null;
    }
    return this.users.stream()
        .filter(u -> personalNumber.equals(u.getPersonalNumber()))
        .findFirst()
        .orElseGet(() -> savedUsers.stream()
            .filter(u -> personalNumber.equals(u.getPersonalNumber()))
            .findFirst()
            .orElse(null));
  }

  /**
   * Adds a user to the users that the tester has added. When the list is full, the oldest user is dropped.
   *
   * @param user the user to add
   * @param savedUsers the users that the tester has added
   * @return the new list of added users
   */
  public static @NonNull List<SimulatedUser> addSavedUser(final @NonNull SimulatedUser user,
      final @NonNull List<SimulatedUser> savedUsers) {
    final List<SimulatedUser> updated = new ArrayList<>(savedUsers);
    updated.remove(user);
    while (updated.size() >= MAX_SAVED_USERS) {
      updated.removeFirst();
    }
    updated.add(user);
    return updated;
  }

}
