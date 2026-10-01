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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SimulatedUser} and {@link SimulatedUsers}.
 *
 * @author Martin Lindström
 */
class SimulatedUsersTest {

  @Test
  void theDisplayNameAndDateOfBirthAreDerived() {
    final SimulatedUser user = user("197705232382", "Frida", "Kranstege");
    assertThat(user.getDisplayName()).isEqualTo("Frida Kranstege");
    assertThat(user.getDateOfBirth()).isEqualTo("1977-05-23");
    assertThat(user.toViewString()).isEqualTo("Frida Kranstege (197705232382)");

    user.setDisplayName("Frida K");
    user.setDateOfBirth("1977-05-24");
    assertThat(user.getDisplayName()).isEqualTo("Frida K");
    assertThat(user.getDateOfBirth()).isEqualTo("1977-05-24");

    assertThat(user("abc", "A", "B").getDateOfBirth()).isNull();
  }

  @Test
  void usersAreEncodedForTheCookieAndDecoded() {
    final List<SimulatedUser> users = List.of(user("197705232382", "Frida", "Kranstege"),
        user("188803099368", "Åsa Öberg", "Andersson"));
    final List<SimulatedUser> decoded = SimulatedUser.parseList(SimulatedUser.encodeList(users));
    assertThat(decoded).containsExactlyElementsOf(users);
    assertThat(decoded.get(0).getGivenName()).isEqualTo("Frida");
    assertThat(decoded.get(0).getDateOfBirth()).isEqualTo("1977-05-23");
  }

  @Test
  void invalidCookieValuesAreIgnored() {
    assertThat(SimulatedUser.parseList("")).isEmpty();
    assertThat(SimulatedUser.parseList("onlyone:::197705232382%23Frida%23Kranstege")).hasSize(1);
    assertThat(SimulatedUser.parse("%zz")).isNull();
    assertThat(SimulatedUser.parse("%23Frida%23Kranstege")).isNull();
  }

  @Test
  void usersAreSortedBySurnameAndSavedUsersAreAdded() {
    final SimulatedUsers users = new SimulatedUsers(List.of(user("1", "A", "Svensson"), user("2", "B", "Andersson")));
    final List<SimulatedUser> all = users.getUsers(List.of(user("3", "C", "Larsson"), user("1", "X", "Copy")));
    assertThat(all).extracting(SimulatedUser::getPersonalNumber).containsExactly("2", "3", "1");

    final SimulatedUser noSurname = user("4", "D", null);
    assertThat(users.getUsers(List.of(noSurname))).last().isEqualTo(noSurname);
  }

  @Test
  void usersAreFoundAmongTheFixedAndSavedUsers() {
    final SimulatedUsers users = new SimulatedUsers(List.of(user("1", "A", "Svensson")));
    assertThat(users.findUser("1", List.of())).isNotNull();
    assertThat(users.findUser("3", List.of(user("3", "C", "Larsson")))).isNotNull();
    assertThat(users.findUser("4", List.of())).isNull();
    assertThat(users.findUser(null, List.of())).isNull();
  }

  @Test
  void theSavedUsersAreLimited() {
    List<SimulatedUser> saved = new ArrayList<>();
    for (final int i : IntStream.range(0, SimulatedUsers.MAX_SAVED_USERS + 5).toArray()) {
      saved = SimulatedUsers.addSavedUser(user(Integer.toString(i), "G", "S"), saved);
    }
    assertThat(saved).hasSize(SimulatedUsers.MAX_SAVED_USERS);
    assertThat(saved.getFirst().getPersonalNumber()).isEqualTo("5");

    // A user that is added again is moved last, not duplicated
    saved = SimulatedUsers.addSavedUser(user("10", "G", "S"), saved);
    assertThat(saved).hasSize(SimulatedUsers.MAX_SAVED_USERS);
    assertThat(saved.getLast().getPersonalNumber()).isEqualTo("10");
  }

  @Test
  void invalidUsersAreRejected() {
    assertThatThrownBy(() -> new SimulatedUsers(List.of(user(null, "A", "B"))))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new SimulatedUsers(List.of(user("1", "A", "B"), user("1", "C", "D"))))
        .isInstanceOf(IllegalArgumentException.class);
  }

  static SimulatedUser user(final String pnr, final String givenName, final String surname) {
    final SimulatedUser user = new SimulatedUser();
    user.setPersonalNumber(pnr);
    user.setGivenName(givenName);
    user.setSurname(surname);
    return user;
  }

}
