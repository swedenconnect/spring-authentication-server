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
package se.swedenconnect.spring.authnserver.entity;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.ContactPerson;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.ContactPersonType;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.Logo;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.Organization;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.UiInfo;

/**
 * Tests for {@link EntityInformation}.
 *
 * @author Martin Lindström
 */
class EntityInformationTest {

  private static final ContactPerson TECHNICAL = new ContactPerson(null, "T", null, List.of("t@example.com"), null);

  private static final ContactPerson SUPPORT = new ContactPerson(null, "S", null, List.of("s@example.com"), null);

  private static final EntityInformation SHARED = new EntityInformation(
      new UiInfo(Map.of("sv", "Delad"), Map.of("sv", "Beskrivning"),
          List.of(new Logo("https://example.com/logo.svg", null, 1, 1, null))),
      new Organization(Map.of("sv", "Org"), Map.of("sv", "O"), Map.of("sv", "https://example.com"), "5561234567"),
      orderedContacts(ContactPersonType.technical, TECHNICAL, ContactPersonType.support, SUPPORT));

  @Test
  void anEmptyOverrideChangesNothing() {
    assertThat(SHARED.overriddenBy(null)).isSameAs(SHARED);
    assertThat(SHARED.overriddenBy(EntityInformation.empty())).isSameAs(SHARED);
    assertThat(EntityInformation.empty().isEmpty()).isTrue();
    assertThat(SHARED.isEmpty()).isFalse();
  }

  @Test
  void eachAssignedValueReplacesTheSharedValue() {
    final ContactPerson otherSupport = new ContactPerson(null, "X", null, List.of("x@example.com"), null);
    final ContactPerson security = new ContactPerson(null, "Y", null, List.of("y@example.com"), null);
    final EntityInformation override = new EntityInformation(
        new UiInfo(Map.of("en", "Override"), null, null),
        new Organization(null, null, null, "5569876543"),
        orderedContacts(ContactPersonType.support, otherSupport, ContactPersonType.security, security));

    final EntityInformation result = SHARED.overriddenBy(override);

    assertThat(result.uiInfo()).isEqualTo(new UiInfo(Map.of("en", "Override"), Map.of("sv", "Beskrivning"),
        SHARED.uiInfo().logotypes()));
    assertThat(result.organization()).isEqualTo(new Organization(Map.of("sv", "Org"), Map.of("sv", "O"),
        Map.of("sv", "https://example.com"), "5569876543"));
    assertThat(result.contactPersons()).containsExactly(Map.entry(ContactPersonType.technical, TECHNICAL),
        Map.entry(ContactPersonType.support, otherSupport), Map.entry(ContactPersonType.security, security));
  }

  @Test
  void anOverrideOfNothingIsTheOverride() {
    final EntityInformation override = new EntityInformation(new UiInfo(Map.of("en", "A"), null, null),
        new Organization(null, null, null, "1"), Map.of(ContactPersonType.other, TECHNICAL));
    assertThat(EntityInformation.empty().overriddenBy(override)).isEqualTo(override);
  }

  @Test
  void aLogoGivenAsAPathIsRelativeToTheBaseUrl() {
    assertThat(new Logo(null, "/logo.svg", null, null, null).getUrl("https://idp.example.com"))
        .isEqualTo("https://idp.example.com/logo.svg");
    assertThat(new Logo("https://cdn.example.com/logo.svg", null, null, null, null).getUrl("https://x"))
        .isEqualTo("https://cdn.example.com/logo.svg");
  }

  @Test
  void theServerHoldsTheSharedInformation() {
    final AuthnServerConfigurer server = new AuthnServerConfigurer();
    assertThat(server.getEntityInformation().isEmpty()).isTrue();
    assertThat(server.entityInformation(SHARED).getEntityInformation()).isSameAs(SHARED);
    assertThat(server.entityInformation(null).getEntityInformation().isEmpty()).isTrue();
  }

  private static Map<ContactPersonType, ContactPerson> orderedContacts(final ContactPersonType t1,
      final ContactPerson c1, final ContactPersonType t2, final ContactPerson c2) {
    final Map<ContactPersonType, ContactPerson> map = new LinkedHashMap<>();
    map.put(t1, c1);
    map.put(t2, c2);
    return map;
  }

}
