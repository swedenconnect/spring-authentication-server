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
package se.swedenconnect.spring.authnserver.oidc.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.ContactPerson;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.ContactPersonType;

/**
 * Tests for {@link OidcEntityMetadata}.
 *
 * @author Martin Lindström
 */
class OidcEntityMetadataTest {

  private static final String BASE_URL = "https://op.example.com";

  @Test
  void theEntityInformationIsMapped() {
    final Map<ContactPersonType, ContactPerson> contacts = new LinkedHashMap<>();
    contacts.put(ContactPersonType.support, contact("mailto:support@example.com", "ops@example.com"));
    contacts.put(ContactPersonType.technical, contact("ops@example.com"));
    contacts.put(ContactPersonType.administrative, contact("admin@example.com"));
    final EntityInformation information = new EntityInformation(
        new EntityInformation.UiInfo(orderedMap("sv", "Exempel", "en", "Example"),
            Map.of("en", "An example"),
            List.of(new EntityInformation.Logo("https://cdn.example.com/sv.svg", null, 10, 10, "sv"),
                new EntityInformation.Logo(null, "/images/logo.svg", 10, 10, null))),
        new EntityInformation.Organization(Map.of("sv", "Exempel AB"), Map.of("sv", "Exempel"),
            orderedMap("sv", "https://www.example.se", "en", "https://www.example.com"), "5561234567"),
        contacts);

    final OidcEntityMetadata metadata = OidcEntityMetadata.from(information, BASE_URL);

    assertThat(metadata.logoUri()).isEqualTo(BASE_URL + "/images/logo.svg");
    assertThat(metadata.organizationUri()).isEqualTo("https://www.example.se");
    assertThat(metadata.organizationIdentifier()).isEqualTo("urn:glue:iso6523:0007:5561234567");
    assertThat(metadata.contacts()).containsExactly("ops@example.com", "support@example.com");

    assertThat(metadata.toParameters()).containsExactly(
        Map.entry("display_name#sv", "Exempel"),
        Map.entry("display_name#en", "Example"),
        Map.entry("description#en", "An example"),
        Map.entry("organization_name#sv", "Exempel AB"),
        Map.entry("organization_uri", "https://www.example.se"),
        Map.entry("organization_identifier", "urn:glue:iso6523:0007:5561234567"),
        Map.entry("logo_uri", BASE_URL + "/images/logo.svg"),
        Map.entry("contacts", List.of("ops@example.com", "support@example.com")));
  }

  @Test
  void theFirstLogoIsUsedWhenAllHaveALanguage() {
    final EntityInformation information = new EntityInformation(new EntityInformation.UiInfo(null, null,
        List.of(new EntityInformation.Logo("https://cdn.example.com/sv.svg", null, 10, 10, "sv"),
            new EntityInformation.Logo("https://cdn.example.com/en.svg", null, 10, 10, "en"))), null, null);

    assertThat(OidcEntityMetadata.from(information, BASE_URL).logoUri()).isEqualTo("https://cdn.example.com/sv.svg");
  }

  @Test
  void anOrganizationNumberThatIsNotTenDigitsGivesNoIdentifier() {
    for (final String number : List.of("556123-4567", "55612345678", "556123456", "abcdefghij")) {
      final EntityInformation information =
          new EntityInformation(null, new EntityInformation.Organization(null, null, null, number), null);
      assertThat(OidcEntityMetadata.from(information, BASE_URL).organizationIdentifier()).as(number).isNull();
    }
  }

  @Test
  void emptyInformationGivesNoParameters() {
    final OidcEntityMetadata metadata = OidcEntityMetadata.from(EntityInformation.empty(), BASE_URL);
    assertThat(metadata).isEqualTo(OidcEntityMetadata.empty());
    assertThat(metadata.toParameters()).isEmpty();
  }

  @Test
  void assignedValuesOverrideTheMappedOnes() {
    final OidcEntityMetadata mapped = new OidcEntityMetadata(Map.of("sv", "A"), Map.of("sv", "B"),
        Map.of("sv", "C"), "https://d.example.com", "urn:e", "https://f.example.com/logo.svg", List.of("g@x.se"));

    assertThat(mapped.overriddenBy(null)).isSameAs(mapped);
    assertThat(mapped.overriddenBy(OidcEntityMetadata.empty())).isEqualTo(mapped);
    assertThat(mapped.overriddenBy(new OidcEntityMetadata(null, null, null, null, null,
        "https://other.example.com/logo.svg", List.of("other@x.se"))))
        .isEqualTo(new OidcEntityMetadata(Map.of("sv", "A"), Map.of("sv", "B"), Map.of("sv", "C"),
            "https://d.example.com", "urn:e", "https://other.example.com/logo.svg", List.of("other@x.se")));
    assertThat(mapped.overriddenBy(new OidcEntityMetadata(Map.of("en", "X"), Map.of("en", "Y"), Map.of("en", "Z"),
        "https://u.example.com", "urn:i", null, null)).toParameters())
        .containsEntry("display_name#en", "X")
        .containsEntry("description#en", "Y")
        .containsEntry("organization_name#en", "Z")
        .containsEntry("organization_uri", "https://u.example.com")
        .containsEntry("organization_identifier", "urn:i")
        .doesNotContainKey("display_name#sv");
  }

  @Test
  void theFederationRequirementsAreChecked() {
    new OidcEntityMetadata(null, null, null, null, null, "https://op.example.com/logo.svg", List.of("a@example.com"))
        .validate();

    assertThatThrownBy(() -> new OidcEntityMetadata(null, null, null, null, null,
        "https://op.example.com/logo.svg", null).validate())
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("contacts");
    assertThatThrownBy(() -> new OidcEntityMetadata(null, null, null, null, null,
        "https://op.example.com/logo.svg", List.of("not an address")).validate())
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("contacts");
    assertThatThrownBy(() -> new OidcEntityMetadata(null, null, null, null, null,
        "http://op.example.com/logo.svg", List.of("a@example.com")).validate())
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("logo_uri");
    assertThatThrownBy(() -> new OidcEntityMetadata(null, null, null, null, null,
        null, List.of("a@example.com")).validate())
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("logo_uri");
  }

  private static ContactPerson contact(final String... addresses) {
    return new ContactPerson(null, null, null, List.of(addresses), null);
  }

  private static Map<String, String> orderedMap(final String k1, final String v1, final String k2, final String v2) {
    final Map<String, String> map = new LinkedHashMap<>();
    map.put(k1, v1);
    map.put(k2, v2);
    return map;
  }

}
