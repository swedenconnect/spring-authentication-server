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
package se.swedenconnect.spring.authnserver.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Tests for {@link RequesterRecord}, {@link DisplayName} and {@link Logo}.
 *
 * @author Martin Lindström
 */
class RequesterRecordTest {

  private static final Requester REQUESTER = new Requester(AuthenticationProtocol.SAML, "https://sp.example.com");

  @Test
  void displayNameForExactLanguage() {
    final RequesterRecord record = record(
        List.of(new DisplayName("sv", "Svenskt namn"), new DisplayName("en", "English name")), List.of());
    assertThat(record.getDisplayName("sv")).isEqualTo("Svenskt namn");
    assertThat(record.getDisplayName("en")).isEqualTo("English name");
  }

  @Test
  void displayNameForPrimarySubtag() {
    final RequesterRecord record = record(List.of(new DisplayName("sv-SE", "Svenskt namn")), List.of());
    assertThat(record.getDisplayName("sv")).isEqualTo("Svenskt namn");
    assertThat(record.getDisplayName("sv-FI")).isEqualTo("Svenskt namn");
  }

  @Test
  void displayNameFallsBackToTheNameWithoutLanguage() {
    final RequesterRecord record = record(
        List.of(new DisplayName("sv", "Svenskt namn"), new DisplayName(null, "Fallback")), List.of());
    assertThat(record.getDisplayName("de")).isEqualTo("Fallback");
    assertThat(record.getDisplayName(null)).isEqualTo("Fallback");
  }

  @Test
  void noDisplayNameAtAll() {
    final RequesterRecord record = record(List.of(new DisplayName("sv", "Svenskt namn")), List.of());
    assertThat(record.getDisplayName("de")).isNull();
    assertThat(record().getDisplayName("sv")).isNull();
  }

  @Test
  void logoForLanguageThenWithoutLanguageThenFirst() {
    final Logo swedish = new Logo("sv", "https://sp.example.com/sv.svg", 40, 80);
    final Logo generic = Logo.of("https://sp.example.com/logo.svg");
    final RequesterRecord record = record(List.of(), List.of(swedish, generic));
    assertThat(record.getLogo("sv")).isEqualTo(swedish);
    assertThat(record.getLogo("sv-SE")).isEqualTo(swedish);
    assertThat(record.getLogo("de")).isEqualTo(generic);
    assertThat(record.getLogo(null)).isEqualTo(generic);

    final RequesterRecord onlySwedish = record(List.of(), List.of(swedish));
    assertThat(onlySwedish.getLogo("de")).isEqualTo(swedish);
    assertThat(record().getLogo("sv")).isNull();
  }

  @Test
  void marks() {
    final RequesterRecord record = new RequesterRecord(REQUESTER, List.of(), List.of(), Set.of("mark-1"), "metadata");
    assertThat(record.hasMark("mark-1")).isTrue();
    assertThat(record.hasMark("mark-2")).isFalse();

    final RequesterRecord updated = record.withMarks(List.of("mark-2"));
    assertThat(updated.marks()).containsExactlyInAnyOrder("mark-1", "mark-2");
    assertThat(record.marks()).containsExactly("mark-1");
    assertThat(record.withMarks(List.of("mark-1"))).isSameAs(record);
  }

  @Test
  void theOrganisationNumberIsOptionalAndKeptWhenMarksAreAdded() {
    assertThat(record().organizationNumber()).isNull();

    final RequesterRecord record =
        new RequesterRecord(REQUESTER, List.of(), List.of(), Set.of("mark-1"), "556677-8899", "metadata");
    assertThat(record.organizationNumber()).isEqualTo("556677-8899");
    assertThat(record.withMarks(List.of("mark-2")).organizationNumber()).isEqualTo("556677-8899");
  }

  @Test
  void protocolMetadataInItsOwnType() {
    final RequesterRecord record = record();
    assertThat(record.getProtocolMetadata(String.class)).isEqualTo("metadata");
    assertThatThrownBy(() -> record.getProtocolMetadata(Integer.class))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void protocolAndIdentifier() {
    assertThat(record().getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(record().getIdentifier()).isEqualTo("https://sp.example.com");
  }

  @Test
  void displayNameAndLogoAreValidated() {
    assertThatThrownBy(() -> new DisplayName("", "name")).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new DisplayName("sv", " ")).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Logo("", "https://x", null, null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Logo("sv", "", null, null)).isInstanceOf(IllegalArgumentException.class);
    assertThat(new DisplayName(null, "name").getPrimaryLanguage()).isNull();
    assertThat(new DisplayName("sv-SE", "name").getPrimaryLanguage()).isEqualTo("sv");
    assertThat(Logo.of("https://x").getPrimaryLanguage()).isNull();
  }

  private static RequesterRecord record() {
    return record(List.of(), List.of());
  }

  private static RequesterRecord record(final List<DisplayName> displayNames, final List<Logo> logos) {
    return new RequesterRecord(REQUESTER, displayNames, logos, Set.of(), "metadata");
  }

}
