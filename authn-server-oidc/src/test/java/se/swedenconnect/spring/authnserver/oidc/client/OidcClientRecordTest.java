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
package se.swedenconnect.spring.authnserver.oidc.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.Logo;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link OidcClientRecord}.
 *
 * @author Martin Lindström
 */
class OidcClientRecordTest {

  private static final String CLIENT_ID = "https://client.example.com";

  @Test
  void displayNamesAndLogosComeFromTheClientMetadata() throws Exception {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setName("Klienten", LangTag.parse("sv"));
    metadata.setName("The Client", LangTag.parse("en"));
    metadata.setName("Fallback");
    metadata.setLogoURI(URI.create("https://client.example.com/logo-sv.svg"), LangTag.parse("sv"));
    metadata.setLogoURI(URI.create("https://client.example.com/logo.svg"));

    final RequesterRecord record = OidcClientRecord.of(CLIENT_ID, metadata).toRequesterRecord();

    assertThat(record.requester().protocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(record.getIdentifier()).isEqualTo(CLIENT_ID);
    assertThat(record.displayNames()).containsExactlyInAnyOrder(
        new DisplayName("sv", "Klienten"),
        new DisplayName("en", "The Client"),
        new DisplayName(null, "Fallback"));
    assertThat(record.getDisplayName("sv")).isEqualTo("Klienten");
    assertThat(record.getDisplayName("de")).isEqualTo("Fallback");
    assertThat(record.logos()).containsExactlyInAnyOrder(
        new Logo("sv", "https://client.example.com/logo-sv.svg", null, null),
        new Logo(null, "https://client.example.com/logo.svg", null, null));
    assertThat(record.getLogo("sv").url()).isEqualTo("https://client.example.com/logo-sv.svg");
    assertThat(record.getProtocolMetadata(OIDCClientMetadata.class)).isSameAs(metadata);
    assertThat(record.marks()).isEmpty();
  }

  @Test
  void theMarksAreTheTrustMarkTypes() {
    final Set<String> types = Set.of("https://example.com/mark-1", "https://example.com/mark-2");

    final RequesterRecord record =
        new OidcClientRecord(CLIENT_ID, new OIDCClientMetadata(), types).toRequesterRecord();

    assertThat(record.marks()).containsExactlyInAnyOrderElementsOf(types);
    assertThat(record.displayNames()).isEmpty();
    assertThat(record.logos()).isEmpty();
  }

  @Test
  void theClientIdIsRequired() {
    assertThatThrownBy(() -> OidcClientRecord.of("", new OIDCClientMetadata()))
        .isInstanceOf(IllegalArgumentException.class);
  }

}
