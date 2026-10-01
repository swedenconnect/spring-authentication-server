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
package se.swedenconnect.spring.authnserver.service.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.nimbusds.langtag.LangTag;

import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;

/**
 * Tests for {@link OidcClientLoader}.
 *
 * @author Martin Lindström
 */
class OidcClientLoaderTest {

  @Test
  void theClientsOfTheTestProfileAreRead() throws Exception {
    final List<OidcClientRecord> clients = OidcClientLoader.load(List.of(
        new ClassPathResource("complete/oidc-clients.json")));
    assertThat(clients).hasSize(1);
    assertThat(clients.getFirst().clientId()).isEqualTo("https://rp.test.local");
    assertThat(clients.getFirst().metadata().getName(LangTag.parse("sv"))).isEqualTo("Testklient");
    assertThat(clients.getFirst().metadata().getJWKSet().getKeys()).hasSize(1);
  }

  @Test
  void anObjectAndAnArrayAreBothAccepted() {
    assertThat(OidcClientLoader.load(json("{\"client_id\":\"a\",\"redirect_uris\":[\"https://a/cb\"]}")))
        .extracting(OidcClientRecord::clientId).containsExactly("a");
    assertThat(OidcClientLoader.load(json("[{\"client_id\":\"a\"},{\"client_id\":\"b\"}]")))
        .extracting(OidcClientRecord::clientId).containsExactly("a", "b");
    assertThat(OidcClientLoader.load(List.of())).isEmpty();
  }

  @Test
  void theClientIdIsNotPartOfTheMetadata() {
    final OidcClientRecord client = OidcClientLoader.load(json("{\"client_id\":\"a\",\"client_secret\":\"s\"}"))
        .getFirst();
    assertThat(client.metadata().toJSONObject()).doesNotContainKey("client_id");
    assertThat(client.metadata().getCustomField(OidcClientRecord.CLIENT_SECRET)).isEqualTo("s");
  }

  @Test
  void invalidClientsAreRejected() {
    assertThatThrownBy(() -> OidcClientLoader.load(json("{\"redirect_uris\":[\"https://a/cb\"]}")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client_id");
    assertThatThrownBy(() -> OidcClientLoader.load(json("[\"a\"]")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("not a JSON object");
    assertThatThrownBy(() -> OidcClientLoader.load(json("\"a\"")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("does not hold");
    assertThatThrownBy(() -> OidcClientLoader.load(json("{\"client_id\":")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Failed to read");
    assertThatThrownBy(() -> OidcClientLoader.load(json("{\"client_id\":\"a\",\"redirect_uris\":\"x\"}")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Invalid metadata");
    assertThatThrownBy(() -> OidcClientLoader.load(new ClassPathResource("does-not-exist.json")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Failed to read");
  }

  @Test
  void aClientGivenTwiceIsRejected() {
    assertThatThrownBy(() -> OidcClientLoader.load(List.of(json("{\"client_id\":\"a\"}"),
        json("{\"client_id\":\"a\"}"))))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("more than once");
  }

  private static Resource json(final String json) {
    return new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8));
  }

}
