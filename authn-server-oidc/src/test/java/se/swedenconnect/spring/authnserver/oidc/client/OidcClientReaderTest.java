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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.nimbusds.oauth2.sdk.auth.Secret;

/**
 * Tests for {@link OidcClientReader}.
 *
 * @author Martin Lindström
 */
class OidcClientReaderTest {

  private static final String METADATA = """
      {"redirect_uris":["https://rp.example.com/cb"],"client_name#en":"The RP","token_endpoint_auth_method":"%s"}""";

  private static final String ORIGIN = "authn-server.oidc.clients[0]";

  @Test
  void anInlineClientIsRead() {
    final List<OidcClientRecord> clients = new OidcClientReader()
        .addClient("https://rp.example.com", METADATA.formatted("client_secret_basic"), "secret",
            List.of("https://tm.example.com/a", " https://tm.example.com/b "), ORIGIN)
        .getClients();

    assertThat(clients).hasSize(1);
    final OidcClientRecord client = clients.get(0);
    assertThat(client.clientId()).isEqualTo("https://rp.example.com");
    assertThat(client.metadata().getRedirectionURIs()).extracting(Object::toString)
        .containsExactly("https://rp.example.com/cb");
    assertThat(OidcClientRecord.getClientSecret(client.metadata())).isEqualTo(new Secret("secret"));
    assertThat(client.trustMarkTypes()).containsExactlyInAnyOrder("https://tm.example.com/a",
        "https://tm.example.com/b");
    assertThat(client.toRequesterRecord().marks()).containsExactlyInAnyOrder("https://tm.example.com/a",
        "https://tm.example.com/b");
  }

  @Test
  void anInlineClientNeedsNoSecretOrTrustMarkTypes() {
    final OidcClientRecord client = new OidcClientReader()
        .addClient("https://rp.example.com", METADATA.formatted("private_key_jwt"), null, null, ORIGIN)
        .getClients().get(0);
    assertThat(OidcClientRecord.getClientSecret(client.metadata())).isNull();
    assertThat(client.trustMarkTypes()).isEmpty();
  }

  @Test
  void aFileWithAnArrayOfClientsIsRead() {
    final List<OidcClientRecord> clients = new OidcClientReader()
        .readLocation(new ClassPathResource("clients/clients.json"))
        .getClients();

    assertThat(clients).extracting(OidcClientRecord::clientId)
        .containsExactly("https://one.example.com", "https://two.example.com");
    assertThat(OidcClientRecord.getClientSecret(clients.get(0).metadata())).isNull();
    assertThat(clients.get(0).trustMarkTypes()).containsExactly("https://tm.example.com/a");
    assertThat(OidcClientRecord.getClientSecret(clients.get(1).metadata())).isEqualTo(new Secret("two-secret"));
    assertThat(clients.get(1).trustMarkTypes()).isEmpty();
    // The metadata of a file client is the client's registered metadata, unchanged
    assertThat(OidcClientRecord.toJson(clients.get(1).metadata())).doesNotContain("client_id");
  }

  @Test
  void aFileWithOneClientObjectIsRead() {
    final List<OidcClientRecord> clients = new OidcClientReader()
        .readLocation(json("""
            {"client_id":"https://rp.example.com","metadata":%s}""".formatted(METADATA.formatted("none"))))
        .getClients();
    assertThat(clients).extracting(OidcClientRecord::clientId).containsExactly("https://rp.example.com");
  }

  @Test
  void aClientIdInTheMetadataMustBeTheClientsOwn() {
    final String metadata = """
        {"client_id":"%s","redirect_uris":["https://rp.example.com/cb"]}""";
    assertThat(new OidcClientReader()
        .addClient("https://rp.example.com", metadata.formatted("https://rp.example.com"), null, null, ORIGIN)
        .getClients()).hasSize(1);
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader()
            .addClient("https://rp.example.com", metadata.formatted("https://other.example.com"), null, null, ORIGIN))
        .withMessageContaining("https://rp.example.com")
        .withMessageContaining("different client_id");
  }

  @Test
  void aClientSecretInTheMetadataIsRejected() {
    final String metadata = """
        {"client_secret":"secret","redirect_uris":["https://rp.example.com/cb"]}""";
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().addClient("https://rp.example.com", metadata, null, null, ORIGIN))
        .withMessageContaining("client-secret")
        .withMessageContaining("client_secret");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            {"client_id":"https://rp.example.com","client_secret":"s","metadata":%s}""".formatted(metadata))))
        .withMessageContaining("client-secret");
  }

  @Test
  void invalidMetadataIsRejectedNamingTheClientAndWhereItCameFrom() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader()
            .addClient("https://rp.example.com", "{\"redirect_uris\":\"not a list\"}", null, null, ORIGIN))
        .withMessageContaining("Invalid metadata")
        .withMessageContaining("https://rp.example.com")
        .withMessageContaining(ORIGIN);
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().addClient("https://rp.example.com", "{not json", null, null, ORIGIN))
        .withMessageContaining("not valid JSON");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().addClient("https://rp.example.com", "[]", null, null, ORIGIN))
        .withMessageContaining("not a JSON object");
  }

  @Test
  void anInlineClientNeedsAnIdentifierAndMetadata() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().addClient(" ", METADATA.formatted("none"), null, null, ORIGIN))
        .withMessageContaining("no client identifier");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().addClient("https://rp.example.com", null, null, null, ORIGIN))
        .withMessageContaining("no metadata");
  }

  @Test
  void emptySecretsAndTrustMarkTypesAreRejected() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader()
            .addClient("https://rp.example.com", METADATA.formatted("none"), " ", null, ORIGIN))
        .withMessageContaining("empty client secret");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader()
            .addClient("https://rp.example.com", METADATA.formatted("none"), null, List.of(""), ORIGIN))
        .withMessageContaining("empty trust mark type");
  }

  @Test
  void aClientGivenMoreThanOnceIsRejected() {
    final OidcClientReader reader = new OidcClientReader()
        .readLocation(new ClassPathResource("clients/clients.json"));
    assertThatIllegalArgumentException()
        .isThrownBy(() -> reader.addClient("https://two.example.com", METADATA.formatted("none"), null, null, ORIGIN))
        .withMessageContaining("'https://two.example.com' is given more than once")
        .withMessageContaining(ORIGIN);
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            [{"client_id":"https://rp.example.com","metadata":{}},
             {"client_id":"https://rp.example.com","metadata":{}}]""")))
        .withMessageContaining("more than once");
  }

  @Test
  void invalidFilesAreRejected() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(new ClassPathResource("clients/missing.json")))
        .withMessageContaining("Failed to read");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("{not json")))
        .withMessageContaining("Failed to read");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("\"a string\"")))
        .withMessageContaining("does not hold a JSON object or an array");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("[1]")))
        .withMessageContaining("not a JSON object");
  }

  @Test
  void invalidClientObjectsAreRejected() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("{\"metadata\":{}}")))
        .withMessageContaining("has no client_id");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("{\"client_id\":\"https://rp.example.com\"}")))
        .withMessageContaining("has no metadata object");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            {"client_id":"https://rp.example.com","metadata":{},"client_secret":1}""")))
        .withMessageContaining("client_secret")
        .withMessageContaining("not a string");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            {"client_id":"https://rp.example.com","metadata":{},"trust_mark_types":"https://tm"}""")))
        .withMessageContaining("not an array");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            {"client_id":"https://rp.example.com","metadata":{},"trust_mark_types":[1]}""")))
        .withMessageContaining("not a string");
  }

  @Test
  void theOldShapeWithTheMetadataNextToTheClientIdIsRejected() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcClientReader().readLocation(json("""
            {"client_id":"https://rp.example.com","redirect_uris":["https://rp.example.com/cb"]}""")))
        .withMessageContaining("unknown field 'redirect_uris'")
        .withMessageContaining("goes in 'metadata'");
  }

  private static Resource json(final String json) {
    return new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8), "test clients");
  }

}
