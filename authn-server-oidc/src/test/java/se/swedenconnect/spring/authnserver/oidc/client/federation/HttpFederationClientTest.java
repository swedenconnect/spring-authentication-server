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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link HttpFederationClient}.
 *
 * @author Martin Lindström
 */
class HttpFederationClientTest extends FederationTestSupport {

  /** The HTTP server of the test. */
  private HttpServer server;

  /** The queries that the server was called with. */
  private final List<String> queries = new ArrayList<>();

  /** What the server answers. */
  private int status = 200;

  /** The body that the server answers with. */
  private String body = "";

  @AfterEach
  void stopServer() {
    if (this.server != null) {
      this.server.stop(0);
      this.server = null;
    }
  }

  @Test
  void theResolveRequestCarriesTheSubjectTheTrustAnchorAndTheEntityType() throws Exception {
    final ECKey key = key("k1");
    final SignedJWT response = resolveResponse(key, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));
    this.body = response.serialize();
    final int port = this.startServer();

    final SignedJWT answer = new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, "openid_relying_party", Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT,
            "http://localhost:%d/resolve".formatted(port))));

    assertThat(answer).isNotNull();
    assertThat(answer.serialize()).isEqualTo(this.body);
    assertThat(this.queries).hasSize(1);
    assertThat(this.queries.get(0))
        .contains("sub=https%3A%2F%2Fclient.example.com")
        .contains("trust_anchor=https%3A%2F%2Fta.example.com")
        .contains("entity_type=openid_relying_party");
  }

  @Test
  void theTrustMarkRequestCarriesTheTypeAndTheSubject() throws Exception {
    final ECKey key = key("k1");
    this.body = trustMark(key, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    final int port = this.startServer();

    final SignedJWT answer = new HttpFederationClient().trustMark(new FederationRequest<>(
        new TrustMarkRequest(new EntityID(CLIENT_ID), new EntityID(TRUST_MARK_ISSUER), new EntityID(MARK_ONE)),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT,
            "http://localhost:%d/trust_mark".formatted(port))));

    assertThat(answer).isNotNull();
    assertThat(this.queries.get(0))
        .contains("trust_mark_type=https%3A%2F%2Fexample.com%2Fmark-one")
        .contains("sub=https%3A%2F%2Fclient.example.com");
  }

  @Test
  void anEndpointThatAnswersNotFoundGivesNothing() throws Exception {
    this.status = 404;
    final int port = this.startServer();

    assertThat(new HttpFederationClient().resolve(this.resolveRequest(port))).isNull();
  }

  @Test
  void anEndpointThatFailsIsAnError() throws Exception {
    this.status = 500;
    this.body = "server error";
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("500");
  }

  @Test
  void anEndpointThatDoesNotAnswerWithASignedJwtIsAnError() throws Exception {
    this.body = "not a jwt";
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("signed JWT");
  }

  @Test
  void anEndpointThatAnswersWithAnEmptyBodyIsAnError() throws Exception {
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("empty body");
  }

  @Test
  void anEndpointThatCannotBeReachedIsAnError() {
    assertThatThrownBy(() -> new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "http://localhost:1/resolve"))))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aRequestWithoutAnEndpointIsAnError() {
    assertThatThrownBy(() -> new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE), Map.of())))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT);
  }

  @Test
  void theCallsThatTheClientRegistryDoesNotMakeAreNotImplemented() {
    final HttpFederationClient client = new HttpFederationClient();
    assertThatThrownBy(() -> client.entityConfiguration(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.fetch(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.subordinateListing(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.trustMarkedListing(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.trustMarkStatus(null)).isInstanceOf(UnsupportedOperationException.class);
  }

  private FederationRequest<ResolveRequest> resolveRequest(final int port) {
    return new FederationRequest<>(new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT,
            URI.create("http://localhost:%d/resolve".formatted(port)).toString()));
  }

  /**
   * Starts an HTTP server that records the query and answers with the configured status and body.
   *
   * @return the port that the server listens on
   * @throws IOException if the server cannot be started
   */
  private int startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", this::handle);
    this.server.start();
    return this.server.getAddress().getPort();
  }

  private void handle(final HttpExchange exchange) throws IOException {
    this.queries.add(exchange.getRequestURI().getRawQuery());
    final byte[] bytes = this.body.getBytes(StandardCharsets.UTF_8);
    if (bytes.length == 0) {
      exchange.sendResponseHeaders(this.status, -1);
      exchange.close();
      return;
    }
    exchange.sendResponseHeaders(this.status, bytes.length);
    try (final OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

}
