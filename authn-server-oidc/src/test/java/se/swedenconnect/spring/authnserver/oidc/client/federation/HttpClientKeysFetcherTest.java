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
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;
import com.sun.net.httpserver.HttpServer;

/**
 * Tests for {@link HttpClientKeysFetcher}.
 *
 * @author Martin Lindström
 */
class HttpClientKeysFetcherTest extends FederationTestSupport {

  private static final ECKey ENTITY_KEY = key("entity-key");

  private HttpServer server;

  private final List<String> paths = new ArrayList<>();

  private final List<FederationCallEvent> events = new ArrayList<>();

  private HttpClientKeysFetcher fetcher;

  @BeforeEach
  void startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", exchange -> {
      final String path = exchange.getRequestURI().getPath();
      this.paths.add(path);
      int status = 200;
      String contentType = "application/json";
      final String body;
      switch (path) {
        case "/jwks" -> body = publicKeys(CLIENT_KEY).toString();
        case "/not-jwks" -> body = "{\"keys\": 17}";
        case "/signed" -> {
          contentType = HttpClientKeysFetcher.SIGNED_JWKS_CONTENT_TYPE;
          body = signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)).serialize();
        }
        case "/signed-created" -> {
          status = 201;
          contentType = HttpClientKeysFetcher.SIGNED_JWKS_CONTENT_TYPE;
          body = signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)).serialize();
        }
        case "/signed-as-json" -> body = signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)).serialize();
        case "/signed-not-jwt" -> {
          contentType = HttpClientKeysFetcher.SIGNED_JWKS_CONTENT_TYPE;
          body = "not a JWT";
        }
        case "/large" -> body = "{\"keys\": [], \"x\": \"" + "x".repeat(200) + "\"}";
        case "/redirect" -> {
          status = 302;
          body = "";
          exchange.getResponseHeaders().add("Location", "/jwks");
        }
        default -> {
          status = 404;
          body = "{}";
        }
      }
      exchange.getResponseHeaders().add("Content-Type", contentType);
      final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
      try (final OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
    });
    this.server.start();
    this.fetcher = new HttpClientKeysFetcher();
    this.fetcher.setApplicationEventPublisher(e -> this.events.add((FederationCallEvent) e));
  }

  @AfterEach
  void stopServer() {
    this.server.stop(0);
  }

  @Test
  void aJwkSetIsFetchedAndTheCallShowsInHealth() throws IOException {
    assertThat(this.fetcher.fetchJwks(this.uri("/jwks")).getKeyByKeyId(CLIENT_KEY.getKeyID())).isNotNull();

    assertThat(this.events).singleElement().satisfies(e -> {
      assertThat(e.getCall()).isEqualTo(FederationCallEvent.Call.CLIENT_KEYS);
      assertThat(e.getServiceType()).isEqualTo(FederationCallEvent.ServiceType.CLIENT_KEYS);
      assertThat(e.getServiceId()).isEqualTo(this.uri("/jwks").toString());
      assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.SUCCESS);
    });
  }

  @Test
  void aSignedJwkSetIsFetchedWithoutBeingVerified() throws IOException {
    assertThat(this.fetcher.fetchSignedJwks(this.uri("/signed")).getHeader().getKeyID())
        .isEqualTo(ENTITY_KEY.getKeyID());
    assertThat(this.events).singleElement()
        .satisfies(e -> assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.SUCCESS));
  }

  @Test
  void aSignedJwkSetMustBeAnsweredWithStatus200AndItsContentType() {
    assertThatThrownBy(() -> this.fetcher.fetchSignedJwks(this.uri("/signed-created")))
        .isInstanceOf(IOException.class)
        .hasMessage("HTTP status 201");
    assertThatThrownBy(() -> this.fetcher.fetchSignedJwks(this.uri("/signed-as-json")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("content type");
    assertThatThrownBy(() -> this.fetcher.fetchSignedJwks(this.uri("/signed-not-jwt")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not a signed JWT");
    assertThat(this.events).hasSize(3).allSatisfy(
        e -> assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.ERROR_RESPONSE));
  }

  @Test
  void anAnswerThatIsNotAJwkSetCannotBeRead() {
    assertThatThrownBy(() -> this.fetcher.fetchJwks(this.uri("/not-jwks")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not a JWK Set");
    assertThatThrownBy(() -> this.fetcher.fetchJwks(this.uri("/missing")))
        .isInstanceOf(IOException.class)
        .hasMessage("HTTP status 404");
    assertThat(this.events).hasSize(2).allSatisfy(e -> {
      assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.ERROR_RESPONSE);
      assertThat(e.getError()).isNotNull();
    });
  }

  @Test
  void aRedirectIsNotFollowed() {
    assertThatThrownBy(() -> this.fetcher.fetchJwks(this.uri("/redirect")))
        .isInstanceOf(IOException.class)
        .hasMessage("HTTP status 302");
    assertThat(this.paths).containsExactly("/redirect");
  }

  @Test
  void anAnswerLargerThanTheMaximumSizeCannotBeRead() throws IOException {
    final HttpClientKeysFetcher small = new HttpClientKeysFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(5),
        100);
    assertThatThrownBy(() -> small.fetchJwks(this.uri("/large")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("larger than 100 bytes");
    assertThat(new HttpClientKeysFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(5), 1000)
        .fetchJwks(this.uri("/jwks")).getKeys()).hasSize(1);
  }

  @Test
  void anUnreachableHostIsShownAsUnreachable() throws IOException {
    final int port;
    try (final ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    assertThatThrownBy(() -> this.fetcher.fetchJwks(URI.create("http://localhost:" + port + "/jwks")))
        .isInstanceOf(IOException.class);
    assertThat(this.events).singleElement()
        .satisfies(e -> assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.UNREACHABLE));
  }

  @Test
  void withoutAnEventPublisherNothingIsPublished() throws IOException {
    assertThat(new HttpClientKeysFetcher().fetchJwks(this.uri("/jwks")).getKeys()).hasSize(1);
    assertThat(this.events).isEmpty();
  }

  @Test
  void theMaximumSizeMustBePositive() {
    assertThatThrownBy(() -> new HttpClientKeysFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(1), 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private URI uri(final String path) {
    return URI.create("http://localhost:" + this.server.getAddress().getPort() + path);
  }

}
