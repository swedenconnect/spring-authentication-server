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

import com.sun.net.httpserver.HttpServer;

/**
 * Tests for {@link HttpSectorIdentifierFetcher}.
 *
 * @author Martin Lindström
 */
class HttpSectorIdentifierFetcherTest {

  private HttpServer server;

  private final List<String> paths = new ArrayList<>();

  @BeforeEach
  void startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", exchange -> {
      this.paths.add(exchange.getRequestURI().getPath());
      final String path = exchange.getRequestURI().getPath();
      final int status;
      final String body;
      switch (path) {
        case "/array" -> {
          status = 200;
          body = "[\"https://rp.example.com/cb\", \"https://app.example.com/cb\"]";
        }
        case "/created" -> {
          status = 201;
          body = "[]";
        }
        case "/object" -> {
          status = 200;
          body = "{\"redirect_uris\": [\"https://rp.example.com/cb\"]}";
        }
        case "/numbers" -> {
          status = 200;
          body = "[\"https://rp.example.com/cb\", 17]";
        }
        case "/string" -> {
          status = 200;
          body = "\"https://rp.example.com/cb\"";
        }
        case "/not-json" -> {
          status = 200;
          body = "<html>Not JSON</html>";
        }
        case "/two-values" -> {
          status = 200;
          body = "[], []";
        }
        case "/empty" -> {
          status = 200;
          body = "";
        }
        case "/large" -> {
          status = 200;
          body = "[\"" + "x".repeat(200) + "\"]";
        }
        case "/redirect" -> {
          status = 302;
          body = "";
          exchange.getResponseHeaders().add("Location", "/array");
        }
        default -> {
          status = 404;
          body = "{}";
        }
      }
      final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
      try (final OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
    });
    this.server.start();
  }

  @AfterEach
  void stopServer() {
    this.server.stop(0);
  }

  @Test
  void aJsonArrayOfStringsIsReturned() throws IOException {
    assertThat(new HttpSectorIdentifierFetcher().fetch(this.uri("/array")))
        .containsExactly("https://rp.example.com/cb", "https://app.example.com/cb");
    assertThat(new HttpSectorIdentifierFetcher().fetch(this.uri("/created"))).isEmpty();
  }

  @Test
  void jsonThatIsNotAnArrayOfStringsGivesNull() throws IOException {
    final HttpSectorIdentifierFetcher fetcher = new HttpSectorIdentifierFetcher();
    assertThat(fetcher.fetch(this.uri("/object"))).isNull();
    assertThat(fetcher.fetch(this.uri("/numbers"))).isNull();
    assertThat(fetcher.fetch(this.uri("/string"))).isNull();
  }

  @Test
  void aBodyThatIsNotJsonCannotBeFetched() {
    final HttpSectorIdentifierFetcher fetcher = new HttpSectorIdentifierFetcher();
    for (final String path : List.of("/not-json", "/two-values", "/empty")) {
      assertThatThrownBy(() -> fetcher.fetch(this.uri(path)))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("not valid JSON");
    }
  }

  @Test
  void anAnswerOtherThan2xxCannotBeFetched() {
    assertThatThrownBy(() -> new HttpSectorIdentifierFetcher().fetch(this.uri("/missing")))
        .isInstanceOf(IOException.class)
        .hasMessage("HTTP status 404");
  }

  @Test
  void aRedirectIsNotFollowed() {
    assertThatThrownBy(() -> new HttpSectorIdentifierFetcher().fetch(this.uri("/redirect")))
        .isInstanceOf(IOException.class)
        .hasMessage("HTTP status 302");
    assertThat(this.paths).containsExactly("/redirect");
  }

  @Test
  void aDocumentLargerThanTheMaximumSizeCannotBeFetched() throws IOException {
    final HttpSectorIdentifierFetcher fetcher =
        new HttpSectorIdentifierFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(5), 100);
    assertThatThrownBy(() -> fetcher.fetch(this.uri("/large")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("larger than 100 bytes");
    assertThat(fetcher.fetch(this.uri("/array"))).hasSize(2);
  }

  @Test
  void anUnreachableHostCannotBeFetched() throws IOException {
    final int port;
    try (final ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    assertThatThrownBy(() -> new HttpSectorIdentifierFetcher().fetch(URI.create("http://localhost:" + port + "/")))
        .isInstanceOf(IOException.class);
  }

  @Test
  void theMaximumSizeMustBePositive() {
    assertThatThrownBy(() -> new HttpSectorIdentifierFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(1), 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private URI uri(final String path) {
    return URI.create("http://localhost:" + this.server.getAddress().getPort() + path);
  }

}
