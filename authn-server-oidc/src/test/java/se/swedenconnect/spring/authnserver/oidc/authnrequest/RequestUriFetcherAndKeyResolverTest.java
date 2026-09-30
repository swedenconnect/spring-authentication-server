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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.sun.net.httpserver.HttpServer;

import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;

/**
 * Tests for {@link HttpRequestUriFetcher} and {@link DefaultClientKeyResolver}.
 *
 * @author Martin Lindström
 */
class RequestUriFetcherAndKeyResolverTest {

  private HttpServer server;

  private String baseUrl;

  @BeforeEach
  void startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/ro", exchange -> respond(exchange, 200, " eyJ.payload.sig \n"));
    this.server.createContext("/missing", exchange -> respond(exchange, 404, "not found"));
    this.server.createContext("/large", exchange -> respond(exchange, 200, "x".repeat(200)));
    this.server.createContext("/jwks", exchange -> respond(exchange, 200,
        new JWKSet(clientJwk()).toString()));
    this.server.start();
    this.baseUrl = "http://localhost:" + this.server.getAddress().getPort();
  }

  @AfterEach
  void stopServer() {
    this.server.stop(0);
  }

  @Test
  void aRequestObjectIsFetched() throws Exception {
    assertThat(new HttpRequestUriFetcher().fetch(URI.create(this.baseUrl + "/ro"))).isEqualTo("eyJ.payload.sig");
  }

  @Test
  void anErrorStatusOrATooLargeObjectFails() {
    final HttpRequestUriFetcher fetcher =
        new HttpRequestUriFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(2), 100);
    assertThatThrownBy(() -> fetcher.fetch(URI.create(this.baseUrl + "/missing")))
        .isInstanceOf(IOException.class).hasMessageContaining("404");
    assertThatThrownBy(() -> fetcher.fetch(URI.create(this.baseUrl + "/large")))
        .isInstanceOf(IOException.class).hasMessageContaining("larger than");
    assertThatThrownBy(() -> new HttpRequestUriFetcher(HttpClient.newHttpClient(), Duration.ofSeconds(2), 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theKeysComeFromJwksOrJwksUri() throws Exception {
    final DefaultClientKeyResolver resolver = new DefaultClientKeyResolver();
    final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("client-key").build();

    final OIDCClientMetadata inline = new OIDCClientMetadata();
    inline.setJWKSet(new JWKSet(clientJwk()));
    assertThat(resolver.resolve("client", inline, header)).hasSize(1);
    assertThat(resolver.resolve("client", inline,
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("other").build())).isEmpty();

    final OIDCClientMetadata remote = new OIDCClientMetadata();
    remote.setJWKSetURI(URI.create(this.baseUrl + "/jwks"));
    assertThat(resolver.resolve("client", remote, header)).hasSize(1);
    // Cached source is reused
    assertThat(resolver.resolve("client", remote, header)).hasSize(1);

    assertThat(resolver.resolve("client", new OIDCClientMetadata(), header)).isEqualTo(List.of());
  }

  private static RSAKey clientJwk() {
    return new RSAKey.Builder((RSAPublicKey) KeyTestSupport.rsa("client", 2048).getPublicKey())
        .keyID("client-key").build();
  }

  private static void respond(final com.sun.net.httpserver.HttpExchange exchange, final int status,
      final String body) throws IOException {
    final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (final OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

}
