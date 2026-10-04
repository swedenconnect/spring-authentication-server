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
package se.swedenconnect.spring.authnserver.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.context.ConfigurableApplicationContext;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

/**
 * Tests that a request from a client that the configured clients do not know, when the federation cannot be reached,
 * shows the error page with HTTP status 503, and that the server starts although the federation cannot be reached.
 *
 * @author Martin Lindström
 */
class UnreachableFederationTest {

  @TempDir
  Path directory;

  @Test
  void aClientThatCannotBeCheckedShowsTheErrorPageWith503() throws Exception {
    final Path trustAnchorKeys = this.directory.resolve("ta-jwks.json");
    Files.writeString(trustAnchorKeys,
        new JWKSet(new ECKeyGenerator(Curve.P_256).keyID("ta").generate().toPublicJWK()).toString());
    final int port = freePort();
    final String baseUrl = "https://localhost:" + port;
    final String unreachable = "http://localhost:" + freePort();

    try (final ConfigurableApplicationContext context = new SpringApplication(ReferenceApplication.class).run(
        "--spring.profiles.active=complete",
        "--server.port=" + port,
        "--management.server.port=" + freePort(),
        "--authn-server.base-url=" + baseUrl,
        "--authn-server.saml.entity-id=" + baseUrl + "/saml",
        "--authn-server.oidc.issuer=" + baseUrl,
        "--authn-server.oidc.federation.enabled=true",
        "--authn-server.oidc.federation.authority-hints[0]=" + unreachable,
        "--authn-server.oidc.federation.keys[0].credential.bundle=oidc-sign",
        "--authn-server.oidc.federation.trust-anchor.entity-id=" + unreachable,
        "--authn-server.oidc.federation.trust-anchor.jwks=file:" + trustAnchorKeys)) {

      final Instant start = Instant.now();
      final String clientId = "https://federation-rp.test.local";
      final HttpResponse<String> response = new TestBrowser().get(baseUrl + "/oidc/authorize?response_type=code"
          + "&scope=openid&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
          + "&redirect_uri=" + URLEncoder.encode(clientId + "/callback", StandardCharsets.UTF_8));

      AuthorizationErrorPageTest.assertErrorPage(response, 503,
          "The service that sent you here could not be checked right now. Please try again later.");
      assertThat(context.getBean(AuditEventRepository.class).find(clientId, start, "authn_unrecoverable_error"))
          .hasSize(1);

      // A configured client is still served
      final HttpResponse<String> configured = new TestBrowser().get(baseUrl + "/oidc/authorize?response_type=code"
          + "&scope=openid&client_id=" + URLEncoder.encode(OidcFlowTest.CLIENT_ID, StandardCharsets.UTF_8)
          + "&redirect_uri=" + URLEncoder.encode(OidcFlowTest.REDIRECT_URI, StandardCharsets.UTF_8));
      assertThat(configured.statusCode()).isEqualTo(302);
    }
  }

  private static int freePort() {
    try (final ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
    catch (final IOException e) {
      throw new IllegalStateException(e);
    }
  }

}
