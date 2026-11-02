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
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * Tests that a deployment can replace the {@code service_documentation} that the reference publishes in its discovery
 * document. The default value is tested in {@link PublishedInformationTest}.
 *
 * @author Martin Lindström
 */
class ServiceDocumentationTest {

  @Test
  void aConfiguredServiceDocumentationReplacesTheDefault() throws Exception {
    final int port = freePort();
    final String baseUrl = "https://localhost:" + port;
    try (final ConfigurableApplicationContext context = new SpringApplication(ReferenceApplication.class).run(
        "--spring.profiles.active=complete",
        "--server.port=" + port,
        "--management.server.port=" + freePort(),
        "--authn-server.base-url=" + baseUrl,
        "--authn-server.saml.entity-id=" + baseUrl + "/saml",
        "--authn-server.oidc.issuer=" + baseUrl,
        "--authn-server.oidc.discovery.additional-parameters.service_documentation=https://op.example.com/docs")) {

      final Map<String, Object> document = JSONObjectUtils.parse(
          new TestBrowser().get(baseUrl + "/.well-known/openid-configuration").body());
      assertThat(JSONObjectUtils.getString(document, "service_documentation"))
          .isEqualTo("https://op.example.com/docs");
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
