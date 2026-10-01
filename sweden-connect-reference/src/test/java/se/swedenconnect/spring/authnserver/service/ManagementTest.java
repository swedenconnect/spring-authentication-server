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

import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Map;

import org.apache.catalina.connector.Connector;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.context.WebServerApplicationContext;

import se.swedenconnect.spring.authnserver.service.config.TomcatAjpCustomizer;

/**
 * Tests the Actuator, which answers on the management port only, and that the AJP connector is not started by
 * default.
 *
 * @author Martin Lindström
 */
class ManagementTest extends AbstractCompleteProfileTest {

  /** The base URL of the Actuator. */
  static final String ACTUATOR = "https://localhost:" + MANAGEMENT_PORT + "/actuator";

  @Autowired
  private WebServerApplicationContext context;

  @Test
  void healthAndInfoAnswerOnTheManagementPort() throws Exception {
    final HttpResponse<String> health = new TestBrowser().get(ACTUATOR + "/health");
    assertThat(health.statusCode()).isEqualTo(200);
    assertThat(health.body()).contains("\"status\":\"UP\"");

    final HttpResponse<String> info = new TestBrowser().get(ACTUATOR + "/info");
    assertThat(info.statusCode()).isEqualTo(200);
  }

  @Test
  void theClientsEndpointIsReadOnly() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final HttpResponse<String> clients = browser.get(ACTUATOR + "/clients");
    assertThat(clients.statusCode()).isEqualTo(200);
    assertThat(clients.body()).contains("https://rp.test.local").contains("https://sp.test.local");

    final HttpResponse<String> update = browser.post(ACTUATOR + "/clients/oidc?id=https%3A%2F%2Frp.test.local",
        Map.of());
    assertThat(update.statusCode()).isEqualTo(405);
  }

  @Test
  void theActuatorDoesNotAnswerOnTheServicePort() throws Exception {
    final TestBrowser browser = new TestBrowser();
    assertThat(browser.get(BASE_URL + "/actuator/health").statusCode()).isEqualTo(403);
    assertThat(browser.get(BASE_URL + "/actuator/clients").statusCode()).isEqualTo(403);
  }

  @Test
  void theAjpConnectorIsNotStartedByDefault() {
    assertThat(this.context.getBeanProvider(TomcatAjpCustomizer.class).getIfAvailable()).isNull();
    final Connector[] connectors =
        ((TomcatWebServer) this.context.getWebServer()).getTomcat().getService().findConnectors();
    assertThat(connectors).isNotEmpty();
    assertThat(Arrays.stream(connectors).map(Connector::getProtocol)).noneMatch(p -> p.startsWith("AJP"));
  }

}
