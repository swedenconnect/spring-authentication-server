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

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.federation.OidcEntityMetadata;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests what the reference publishes about itself, with display names per protocol and a shared description, and that
 * the OpenID Connect clients of {@code authn-server.oidc.clients} are found.
 *
 * @author Martin Lindström
 */
class PublishedInformationTest extends AbstractCompleteProfileTest {

  @Autowired
  private ConfiguredAuthnServer server;

  @Test
  void theSamlMetadataHasTheSamlDisplayNamesAndTheSharedDescription() throws Exception {
    final HttpResponse<String> response = new TestBrowser().get(BASE_URL + "/saml2/metadata");
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body())
        .contains(">Sweden Connect Reference IdP<", ">Sweden Connect Referens-IdP<")
        .contains(">Sweden Connect Reference Authentication Service<", ">Sweden Connect referens-legitimeringstjänst<")
        .doesNotContain("Reference OP", "Referens-OP");
  }

  @Test
  void theOpenIdProviderMetadataHasTheOidcDisplayNamesAndTheSharedDescription() {
    final OidcEntityMetadata metadata = this.server.getConfigurer()
        .getProtocolConfigurer(OidcProviderConfigurer.class)
        .getEntityMetadata();
    assertThat(metadata.displayNames())
        .containsEntry("en", "Sweden Connect Reference OP")
        .containsEntry("sv", "Sweden Connect Referens-OP");
    assertThat(metadata.descriptions())
        .containsEntry("en", "Sweden Connect Reference Authentication Service")
        .containsEntry("sv", "Sweden Connect referens-legitimeringstjänst");
  }

  @Test
  void theOidcClientsOfThePropertiesAreFound() throws Exception {
    final RequesterRecord inline = this.server.getClientRegistry()
        .lookup(AuthenticationProtocol.OIDC, "https://inline.test.local");
    assertThat(inline).isNotNull();
    assertThat(inline.marks()).containsExactly("https://inline.test.local/trust-mark");
    assertThat(this.server.getClientRegistryBackends().stream()
        .filter(b -> b.getProtocol() == AuthenticationProtocol.OIDC)
        .flatMap(b -> b.getClients().stream())
        .map(RegisteredClient::source)
        .distinct())
        .containsExactly("properties");
    assertThat(this.server.getClientRegistry().lookup(AuthenticationProtocol.OIDC, OidcFlowTest.CLIENT_ID))
        .isNotNull();
  }

}
