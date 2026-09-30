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
package se.swedenconnect.spring.authnserver.starter.saml;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.ClassUtils;

/**
 * Tests that a SAML-only application using the SAML starter starts and publishes its metadata, without the OIDC
 * module.
 *
 * @author Martin Lindström
 */
@SpringBootTest(classes = SamlStarterTest.TestApplication.class, properties = {
    "authn-server.base-url=https://idp.example.com",
    "authn-server.saml.enabled=true",
    "authn-server.saml.credentials.default-credential.jks.store.location=classpath:credentials/idp-credentials.p12",
    "authn-server.saml.credentials.default-credential.jks.store.password=secret",
    "authn-server.saml.credentials.default-credential.jks.store.type=PKCS12",
    "authn-server.saml.credentials.default-credential.jks.key.alias=sign",
    "authn-server.saml.credentials.default-credential.jks.key.key-password=secret"
})
class SamlStarterTest {

  /** The test application. */
  @SpringBootApplication
  static class TestApplication {
  }

  @Autowired
  @Qualifier("springSecurityFilterChain")
  private Filter securityFilter;

  @Test
  void theOidcModuleIsNotOnTheClasspath() {
    assertThat(ClassUtils.isPresent("se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry", null)).isFalse();
  }

  @Test
  void theMetadataIsPublished() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/saml2/metadata");
    request.setServletPath("/saml2/metadata");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.securityFilter.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).contains("entityID=\"https://idp.example.com\"");
  }

}
