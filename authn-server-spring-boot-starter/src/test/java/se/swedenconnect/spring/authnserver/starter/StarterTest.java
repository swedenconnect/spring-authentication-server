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
package se.swedenconnect.spring.authnserver.starter;

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

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Tests that an application using the starter for both protocols starts with both protocols enabled.
 *
 * @author Martin Lindström
 */
@SpringBootTest(classes = StarterTest.TestApplication.class, properties = {
    "spring.application.name=authn-server-test",
    "authn-server.base-url=https://idp.example.com",
    "authn-server.saml.enabled=true",
    "authn-server.oidc.enabled=true",
    "authn-server.saml.credentials.default-credential.jks.store.location=classpath:credentials/idp-credentials.p12",
    "authn-server.saml.credentials.default-credential.jks.store.password=secret",
    "authn-server.saml.credentials.default-credential.jks.store.type=PKCS12",
    "authn-server.saml.credentials.default-credential.jks.key.alias=sign",
    "authn-server.saml.credentials.default-credential.jks.key.key-password=secret",
    "authn-server.saml.metadata-providers[0].location=classpath:metadata/sp-metadata.xml",
    "authn-server.oidc.keys.signing[0].credential.jks.store.location=classpath:credentials/oidc-keys.p12",
    "authn-server.oidc.keys.signing[0].credential.jks.store.password=secret",
    "authn-server.oidc.keys.signing[0].credential.jks.store.type=PKCS12",
    "authn-server.oidc.keys.signing[0].credential.jks.key.alias=rsa-sign",
    "authn-server.oidc.keys.signing[0].credential.jks.key.key-password=secret"
})
class StarterTest {

  /** The test application. */
  @SpringBootApplication
  static class TestApplication {
  }

  @Autowired
  @Qualifier("springSecurityFilterChain")
  private Filter securityFilter;

  @Test
  void theSamlMetadataIsPublished() throws Exception {
    assertThat(this.get("/saml2/metadata").getStatus()).isEqualTo(200);
  }

  @Test
  void theOidcDiscoveryDocumentAndJwksArePublished() throws Exception {
    final MockHttpServletResponse discovery = this.get("/.well-known/openid-configuration");
    assertThat(discovery.getStatus()).isEqualTo(200);
    assertThat(OIDCProviderMetadata.parse(discovery.getContentAsString()).getIssuer().getValue())
        .isEqualTo("https://idp.example.com");
    assertThat(this.get("/oidc/jwks").getStatus()).isEqualTo(200);
  }

  private MockHttpServletResponse get(final String path) throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.securityFilter.doFilter(request, response, new MockFilterChain());
    return response;
  }

}
