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
package se.swedenconnect.spring.authnserver.saml.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.Filter;

import java.io.ByteArrayInputStream;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.web.Saml2IdpMetadataEndpointFilter;

/**
 * Test cases for {@link Saml2IdpConfigurer}, building a working filter chain without the autoconfiguration.
 *
 * @author Martin Lindström
 */
class Saml2IdpConfigurerTest extends OpenSamlTestBase {

  private static final String BASE_URL = "https://idp.example.com/auth";

  /** The customization of the configurer for the current test. */
  private static Consumer<AuthnServerConfigurer> customizer;

  /** The configuration that an application without Spring Boot would write. */
  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .protocol(new Saml2IdpConfigurer()
              .defaultCredential(TestCredentials.SIGN));
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      return http.build();
    }
  }

  @Test
  void theMetadataIsServedAtTheMetadataEndpoint() throws Exception {
    try (final AnnotationConfigWebApplicationContext context = context(c -> {})) {
      final MockHttpServletResponse response = get(context, "/saml2/metadata", null);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentType()).startsWith("application/xml");

      final EntityDescriptor ed = parse(response);
      assertThat(ed.getEntityID()).isEqualTo(BASE_URL);
      assertThat(ed.getSignature()).isNotNull();

      final MockHttpServletResponse response2 =
          get(context, "/saml2/metadata", Saml2IdpMetadataEndpointFilter.APPLICATION_SAML_METADATA.toString());
      assertThat(response2.getContentType()).startsWith("application/samlmetadata+xml");
    }
  }

  @Test
  void changingTheSamlPathMovesEveryEndpoint() throws Exception {
    try (final AnnotationConfigWebApplicationContext context =
        context(c -> c.protocol(Saml2IdpConfigurer.class, s -> s.path("/idp")))) {

      final MockHttpServletResponse response = get(context, "/idp/metadata", null);
      assertThat(response.getStatus()).isEqualTo(200);
      final EntityDescriptor ed = parse(response);
      assertThat(ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices())
          .extracting(SingleSignOnService::getLocation)
          .containsExactly(BASE_URL + "/idp/redirect/authn", BASE_URL + "/idp/post/authn");

      final SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
      assertThat(chain.matches(request("GET", "/idp/redirect/authn"))).isTrue();
      assertThat(chain.matches(request("POST", "/idp/post/authn"))).isTrue();
      assertThat(chain.matches(request("GET", "/saml2/redirect/authn"))).isFalse();
      assertThat(chain.matches(request("GET", "/saml2/metadata"))).isFalse();
    }
  }

  @Test
  void theChainMatchesTheSamlEndpointsOnly() throws Exception {
    try (final AnnotationConfigWebApplicationContext context = context(c -> c.protocol(Saml2IdpConfigurer.class,
        s -> s.hokRedirectAuthnEndpoint("/hok/redirect")))) {
      final SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
      assertThat(chain.matches(request("GET", "/saml2/redirect/authn"))).isTrue();
      assertThat(chain.matches(request("POST", "/saml2/post/authn"))).isTrue();
      assertThat(chain.matches(request("GET", "/saml2/hok/redirect"))).isTrue();
      assertThat(chain.matches(request("GET", "/saml2/metadata"))).isTrue();
      assertThat(chain.matches(request("POST", "/saml2/metadata"))).isFalse();
      assertThat(chain.matches(request("GET", "/other"))).isFalse();
    }
  }

  @Test
  void aMissingValueFailsWhenTheChainIsBuilt() {
    assertThatThrownBy(() -> context(c -> c.protocol(Saml2IdpConfigurer.class, s -> s.defaultCredential(null))))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause().hasMessageContaining("Missing SAML signing credential");
  }

  private static AnnotationConfigWebApplicationContext context(final Consumer<AuthnServerConfigurer> c) {
    customizer = c;
    final AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
    context.setServletContext(new MockServletContext());
    context.register(TestConfiguration.class);
    try {
      context.refresh();
    }
    catch (final RuntimeException e) {
      context.close();
      throw e;
    }
    return context;
  }

  private static MockHttpServletResponse get(final AnnotationConfigWebApplicationContext context, final String path,
      final String accept) throws Exception {
    final Filter filter = context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletRequest request = request("GET", path);
    if (accept != null) {
      request.addHeader("Accept", accept);
    }
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private static MockHttpServletRequest request(final String method, final String path) {
    final MockHttpServletRequest request = new MockHttpServletRequest(method, path);
    request.setServletPath(path);
    return request;
  }

  private static EntityDescriptor parse(final MockHttpServletResponse response) throws Exception {
    return (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(response.getContentAsByteArray()));
  }

}
