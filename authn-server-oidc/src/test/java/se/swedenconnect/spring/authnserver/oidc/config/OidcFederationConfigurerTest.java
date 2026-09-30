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
package se.swedenconnect.spring.authnserver.oidc.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.Filter;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
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

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.oidc.federation.FederationSupport;
import se.swedenconnect.spring.authnserver.oidc.federation.OidcEntityMetadata;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.scope.TestAuthenticationProvider;

/**
 * Tests for {@link OidcFederationConfigurer}: the entity configuration as it is published through the filter chain.
 *
 * @author Martin Lindström
 */
class OidcFederationConfigurerTest {

  private static final String BASE_URL = FederationSupport.ENTITY_ID;

  private static final String AUTHORITY = "https://intermediate.example.com";

  private static final FederationKey ACTIVE = FederationKey.active(KeyTestSupport.rsa("fed-rsa", 2048));

  private static final FederationKey FUTURE = FederationKey.future(KeyTestSupport.ec("fed-ec", "secp256r1"));

  private static final EntityInformation INFORMATION = new EntityInformation(
      new EntityInformation.UiInfo(Map.of("sv", "Exempel-OP"), null,
          List.of(new EntityInformation.Logo(null, "/logo.svg", 64, 64, null))),
      new EntityInformation.Organization(Map.of("sv", "Exempel AB"), null, Map.of("sv", "https://www.example.se"),
          "5561234567"),
      Map.of(EntityInformation.ContactPersonType.technical,
          new EntityInformation.ContactPerson(null, null, null, List.of("ops@example.com"), null)));

  private static Consumer<AuthnServerConfigurer> customizer;

  private static AuthnServerConfigurer built;

  private AnnotationConfigWebApplicationContext context;

  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .entityInformation(INFORMATION)
          .authenticationProvider(new TestAuthenticationProvider("one",
              List.of("http://id.elegnamnden.se/loa/1.0/loa3"),
              List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER), List.of()))
          .protocol(new OidcProviderConfigurer()
              .signingKeys(List.of(SigningKey.active(KeyTestSupport.rsa("op-rsa", 2048))))
              .federation(f -> f
                  .enabled(true)
                  .authorityHints(List.of(AUTHORITY))
                  .keys(List.of(FUTURE, ACTIVE))));
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      built = configurer;
      return http.build();
    }
  }

  @AfterEach
  void close() {
    if (this.context != null) {
      this.context.close();
      this.context = null;
    }
  }

  @Test
  void theEntityConfigurationIsPublishedSignedWithTheActiveKey() throws Exception {
    this.start(c -> {});

    final MockHttpServletResponse response = this.get("/.well-known/openid-federation");

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).isEqualTo("application/entity-statement+jwt");
    final SignedJWT jwt = SignedJWT.parse(response.getContentAsString());
    assertThat(jwt.getHeader().getType().getType()).isEqualTo("entity-statement+jwt");
    assertThat(jwt.getHeader().getKeyID()).isEqualTo(ACTIVE.getKeyId());

    final JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertThat(claims.getIssuer()).isEqualTo(BASE_URL);
    assertThat(claims.getSubject()).isEqualTo(BASE_URL);
    assertThat(claims.getStringListClaim("authority_hints")).containsExactly(AUTHORITY);
    assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
        .isEqualTo(Duration.ofDays(1));
    assertThat(claims.getClaim("trust_marks")).isNull();

    final JWKSet published = JWKSet.parse(claims.getJSONObjectClaim("jwks"));
    assertThat(published.getKeys()).hasSize(2);
    assertThat(jwt.verify(new RSASSAVerifier((RSAKey) published.getKeyByKeyId(ACTIVE.getKeyId())))).isTrue();
    assertThat(published.getKeyByKeyId(FUTURE.getKeyId())).isInstanceOf(ECKey.class);

    assertThat(claims.getJSONObjectClaim("metadata")).containsOnlyKeys("openid_provider");
    final Map<String, Object> op = this.providerMetadata(claims);
    final Map<String, Object> discovery = this.discovery();
    discovery.forEach((name, value) -> assertThat(op).containsEntry(name, value));
    assertThat(op)
        .containsEntry("display_name#sv", "Exempel-OP")
        .containsEntry("organization_name#sv", "Exempel AB")
        .containsEntry("organization_uri", "https://www.example.se")
        .containsEntry("organization_identifier", "urn:glue:iso6523:0007:5561234567")
        .containsEntry("logo_uri", BASE_URL + "/logo.svg")
        .containsEntry("contacts", List.of("ops@example.com"))
        .containsEntry("client_registration_types_supported", List.of("automatic"));
  }

  @Test
  void theTrustMarksOfTheProviderArePublished() throws Exception {
    final ECKey issuerKey = FederationSupport.key("tmi");
    final Instant now = Instant.now();
    final SignedJWT mark = FederationSupport.trustMark(issuerKey, FederationSupport.LOA3, now,
        now.plus(Duration.ofDays(30)));
    final ProviderTrustMarks trustMarks = new ProviderTrustMarks(BASE_URL,
        List.of(FederationSupport.source(FederationSupport.LOA3, issuerKey)),
        new FederationSupport.StubFederationClient().answer(mark), null, Duration.ofMinutes(5),
        Clock.systemUTC());
    trustMarks.refresh();
    this.start(c -> oidc(c).federation(f -> f.providerTrustMarks(trustMarks)));

    final JWTClaimsSet claims = SignedJWT.parse(this.get("/.well-known/openid-federation").getContentAsString())
        .getJWTClaimsSet();

    assertThat(claims.getListClaim("trust_marks"))
        .containsExactly(Map.of("trust_mark_type", FederationSupport.LOA3, "trust_mark", mark.serialize()));
    assertThat(oidc(built).getFederation().getProviderTrustMarks()).isSameAs(trustMarks);
    trustMarks.close();
  }

  @Test
  void theDiscoveryAdditionsAffectBothDocumentsAndTheFederationAdditionsOnlyTheEntityConfiguration()
      throws Exception {
    this.start(c -> oidc(c)
        .discoveryEndpoint(d -> d
            .additionalParameters(Map.of("service_documentation", "https://op.example.com/docs"))
            .providerMetadataCustomizer(m -> m.setCustomParameter("display_name#sv", "Från discovery")))
        .federation(f -> f
            .additionalParameters(Map.of("trust_anchor_hints", List.of("https://ta.example.com"),
                "metadata", Map.of("openid_provider", Map.of("federation_only", "a"))))
            .entityConfigurationCustomizer(claims -> claims.put("custom_claim", "b"))));

    final Map<String, Object> discovery = this.discovery();
    final JWTClaimsSet claims = SignedJWT.parse(this.get("/.well-known/openid-federation").getContentAsString())
        .getJWTClaimsSet();
    final Map<String, Object> op = this.providerMetadata(claims);

    assertThat(discovery).containsEntry("service_documentation", "https://op.example.com/docs")
        .containsEntry("display_name#sv", "Från discovery")
        .doesNotContainKeys("federation_only", "trust_anchor_hints", "custom_claim");
    assertThat(op).containsEntry("service_documentation", "https://op.example.com/docs")
        .containsEntry("display_name#sv", "Från discovery")
        .containsEntry("federation_only", "a");
    assertThat(claims.getStringListClaim("trust_anchor_hints")).containsExactly("https://ta.example.com");
    assertThat(claims.getStringClaim("custom_claim")).isEqualTo("b");
  }

  @Test
  void theOidcOverridesWin() throws Exception {
    this.start(c -> oidc(c)
        .entityInformation(new EntityInformation(new EntityInformation.UiInfo(Map.of("en", "Example OP"), null,
            null), null, null))
        .entityMetadata(new OidcEntityMetadata(null, null, null, null, null, "https://cdn.example.com/logo.svg",
            List.of("support@example.com"))));

    final Map<String, Object> op = this.providerMetadata(
        SignedJWT.parse(this.get("/.well-known/openid-federation").getContentAsString()).getJWTClaimsSet());

    assertThat(op).containsEntry("display_name#en", "Example OP").doesNotContainKey("display_name#sv")
        .containsEntry("organization_name#sv", "Exempel AB")
        .containsEntry("logo_uri", "https://cdn.example.com/logo.svg")
        .containsEntry("contacts", List.of("support@example.com"));
  }

  @Test
  void anIssuerWithAPathMovesTheEndpoint() throws Exception {
    this.start(c -> oidc(c).issuer(BASE_URL + "/op1"));

    assertThat(this.get("/op1/.well-known/openid-federation").getContentType())
        .isEqualTo("application/entity-statement+jwt");
    assertThat(SignedJWT.parse(this.get("/op1/.well-known/openid-federation").getContentAsString())
        .getJWTClaimsSet().getIssuer()).isEqualTo(BASE_URL + "/op1");
  }

  @Test
  void withoutFederationNothingIsPublished() throws Exception {
    this.start(c -> oidc(c).federation(f -> f.enabled(false)));

    final MockHttpServletResponse response = this.get("/.well-known/openid-federation");
    assertThat(response.getContentType()).isNull();
    assertThat(response.getContentAsString()).isEmpty();
  }

  @Test
  void theStartupChecksAreMade() {
    assertThatThrownBy(() -> this.start(c -> oidc(c).federation(f -> f.keys(null))))
        .rootCause().isInstanceOf(IllegalArgumentException.class).hasMessageContaining("federation keys");
    assertThatThrownBy(() -> this.start(c -> oidc(c).federation(f -> f.authorityHints(List.of()))))
        .rootCause().isInstanceOf(IllegalArgumentException.class).hasMessageContaining("authority hints");
    assertThatThrownBy(() -> this.start(c -> oidc(c).entityMetadata(
        new OidcEntityMetadata(null, null, null, null, null, null, List.of("nope")))))
        .rootCause().isInstanceOf(IllegalArgumentException.class).hasMessageContaining("contacts");
    assertThatThrownBy(() -> this.start(c -> oidc(c).entityMetadata(
        new OidcEntityMetadata(null, null, null, null, null, "http://op.example.com/logo.svg", null))))
        .rootCause().isInstanceOf(IllegalArgumentException.class).hasMessageContaining("logo_uri");
    assertThatThrownBy(() -> this.start(c -> oidc(c).federation(f -> f.additionalParameters(
        Map.of("metadata", Map.of("federation_entity", Map.of()))))))
        .rootCause().hasMessageContaining("federation_entity");
  }

  private void start(final Consumer<AuthnServerConfigurer> c) {
    customizer = c;
    this.close();
    this.context = new AnnotationConfigWebApplicationContext();
    this.context.setServletContext(new MockServletContext());
    this.context.register(TestConfiguration.class);
    this.context.refresh();
  }

  private static OidcProviderConfigurer oidc(final AuthnServerConfigurer configurer) {
    return configurer.getProtocolConfigurer(OidcProviderConfigurer.class);
  }

  private MockHttpServletResponse get(final String path) throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    final Filter filter = this.context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private Map<String, Object> discovery() throws Exception {
    return JSONObjectUtils.parse(this.get("/.well-known/openid-configuration").getContentAsString());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> providerMetadata(final JWTClaimsSet claims) throws Exception {
    return (Map<String, Object>) claims.getJSONObjectClaim("metadata").get("openid_provider");
  }

}
