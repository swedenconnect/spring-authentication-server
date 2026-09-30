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
package se.swedenconnect.spring.authnserver.autoconfigure.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import se.oidc.nimbus.claims.ParameterConstants;
import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequiredMarksRequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.WhitelistRequesterPredicate;

/**
 * Tests for {@link OidcAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class OidcAutoConfigurationTest {

  private static final String BASE_URL = "https://op.example.com/auth";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String DISCOVERY = "/.well-known/openid-configuration";

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, SamlAutoConfiguration.class, OidcAutoConfiguration.class,
          AuthnServerAutoConfiguration.class))
      .withPropertyValues("authn-server.base-url=" + BASE_URL, "authn-server.oidc.enabled=true");

  /** A provider delivering a personal identity number and names. */
  @Configuration
  static class ProviderConfiguration {

    @Bean
    UserAuthenticationProvider testProvider() {
      return new UserAuthenticationProvider() {

        @Override
        public @NonNull String getName() {
          return "test";
        }

        @Override
        public @NonNull List<String> getSupportedAuthnContextUris() {
          return List.of(LOA3);
        }

        @Override
        public @NonNull List<String> getSupportedAttributes() {
          return List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME,
              AttributeIdentifiers.SURNAME);
        }

        @Override
        public @Nullable Authentication authenticateUser(final @NonNull UserAuthenticationInputToken token) {
          throw new UnsupportedOperationException();
        }
      };
    }
  }

  /** Captures the configurer. */
  @Configuration
  static class CaptureConfiguration {

    static final AtomicReference<AuthnServerConfigurer> CONFIGURER = new AtomicReference<>();

    @Bean
    @Order(10)
    AuthnServerConfigurerAdapter captureAdapter() {
      return (http, configurer) -> CONFIGURER.set(configurer);
    }
  }

  /** Customizes the discovery document through an adapter. */
  @Configuration
  static class CustomizerConfiguration {

    @Bean
    AuthnServerConfigurerAdapter discoveryCustomizer() {
      return (http, configurer) -> configurer.protocol(OidcProviderConfigurer.class, oidc -> oidc.discoveryEndpoint(
          d -> d.providerMetadataCustomizer(m -> m.setCustomParameter("https://example.com/disco/custom", "x"))));
    }
  }

  @Test
  void theDiscoveryDocumentIsServedUnderTheBaseUrl() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", true))
        .withPropertyValues(signingKey(1, "ec-sign", "active", false))
        .withPropertyValues(signingKey(2, "rsa-future", "future", false))
        .withPropertyValues(decryptionKey(0, "rsa-enc", "active"))
        .withPropertyValues("authn-server.oidc.ui-locales=sv,en", "authn-server.oidc.supports-user-message=true")
        .withUserConfiguration(ProviderConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final MockHttpServletResponse response = get(context, DISCOVERY);
          assertThat(response.getStatus()).isEqualTo(200);
          assertThat(response.getContentType()).startsWith("application/json");

          final OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(response.getContentAsString());
          assertThat(metadata.getIssuer().getValue()).isEqualTo(BASE_URL);
          assertThat(metadata.getJWKSetURI()).isEqualTo(URI.create(BASE_URL + "/oidc/jwks"));
          assertThat(metadata.getIDTokenJWSAlgs()).startsWith(JWSAlgorithm.RS256).contains(JWSAlgorithm.ES256)
              .doesNotContain(JWSAlgorithm.ES384);
          assertThat(metadata.getRequestObjectJWEAlgs()).extracting(a -> a.getName())
              .containsExactly("RSA-OAEP-256", "RSA-OAEP");
          assertThat(metadata.getACRs()).extracting(Identifier::getValue).containsExactly(LOA3);
          assertThat(metadata.getScopes().toStringList())
              .containsExactlyInAnyOrder("openid", "profile", "https://id.oidc.se/scope/naturalPersonInfo");
          assertThat(metadata.getClaims()).contains("sub", "given_name", "family_name", "zoneinfo",
              "https://id.oidc.se/claim/personalIdentityNumber");
          assertThat(metadata.getUILocales()).extracting(LangTag::toString).containsExactly("sv", "en");
          assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME))
              .isEqualTo(true);

          assertThat(get(context, "/oidc" + DISCOVERY).getContentAsByteArray()).isEmpty();
        });
  }

  @Test
  void theJwksHoldsThePublishedKeys() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", true))
        .withPropertyValues(signingKey(1, "rsa-future", "future", false))
        .withPropertyValues(decryptionKey(0, "rsa-enc", "active"))
        .withPropertyValues(decryptionKey(1, "rsa-prev-enc", "previous"))
        .run(context -> {
          final MockHttpServletResponse response = get(context, "/oidc/jwks");
          assertThat(response.getStatus()).isEqualTo(200);

          final JWKSet jwks = JWKSet.parse(response.getContentAsString());
          assertThat(jwks.getKeys()).hasSize(3);
          assertThat(jwks.getKeys()).allMatch(k -> k.getKeyID() != null && !k.isPrivate());
          assertThat(jwks.getKeys()).extracting(JWK::getKeyUse)
              .containsExactly(KeyUse.SIGNATURE, KeyUse.SIGNATURE, KeyUse.ENCRYPTION);
          assertThat(response.getContentAsString()).doesNotContain("\"d\"");
        });
  }

  @Test
  void aPreviousDecryptionKeyIsNotPublished() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues(decryptionKey(0, "rsa-prev-enc", "previous"))
        .run(context -> {
          assertThat(context).hasNotFailed();
          final JWKSet jwks = JWKSet.parse(get(context, "/oidc/jwks").getContentAsString());
          assertThat(jwks.getKeys()).extracting(JWK::getKeyUse).containsExactly(KeyUse.SIGNATURE);
          final OIDCProviderMetadata metadata =
              OIDCProviderMetadata.parse(get(context, DISCOVERY).getContentAsString());
          assertThat(metadata.getRequestObjectJWEAlgs()).isNull();
        });
  }

  @Test
  void theDiscoveryDocumentFollowsTheIssuer() {
    this.runner.withPropertyValues(signingKey(0, "ec-sign", "active", false))
        .withPropertyValues("authn-server.oidc.issuer=" + BASE_URL + "/op1", "authn-server.oidc.path=/op1/oidc",
            "authn-server.oidc.endpoints.jwks=/keys")
        .run(context -> {
          assertThat(get(context, DISCOVERY).getContentAsByteArray()).isEmpty();
          final MockHttpServletResponse response = get(context, "/op1" + DISCOVERY);
          assertThat(response.getStatus()).isEqualTo(200);
          final OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(response.getContentAsString());
          assertThat(metadata.getIssuer().getValue()).isEqualTo(BASE_URL + "/op1");
          assertThat(metadata.getJWKSetURI()).isEqualTo(URI.create(BASE_URL + "/op1/oidc/keys"));
          assertThat(get(context, "/op1/oidc/keys").getStatus()).isEqualTo(200);

          final SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
          assertThat(chain.matches(request("GET", "/op1" + DISCOVERY))).isTrue();
          assertThat(chain.matches(request("GET", "/oidc/jwks"))).isFalse();
        });
  }

  @Test
  void theScopeClaimAndDiscoveryPropertiesAreApplied() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues("authn-server.oidc.scopes=email,phone",
            "authn-server.oidc.claims=https://example.com/claim/employee",
            "authn-server.oidc.discovery.additional-parameters.service_documentation=https://op.example.com/docs",
            "authn-server.oidc.discovery.additional-parameters.frontchannel_logout_supported=true",
            "authn-server.oidc.discovery.additional-parameters.example_list[0]=a",
            "authn-server.oidc.discovery.additional-parameters.example_list[1]=b")
        .withUserConfiguration(CustomizerConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final String json = get(context, DISCOVERY).getContentAsString();
          final OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(json);
          assertThat(metadata.getScopes().toStringList()).containsExactly("openid", "email", "phone");
          assertThat(metadata.getClaims()).contains("https://example.com/claim/employee", "email", "phone_number");
          assertThat(metadata.getServiceDocsURI()).isEqualTo(URI.create("https://op.example.com/docs"));
          assertThat(metadata.supportsFrontChannelLogout()).isTrue();
          assertThat(metadata.getCustomParameters().get("example_list"))
              .isEqualTo(List.of("a", "b"));
          assertThat(metadata.getCustomParameters().get("https://example.com/disco/custom")).isEqualTo("x");
        });
  }

  @Test
  void aTooShortKeyFailsStartup() {
    this.runner.withPropertyValues(signingKey(0, "rsa-short", "active", false))
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("at least 2048 bits"));
  }

  @Test
  void theAuthorizationRequestPropertiesAreApplied() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues("authn-server.oidc.endpoints.authorization=/authz",
            "authn-server.oidc.authorization-request.require-pkce=true",
            "authn-server.oidc.authorization-request.require-signed-request-object=true",
            "authn-server.oidc.authorization-request.require-state=false")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final OidcProviderConfigurer oidc =
              CaptureConfiguration.CONFIGURER.get().getProtocolConfigurer(OidcProviderConfigurer.class);
          assertThat(oidc.isRequirePkce()).isTrue();
          assertThat(oidc.isRequireSignedRequestObject()).isTrue();
          assertThat(oidc.isRequireState()).isFalse();

          final OIDCProviderMetadata metadata =
              OIDCProviderMetadata.parse(get(context, DISCOVERY).getContentAsString());
          assertThat(metadata.getAuthorizationEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/authz"));
          assertThat(metadata.getRequestObjectJWSAlgs()).extracting(JWSAlgorithm::getName).doesNotContain("none");

          final SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
          assertThat(chain.matches(request("GET", "/oidc/authz"))).isTrue();
          assertThat(chain.matches(request("POST", "/oidc/authz"))).isTrue();
        });
  }

  @Test
  void theTokenPropertiesAreApplied() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues("authn-server.oidc.endpoints.token=/tokens",
            "authn-server.oidc.endpoints.userinfo=/me",
            "authn-server.oidc.sign-user-info=false",
            "authn-server.oidc.tokens.authorization-code-lifetime=30s",
            "authn-server.oidc.tokens.access-token-lifetime=2m",
            "authn-server.oidc.tokens.access-token-single-use=false",
            "authn-server.oidc.tokens.id-token-lifetime=3m",
            "authn-server.oidc.client-authentication-methods=private_key_jwt,client_secret_basic")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final OidcProviderConfigurer oidc =
              CaptureConfiguration.CONFIGURER.get().getProtocolConfigurer(OidcProviderConfigurer.class);
          assertThat(oidc.getAuthorizationCodeLifetime()).isEqualTo(Duration.ofSeconds(30));
          assertThat(oidc.getAccessTokenLifetime()).isEqualTo(Duration.ofMinutes(2));
          assertThat(oidc.isSingleUseAccessTokens()).isFalse();
          assertThat(oidc.getIdTokenLifetime()).isEqualTo(Duration.ofMinutes(3));
          assertThat(oidc.getClientAuthenticationMethods()).containsExactlyInAnyOrder(
              ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

          final OIDCProviderMetadata metadata =
              OIDCProviderMetadata.parse(get(context, DISCOVERY).getContentAsString());
          assertThat(metadata.getTokenEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/tokens"));
          assertThat(context.getBean(SecurityFilterChain.class).matches(request("POST", "/oidc/tokens"))).isTrue();
          assertThat(oidc.isSignUserInfo()).isFalse();
          assertThat(metadata.getUserInfoEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/me"));
          assertThat(context.getBean(SecurityFilterChain.class).matches(request("GET", "/oidc/me"))).isTrue();
          assertThat(context.getBean(SecurityFilterChain.class).matches(request("POST", "/oidc/me"))).isTrue();
        });
  }

  @Test
  void anUnsupportedClientAuthenticationMethodFailsStartup() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues("authn-server.oidc.client-authentication-methods=none")
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("Unsupported OIDC client authentication method"));
  }

  @Test
  void theAuthorizationRequestDefaultsApply() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final OidcProviderConfigurer oidc =
              CaptureConfiguration.CONFIGURER.get().getProtocolConfigurer(OidcProviderConfigurer.class);
          assertThat(oidc.isRequirePkce()).isFalse();
          assertThat(oidc.isRequireSignedRequestObject()).isFalse();
          assertThat(oidc.isRequireState()).isTrue();
          assertThat(CaptureConfiguration.CONFIGURER.get().getRequesterAcceptance())
              .isSameAs(RequesterAcceptance.acceptAll());
          final OIDCProviderMetadata metadata =
              OIDCProviderMetadata.parse(get(context, DISCOVERY).getContentAsString());
          assertThat(metadata.getAuthorizationEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/authorize"));
          assertThat(metadata.getRequestObjectJWSAlgs()).extracting(JWSAlgorithm::getName).contains("none");
        });
  }

  @Test
  void theAcceptancePropertiesGiveTheOidcPredicates() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues(
            "authn-server.oidc.requester-acceptance.mode=ANY",
            "authn-server.oidc.requester-acceptance.whitelist[0]=https://rp.example.com",
            "authn-server.oidc.requester-acceptance.required-marks[0][0]=https://tm.example.com/a",
            "authn-server.oidc.requester-acceptance.required-marks[0][1]=https://tm.example.com/b")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final ConfigurableRequesterAcceptance acceptance =
              CaptureConfiguration.CONFIGURER.get().configurableRequesterAcceptance();
          assertThat(acceptance.getMode(AuthenticationProtocol.OIDC))
              .isEqualTo(ConfigurableRequesterAcceptance.Mode.ANY);
          assertThat(acceptance.getMode(AuthenticationProtocol.SAML))
              .isEqualTo(ConfigurableRequesterAcceptance.Mode.ALL);
          assertThat(acceptance.getPredicates()).hasSize(2)
              .allMatch(p -> p.getProtocol() == AuthenticationProtocol.OIDC);
          assertThat(acceptance.getPredicates().get(0)).isInstanceOfSatisfying(WhitelistRequesterPredicate.class,
              p -> assertThat(p.getIdentifiers()).containsExactly("https://rp.example.com"));
          assertThat(acceptance.getPredicates().get(1)).isInstanceOfSatisfying(RequiredMarksRequesterPredicate.class,
              p -> assertThat(p.getGroups()).containsExactly(
                  Set.of("https://tm.example.com/a", "https://tm.example.com/b")));
        });
  }

  @Test
  void aMissingSigningKeyFailsStartup() {
    this.runner.run(context -> assertThat(context).hasFailed()
        .getFailure().rootCause().hasMessageContaining("Missing OIDC signing key"));
  }

  @Test
  void severalActiveKeysWithoutDefaultFailStartup() {
    this.runner.withPropertyValues(signingKey(0, "rsa-sign", "active", false))
        .withPropertyValues(signingKey(1, "ec-sign", "active", false))
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("none is marked as default"));
  }

  @Test
  void aBoundParameterValueBecomesAJsonValue() {
    assertThat(OidcAutoConfiguration.toParameterValue("true")).isEqualTo(true);
    assertThat(OidcAutoConfiguration.toParameterValue("text")).isEqualTo("text");
    assertThat(OidcAutoConfiguration.toParameterValue(Map.of("0", "a", "1", Map.of("k", "false"))))
        .isEqualTo(List.of("a", Map.of("k", false)));
    assertThat(OidcAutoConfiguration.toParameterValue(Map.of("0", "a", "2", "b")))
        .isEqualTo(Map.of("0", "a", "2", "b"));
    assertThat(OidcAutoConfiguration.toParameterValue(List.of("true"))).isEqualTo(List.of(true));
  }

  private static String[] signingKey(final int index, final String alias, final String state,
      final boolean defaultKey) {
    final String prefix = "authn-server.oidc.keys.signing[%d].".formatted(index);
    final List<String> values = new ArrayList<>(credential(prefix, alias));
    values.add(prefix + "state=" + state);
    values.add(prefix + "default-key=" + defaultKey);
    return values.toArray(String[]::new);
  }

  private static String[] decryptionKey(final int index, final String alias, final String state) {
    final String prefix = "authn-server.oidc.keys.decryption[%d].".formatted(index);
    final List<String> values = new ArrayList<>(credential(prefix, alias));
    values.add(prefix + "state=" + state);
    return values.toArray(String[]::new);
  }

  private static List<String> credential(final String prefix, final String alias) {
    return List.of(
        prefix + "credential.jks.store.location=classpath:credentials/oidc-keys.p12",
        prefix + "credential.jks.store.password=secret",
        prefix + "credential.jks.store.type=PKCS12",
        prefix + "credential.jks.key.alias=" + alias,
        prefix + "credential.jks.key.key-password=secret");
  }

  private static MockHttpServletResponse get(final AssertableWebApplicationContext context, final String path)
      throws Exception {
    final Filter filter = context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request("GET", path), response, new MockFilterChain());
    return response;
  }

  private static MockHttpServletRequest request(final String method, final String path) {
    final MockHttpServletRequest request = new MockHttpServletRequest(method, path);
    request.setServletPath(path);
    return request;
  }

}
