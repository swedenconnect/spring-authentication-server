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

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;

import se.oidc.nimbus.claims.ParameterConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.scope.TestAuthenticationProvider;

/**
 * Tests for {@link OidcProviderConfigurer} and {@link OidcDiscoveryEndpointConfigurer}.
 *
 * @author Martin Lindström
 */
class OidcProviderConfigurerTest {

  private static final String BASE_URL = "https://op.example.com/auth";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private final AuthnServerConfigurer server = new AuthnServerConfigurer()
      .baseUrl(BASE_URL)
      .authenticationProvider(new TestAuthenticationProvider("one", List.of(LOA3),
          List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME), List.of()))
      .authenticationProvider(new TestAuthenticationProvider("two", List.of(LOA3, LOA4), List.of(), List.of()));

  private final OidcProviderConfigurer oidc = new OidcProviderConfigurer()
      .signingKeys(List.of(SigningKey.activeDefault(KeyTestSupport.rsa("rsa", 2048)),
          SigningKey.active(KeyTestSupport.ec("ec", "secp256r1")),
          SigningKey.future(KeyTestSupport.ec("future", "secp384r1"))));

  @Test
  void theDiscoveryDocumentHoldsWhatTheProviderOffers() {
    this.oidc.decryptionKeys(List.of(DecryptionKey.active(KeyTestSupport.ec("enc", "secp256r1")),
            DecryptionKey.previous(KeyTestSupport.rsa("prev", 2048))))
        .uiLocales(List.of("sv", "en"));

    final OIDCProviderMetadata metadata = this.build();

    assertThat(metadata.getIssuer().getValue()).isEqualTo(BASE_URL);
    assertThat(metadata.getJWKSetURI()).isEqualTo(URI.create(BASE_URL + "/oidc/jwks"));
    assertThat(metadata.getIDTokenJWSAlgs()).startsWith(JWSAlgorithm.RS256)
        .contains(JWSAlgorithm.PS512, JWSAlgorithm.ES256)
        .doesNotContain(JWSAlgorithm.ES384);
    assertThat(metadata.getRequestObjectJWEAlgs()).containsExactly(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW);
    assertThat(metadata.getScopes().toStringList()).contains("openid", "profile",
        "https://id.oidc.se/scope/naturalPersonInfo");
    assertThat(metadata.getClaims()).contains("sub", "given_name", "zoneinfo",
        "https://id.oidc.se/claim/personalIdentityNumber");
    assertThat(metadata.getACRs()).extracting(Identifier::getValue).containsExactly(LOA3, LOA4);
    assertThat(metadata.getSubjectTypes()).containsExactly(SubjectType.PUBLIC, SubjectType.PAIRWISE);
    assertThat(metadata.getUILocales()).extracting(LangTag::toString).containsExactly("sv", "en");
    assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME)).isNull();
    assertThat(metadata.getUserInfoJWSAlgs()).isNull();
    assertThat(metadata.getAuthorizationEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/authorize"));
    assertThat(metadata.getResponseTypes()).containsExactly(ResponseType.CODE);
    assertThat(metadata.getResponseModes()).containsExactly(ResponseMode.QUERY, ResponseMode.FORM_POST);
    assertThat(metadata.supportsClaimsParam()).isTrue();
    assertThat(metadata.supportsRequestParam()).isTrue();
    assertThat(metadata.supportsRequestURIParam()).isTrue();
    assertThat(metadata.requiresRequestURIRegistration()).isTrue();
    assertThat(metadata.getRequestObjectJWSAlgs()).contains(JWSAlgorithm.RS256, JWSAlgorithm.PS256, JWSAlgorithm.ES256)
        .extracting(JWSAlgorithm::getName).contains("none");
    assertThat(metadata.getCodeChallengeMethods()).containsExactly(CodeChallengeMethod.S256);
    assertThat(metadata.getCustomParameter(ParameterConstants.REQUESTED_PROVIDER_SUPPORTED_PARAM_NAME))
        .isEqualTo(true);
    assertThat(metadata.getTokenEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/token"));
    assertThat(metadata.getGrantTypes()).containsExactly(GrantType.AUTHORIZATION_CODE);
    assertThat(metadata.getTokenEndpointAuthMethods()).containsExactly(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    assertThat(metadata.getTokenEndpointJWSAlgs()).contains(JWSAlgorithm.RS256, JWSAlgorithm.ES256)
        .doesNotContain(JWSAlgorithm.HS256).extracting(JWSAlgorithm::getName).doesNotContain("none");
    assertThat(metadata.getIDTokenJWEAlgs())
        .containsExactly(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.ECDH_ES);
    assertThat(metadata.getIDTokenJWEEncs()).containsExactly(EncryptionMethod.A128CBC_HS256,
        EncryptionMethod.A256CBC_HS512, EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
  }

  @Test
  void theEnabledClientAuthenticationMethodsAreAdvertised() {
    this.oidc.clientAuthenticationMethods(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        ClientAuthenticationMethod.CLIENT_SECRET_JWT));
    final OIDCProviderMetadata metadata = this.build();
    assertThat(metadata.getTokenEndpointAuthMethods()).containsExactly(
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_JWT);
    assertThat(metadata.getTokenEndpointJWSAlgs())
        .containsExactly(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);

    assertThat(new OidcProviderConfigurerTest().buildWith(c -> c.clientAuthenticationMethods(
        Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST))).getTokenEndpointJWSAlgs()).isNull();
  }

  @Test
  void invalidTokenSettingsAreRejected() {
    assertThatThrownBy(() -> new OidcProviderConfigurerTest().buildWith(
        c -> c.clientAuthenticationMethods(Set.of(ClientAuthenticationMethod.NONE))))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Unsupported");
    assertThatThrownBy(() -> new OidcProviderConfigurerTest().buildWith(c -> c.clientAuthenticationMethods(Set.of())))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new OidcProviderConfigurerTest().buildWith(c -> c.idTokenLifetime(Duration.ZERO)))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ID token lifetime");
    assertThatThrownBy(() -> new OidcProviderConfigurerTest().buildWith(c -> c.tokenEndpoint("token")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("token endpoint");
  }

  @Test
  void noneIsNotAdvertisedWhenSignedRequestObjectsAreRequired() {
    this.oidc.requireSignedRequestObject(true);
    assertThat(this.build().getRequestObjectJWSAlgs()).extracting(JWSAlgorithm::getName).doesNotContain("none");
  }

  @Test
  void theAuthorizationEndpointMayBeChanged() {
    this.oidc.authorizationEndpoint("/authz");
    assertThat(this.build().getAuthorizationEndpointURI()).isEqualTo(URI.create(BASE_URL + "/oidc/authz"));
  }

  @Test
  void anAuthorizationEndpointWithoutLeadingSlashIsRejected() {
    this.oidc.authorizationEndpoint("authz");
    assertThatThrownBy(this::build).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("authorization endpoint");
  }

  @Test
  void withoutDecryptionKeysNoEncryptionAlgorithmIsAdvertised() {
    final OIDCProviderMetadata metadata = this.build();

    assertThat(metadata.getRequestObjectJWEAlgs()).isNull();
    assertThat(metadata.getUILocales()).isNull();
  }

  @Test
  void theUserMessageParameterIsAdvertisedWhenUserMessagesAreSupportedForOidc() {
    this.server.supportsUserMessage(true);
    final OIDCProviderMetadata metadata = this.build();
    assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME)).isEqualTo(true);
    assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_MIMETYPES_PARAM_NAME))
        .isEqualTo(List.of("text/plain", "text/markdown"));
  }

  @Test
  void theOidcSettingWinsForUserMessages() {
    this.server.supportsUserMessage(true);
    this.oidc.supportsUserMessage(false);
    final OIDCProviderMetadata metadata = this.build();
    assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME)).isNull();
    assertThat(metadata.getCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_MIMETYPES_PARAM_NAME)).isNull();
  }

  @Test
  void configuredScopesAndClaimsAreApplied() {
    this.oidc.scopes(List.of("email")).claims(List.of("https://example.com/claim/employee"));

    final OIDCProviderMetadata metadata = this.build();

    assertThat(metadata.getScopes().toStringList()).containsExactly("openid", "email");
    assertThat(metadata.getClaims()).contains("email", "email_verified", "https://example.com/claim/employee",
        "given_name");
  }

  @Test
  void additionalParametersAndTheCustomizerAppearInTheDocument() {
    final Map<String, Object> parameters = new LinkedHashMap<>();
    parameters.put("service_documentation", "https://op.example.com/docs");
    parameters.put("https://example.com/disco/feature", List.of("a", "b"));
    parameters.put("frontchannel_logout_supported", true);
    this.oidc.discoveryEndpoint(d -> d.additionalParameters(parameters)
        .providerMetadataCustomizer(m -> m.setCustomParameter("https://example.com/disco/custom", "value")));

    final OIDCProviderMetadata metadata = this.build();
    final JSONObject json = metadata.toJSONObject();

    assertThat(metadata.getServiceDocsURI()).isEqualTo(URI.create("https://op.example.com/docs"));
    assertThat(metadata.supportsFrontChannelLogout()).isTrue();
    assertThat(json.get("https://example.com/disco/feature")).isEqualTo(List.of("a", "b"));
    assertThat(json.get("https://example.com/disco/custom")).isEqualTo("value");
    assertThat(metadata.getIssuer().getValue()).isEqualTo(BASE_URL);
  }

  @Test
  void anAdditionalParameterCannotReplaceABuiltParameter() {
    this.oidc.discoveryEndpoint(d -> d.additionalParameters(Map.of("issuer", "https://other.example.com")));

    assertThatThrownBy(this::build)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("'issuer' is set by the OpenID Provider");
  }

  @Test
  void anInvalidAdditionalParameterIsRejected() {
    this.oidc.discoveryEndpoint(d -> d.additionalParameters(Map.of("service_documentation", List.of(1))));

    assertThatThrownBy(this::build)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid OIDC discovery parameter");
  }

  @Test
  void discoveryIsServedUnderTheIssuer() {
    this.server.protocol(this.oidc);
    this.oidc.init(null);
    assertThat(this.oidc.getDiscoveryEndpointPath()).isEqualTo("/.well-known/openid-configuration");

    final OidcProviderConfigurer withPath = this.newConfigurer().issuer(BASE_URL + "/op1");
    this.server.protocol(withPath);
    withPath.init(null);
    assertThat(withPath.getDiscoveryEndpointPath()).isEqualTo("/op1/.well-known/openid-configuration");
    assertThat(withPath.getEndpointPath(withPath.getJwksEndpoint())).isEqualTo("/oidc/jwks");
  }

  @Test
  void theIssuerMustBeginWithTheBaseUrl() {
    this.server.protocol(this.oidc.issuer("https://other.example.com"));
    assertThatThrownBy(() -> this.oidc.init(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must be the base URL");

    this.oidc.issuer(BASE_URL + "x");
    assertThatThrownBy(() -> this.oidc.init(null)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aSigningKeyIsRequired() {
    this.server.protocol(this.oidc.signingKeys(null));
    assertThatThrownBy(() -> this.oidc.init(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing OIDC signing key");
  }

  @Test
  void theSigningKeySelectorUsesTheConfiguredKeys() {
    this.server.protocol(this.oidc);
    this.oidc.init(null);

    assertThat(this.oidc.getSigningKeySelector().select(JWSAlgorithm.ES256, null).key())
        .isSameAs(this.oidc.getKeys().getActiveSigningKeys().get(1));
  }

  private OidcProviderConfigurer newConfigurer() {
    return new OidcProviderConfigurer()
        .signingKeys(List.of(SigningKey.active(KeyTestSupport.rsa("rsa", 2048))));
  }

  private OIDCProviderMetadata buildWith(final Consumer<OidcProviderConfigurer> customizer) {
    customizer.accept(this.oidc);
    return this.build();
  }

  private OIDCProviderMetadata build() {
    this.server.protocol(this.oidc);
    this.oidc.init(null);
    return this.oidc.getDiscoveryEndpointConfigurer().createProviderMetadata();
  }

}
