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
package se.swedenconnect.spring.authnserver.oidc.token;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;
import jakarta.servlet.RequestDispatcher;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.sun.net.httpserver.HttpServer;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.audit.AuditApplicationListener;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.tracing.CorrelationIDHolder;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.audit.AuditCollector;
import se.swedenconnect.spring.authnserver.oidc.client.ConfigurationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.userinfo.UserInfoRequestProcessor;

/**
 * End-to-end tests of the OpenID Connect code flow: the authentication request, the authentication of the user with a
 * direct and a redirect provider, the authorization code response, the token request, the ID token and the UserInfo
 * endpoint.
 *
 * @author Martin Lindström
 */
class OidcCodeFlowTest {

  private static final String BASE_URL = "https://op.example.com";

  private static final String AUTHZ_PATH = "/oidc/authorize";

  private static final String TOKEN_PATH = "/oidc/token";

  private static final String TOKEN_ENDPOINT = BASE_URL + TOKEN_PATH;

  private static final String USERINFO_PATH = "/oidc/userinfo";

  private static final String USERINFO_ENC_CLIENT = "https://userinfo-enc.example.com";

  private static final String USERINFO_BAD_ENC_CLIENT = "https://userinfo-bad-enc.example.com";

  private static final String OTHER_PNR = "196911292032";

  private static final String REDIRECT_URI = "https://rp.example.com/callback";

  private static final String RSA_CLIENT = "https://rsa.example.com";

  private static final String EC_CLIENT = "https://ec.example.com";

  private static final String JWKS_URI_CLIENT = "https://jwks-uri.example.com";

  private static final String ENC_CLIENT = "https://enc.example.com";

  private static final String BAD_ENC_CLIENT = "https://bad-enc.example.com";

  private static final String BASIC_CLIENT = "https://basic.example.com";

  private static final String POST_CLIENT = "https://post.example.com";

  private static final String SECRET_JWT_CLIENT = "https://secret-jwt.example.com";

  private static final String SECRET = "a-client-secret-that-is-long-enough-for-hs256-0123456789";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  private static final String PNR = "197705232382";

  private static final String PNR_CLAIM = "https://id.oidc.se/claim/personalIdentityNumber";

  private static final String PNR_SCOPE = "https://id.oidc.se/scope/naturalPersonNumber";

  private static final String AUTHN_PATH = "/authn/login";

  private static final String RESUME_PATH = "/authn/resume";

  private static final PkiCredential OP_RSA = KeyTestSupport.rsa("op-rsa", 2048);

  private static final PkiCredential OP_EC = KeyTestSupport.ec("op-ec", "secp256r1");

  private static final PkiCredential CLIENT_RSA = KeyTestSupport.rsa("client-rsa", 2048);

  private static final PkiCredential CLIENT_EC = KeyTestSupport.ec("client-ec", "secp256r1");

  private static final PkiCredential CLIENT_ENC = KeyTestSupport.rsa("client-enc", 2048);

  private static final PkiCredential OTHER = KeyTestSupport.rsa("other", 2048);

  private static final InMemoryAccessTokenStore ACCESS_TOKENS = new InMemoryAccessTokenStore();

  private static HttpServer jwksServer;

  private static String jwksUri;

  private static List<AbstractUserAuthenticationProvider> providers;

  private static Consumer<AuthnServerConfigurer> customizer;

  private AnnotationConfigWebApplicationContext context;

  private MockHttpSession session;

  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .clientRegistryBackend(new ConfigurationClientBackend(clients()))
          .protocol(new OidcProviderConfigurer()
              .signingKeys(List.of(SigningKey.activeDefault(OP_RSA), SigningKey.active(OP_EC)))
              .scopes(List.of("openid", "profile", PNR_SCOPE))
              .authnRequestProcessor(c -> c.accessTokenStore(ACCESS_TOKENS)));
      providers.forEach(configurer::authenticationProvider);
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      return http.build();
    }

    @Bean
    AuditApplicationListener auditApplicationListener(final ApplicationContext context) {
      return AuditCollector.listener(context);
    }

    @Bean
    AuditCollector auditCollector() {
      return new AuditCollector();
    }
  }

  @BeforeAll
  static void startJwksServer() throws Exception {
    jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    jwksServer.createContext("/jwks", exchange -> {
      final byte[] body = new JWKSet(List.of(ecJwk(CLIENT_EC, "ec-key"), rsaJwk(CLIENT_RSA, "rsa-key", null)))
          .toString().getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      try (final OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    jwksServer.start();
    jwksUri = "http://localhost:" + jwksServer.getAddress().getPort() + "/jwks";
  }

  @AfterAll
  static void stopJwksServer() {
    jwksServer.stop(0);
  }

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();
  }

  @AfterEach
  void close() {
    if (this.context != null) {
      this.context.close();
      this.context = null;
    }
  }

  // The flow

  @Test
  void aDirectProviderGivesACodeAndTheTokenRequestGivesTheIdToken() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3, LOA4));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("nonce", "nonce-1");
    params.put("acr_values", LOA4);
    final Map<String, String> response = this.authorize(params);
    assertThat(response.get("state")).isEqualTo("state-1");

    final Instant before = Instant.now().minusSeconds(1);
    final MockHttpServletResponse tokenResponse =
        this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), response.get("code"), REDIRECT_URI, null);
    assertThat(tokenResponse.getStatus()).isEqualTo(200);
    assertThat(tokenResponse.getHeader("Cache-Control")).isEqualTo("no-store");
    final Map<String, Object> json = JSONObjectUtils.parse(tokenResponse.getContentAsString());
    assertThat(json.get("token_type")).isEqualTo("Bearer");
    assertThat(((Number) json.get("expires_in")).longValue()).isEqualTo(300);
    assertThat(json).doesNotContainKey("refresh_token");

    final SignedJWT idToken = SignedJWT.parse((String) json.get("id_token"));
    assertThat(idToken.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    assertThat(idToken.getHeader().getKeyID()).isEqualTo(SigningKey.activeDefault(OP_RSA).getKeyId());
    assertThat(idToken.verify(new RSASSAVerifier((RSAPublicKey) OP_RSA.getPublicKey()))).isTrue();
    final JWTClaimsSet claims = idToken.getJWTClaimsSet();
    assertThat(claims.getIssuer()).isEqualTo(BASE_URL);
    assertThat(claims.getAudience()).containsExactly(RSA_CLIENT);
    assertThat(claims.getSubject()).isNotBlank().isNotEqualTo(PNR);
    assertThat(claims.getStringClaim("nonce")).isEqualTo("nonce-1");
    assertThat(claims.getStringClaim("acr")).isEqualTo(LOA4);
    assertThat(claims.getDateClaim("auth_time").toInstant()).isAfter(before);
    assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
        .isEqualTo(Duration.ofMinutes(5));
    // Only openid - no identity claims
    assertThat(claims.getClaims()).doesNotContainKeys(PNR_CLAIM, "given_name", "family_name");

    final AccessTokenData accessToken = ACCESS_TOKENS.get((String) json.get("access_token"));
    assertThat(accessToken).isNotNull();
    assertThat(accessToken.subject()).isEqualTo(claims.getSubject());
    assertThat(accessToken.singleUse()).isTrue();
    assertThat(accessToken.clientId()).isEqualTo(RSA_CLIENT);
  }

  @Test
  void aRedirectProviderWithFormPostAndAnEcClientAssertion() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(c -> {}, provider);
    final Map<String, String> params = params(EC_CLIENT);
    params.put("response_mode", "form_post");

    final MockHttpServletResponse redirect = this.send(get(AUTHZ_PATH, params));
    assertThat(redirect.getRedirectedUrl()).startsWith(AUTHN_PATH + "?authnId=");
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);

    final MockHttpServletRequest controllerRequest = this.appRequest(AUTHN_PATH, authnId);
    final RedirectForAuthenticationToken input = provider.getAuthenticatorRepository().getInputToken(controllerRequest);
    assertThat(input).isNotNull();
    assertThat(input.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
    provider.getAuthenticatorRepository().complete(new UserAuthentication(user(LOA3)), controllerRequest);

    final MockHttpServletResponse page = this.send(this.appRequest(RESUME_PATH, authnId));
    final Map<String, String> form = formValues(page.getContentAsString());
    assertThat(page.getContentAsString()).contains("action=\"" + REDIRECT_URI + "\"");
    assertThat(form.get("state")).isEqualTo("state-1");

    final MockHttpServletResponse tokenResponse = this.token(
        privateKeyJwt(EC_CLIENT, CLIENT_EC, "ec-key"), form.get("code"), REDIRECT_URI, null);
    assertThat(tokenResponse.getStatus()).isEqualTo(200);
    final SignedJWT idToken = idToken(tokenResponse);
    // The EC client asks for ES256
    assertThat(idToken.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(idToken.verify(new ECDSAVerifier((ECPublicKey) OP_EC.getPublicKey()))).isTrue();
    assertThat(idToken.getJWTClaimsSet().getStringClaim("acr")).isEqualTo(LOA3);
  }

  @Test
  void aCancelledRedirectAuthenticationGivesAnErrorResponse() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(c -> {}, provider);
    final MockHttpServletResponse redirect = this.send(get(AUTHZ_PATH, params(RSA_CLIENT)));
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);
    final MockHttpServletRequest controllerRequest = this.appRequest(AUTHN_PATH, authnId);
    provider.getAuthenticatorRepository().complete(
        new AuthenticationErrorException(AuthenticationError.CANCEL), controllerRequest);

    final Map<String, String> response = query(this.send(this.appRequest(RESUME_PATH, authnId)));
    assertThat(response.get("error")).isEqualTo("access_denied");
    assertThat(response.get("state")).isEqualTo("state-1");
    assertThat(response).doesNotContainKey("code");
  }

  @Test
  void anErrorFromADirectProviderGoesToTheRedirectUri() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.error = new AuthenticationErrorException(AuthenticationError.CANCEL);
    this.start(c -> {}, provider);
    final Map<String, String> response = query(this.send(get(AUTHZ_PATH, params(RSA_CLIENT))));
    assertThat(response.get("error")).isEqualTo("access_denied");
    assertThat(response.get("state")).isEqualTo("state-1");
  }

  @Test
  void aClientAssertionVerifiedWithKeysFromJwksUri() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(JWKS_URI_CLIENT)).get("code");
    assertThat(this.token(privateKeyJwt(JWKS_URI_CLIENT, CLIENT_EC, "ec-key"), code, REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
  }

  @Test
  void aClientWithSeveralKeysMayUseAnyOfThem() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertThat(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_EC, "ec-key"), code, REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
    code = this.authorize(params(RSA_CLIENT)).get("code");
    // No kid - every key of the client is tried
    assertThat(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, null), code, REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
  }

  @Test
  void anEncryptedIdTokenIsSignedThenEncrypted() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(ENC_CLIENT)).get("code");
    final MockHttpServletResponse tokenResponse =
        this.token(privateKeyJwt(ENC_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null);
    assertThat(tokenResponse.getStatus()).isEqualTo(200);

    final JWEObject jwe = JWEObject.parse(
        (String) JSONObjectUtils.parse(tokenResponse.getContentAsString()).get("id_token"));
    assertThat(jwe.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
    assertThat(jwe.getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
    assertThat(jwe.getHeader().getKeyID()).isEqualTo("enc-key");
    jwe.decrypt(new RSADecrypter(CLIENT_ENC.getPrivateKey()));
    final SignedJWT idToken = jwe.getPayload().toSignedJWT();
    assertThat(idToken.verify(new RSASSAVerifier((RSAPublicKey) OP_RSA.getPublicKey()))).isTrue();
    assertThat(idToken.getJWTClaimsSet().getAudience()).containsExactly(ENC_CLIENT);
  }

  @Test
  void aClientAskingForEncryptionThatCannotBeUsedEndsAtAnErrorPage() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final MockHttpServletRequest request = get(AUTHZ_PATH, params(BAD_ENC_CLIENT));
    final MockHttpServletResponse response = this.send(request);
    assertThat(response.getStatus()).isEqualTo(500);
    assertThat(response.getRedirectedUrl()).isNull();
    assertThat(request.getAttribute(RequestDispatcher.ERROR_EXCEPTION))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION));
  }

  // Claims

  @Test
  void scopeClaimsAreDeliveredWhereTheScopeSays() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid profile " + PNR_SCOPE);
    final Tokens tokens = this.codeFlow(params);

    // The personal identity number scope is delivered in both, profile from UserInfo only
    assertThat(tokens.idToken().getClaims()).containsEntry(PNR_CLAIM, PNR)
        .doesNotContainKeys("given_name", "family_name");
    assertThat(tokens.userInfo()).containsEntry(PNR_CLAIM, PNR)
        .containsEntry("given_name", "Kalle").containsEntry("family_name", "Kula");
  }

  @Test
  void claimsOfTheClaimsParameterAreDeliveredWhereItSays() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"id_token\":{\"family_name\":null},\"userinfo\":{\"given_name\":null}}");
    final Tokens tokens = this.codeFlow(params);

    assertThat(tokens.idToken().getClaims()).containsEntry("family_name", "Kula").doesNotContainKey("given_name");
    assertThat(tokens.userInfo()).containsEntry("given_name", "Kalle").doesNotContainKey("family_name");
  }

  @Test
  void aClaimAskedForInTheIdTokenAndCoveredByAUserInfoScopeIsDeliveredInBoth() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid profile");
    params.put("claims", "{\"id_token\":{\"given_name\":{\"essential\":true}}}");
    final Tokens tokens = this.codeFlow(params);

    assertThat(tokens.idToken().getClaims()).containsEntry("given_name", "Kalle").doesNotContainKey("family_name");
    assertThat(tokens.userInfo()).containsEntry("given_name", "Kalle").containsEntry("family_name", "Kula");
  }

  @Test
  void onlyOpenidGivesNoIdentityClaims() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Tokens tokens = this.codeFlow(params(RSA_CLIENT));
    assertThat(tokens.idToken().getClaims()).containsOnlyKeys("iss", "sub", "aud", "exp", "iat", "auth_time", "acr");
    assertThat(tokens.userInfo()).containsOnlyKeys("sub", "iss", "aud");
  }

  @Test
  void acrIsInTheIdTokenAlsoWhenVoluntaryValuesCannotBeMet() throws Exception {
    final ListAppender<ILoggingEvent> appender = appender(
        se.swedenconnect.spring.authnserver.oidc.response.OidcUserAuthenticationResponder.class);
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("acr_values", LOA2);
    final Tokens tokens = this.codeFlow(params);
    assertThat(tokens.idToken().getStringClaim("acr")).isEqualTo(LOA3);
    assertThat(appender.list).anyMatch(e -> e.getLevel() == ch.qos.logback.classic.Level.INFO
        && e.getFormattedMessage().contains("could be met"));
  }

  @Test
  void aRequestWithoutPromptIsNotAnsweredWithSingleSignOn() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(c -> {}, provider);
    final Instant first = this.codeFlow(params(RSA_CLIENT)).idToken().getDateClaim("auth_time").toInstant();
    Thread.sleep(1100);
    final Instant second = this.codeFlow(params(RSA_CLIENT)).idToken().getDateClaim("auth_time").toInstant();
    assertThat(provider.calls).isEqualTo(2);
    assertThat(second).isAfter(first);
  }

  @Test
  void singleSignOnKeepsTheOriginalAuthTime() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(c -> oidc(c).loginWithoutPrompt(false), provider);
    final Instant first = this.codeFlow(params(RSA_CLIENT)).idToken().getDateClaim("auth_time").toInstant();
    Thread.sleep(1100);
    final Instant second = this.codeFlow(params(RSA_CLIENT)).idToken().getDateClaim("auth_time").toInstant();
    assertThat(provider.calls).isEqualTo(1);
    assertThat(second).isEqualTo(first);
  }

  @Test
  void aRequestedSubThatDoesNotMatchGivesAnErrorAndNoCode() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"id_token\":{\"sub\":{\"value\":\"someone-else\"}}}");
    final Map<String, String> response = query(this.send(get(AUTHZ_PATH, params)));
    assertThat(response.get("error")).isEqualTo("access_denied");
    assertThat(response).doesNotContainKey("code");

    // The same sub as the user gets passes
    final String sub = this.codeFlow(params(RSA_CLIENT)).idToken().getSubject();
    params.put("claims", "{\"id_token\":{\"sub\":{\"value\":\"" + sub + "\"}}}");
    assertThat(this.authorize(params)).containsKey("code");
  }

  @Test
  void anIdTokenHintForAnotherSubjectGivesAnError() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final JWTClaimsSet hintClaims = new JWTClaimsSet.Builder()
        .issuer(BASE_URL).audience(RSA_CLIENT).subject("someone-else")
        .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
    final SignedJWT hint = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), hintClaims);
    hint.sign(new RSASSASigner(OP_RSA.getPrivateKey()));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("id_token_hint", hint.serialize());
    assertThat(query(this.send(get(AUTHZ_PATH, params))).get("error")).isEqualTo("access_denied");
  }

  // UserInfo

  @Test
  void userInfoWithTheTokenInTheHeaderAndInAPostBody() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid profile");

    Map<String, Object> json = this.tokenJson(params);
    final String sub = SignedJWT.parse((String) json.get("id_token")).getJWTClaimsSet().getSubject();
    MockHttpServletResponse response = this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).isEqualTo(200);
    SignedJWT jwt = signedUserInfo(response);
    assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    final JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertThat(claims.getSubject()).isEqualTo(sub);
    assertThat(claims.getIssuer()).isEqualTo(BASE_URL);
    assertThat(claims.getAudience()).containsExactly(RSA_CLIENT);
    assertThat(claims.getClaims()).containsEntry("given_name", "Kalle").containsEntry("family_name", "Kula")
        .doesNotContainKey(PNR_CLAIM);

    // In a POST body, and with the header in a POST
    json = this.tokenJson(params);
    response = this.send(userInfoRequest("POST", null, (String) json.get("access_token")));
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    jwt = signedUserInfo(response);
    assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(sub);

    json = this.tokenJson(params);
    response = this.send(userInfoRequest("POST", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void theUserInfoResponseIsSignedWithTheKeyChosenForTheClient() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, Object> json = this.tokenJson(params(EC_CLIENT));
    final SignedJWT jwt =
        signedUserInfo(this.send(userInfoRequest("GET", (String) json.get("access_token"), null)));
    assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly(EC_CLIENT);
  }

  @Test
  void anEncryptedUserInfoResponseIsSignedThenEncrypted() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(USERINFO_ENC_CLIENT);
    params.put("scope", "openid profile");
    final Map<String, Object> json = this.tokenJson(params);
    // The ID token is not encrypted
    final String sub = SignedJWT.parse((String) json.get("id_token")).getJWTClaimsSet().getSubject();

    final MockHttpServletResponse response =
        this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).startsWith("application/jwt");
    final JWEObject jwe = JWEObject.parse(response.getContentAsString());
    assertThat(jwe.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
    assertThat(jwe.getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
    assertThat(jwe.getHeader().getContentType()).isEqualTo("JWT");
    assertThat(jwe.getHeader().getKeyID()).isEqualTo("enc-key");
    jwe.decrypt(new RSADecrypter(CLIENT_ENC.getPrivateKey()));
    final SignedJWT jwt = jwe.getPayload().toSignedJWT();
    verifyByOp(jwt);
    assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(sub);
    assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly(USERINFO_ENC_CLIENT);
    assertThat(jwt.getJWTClaimsSet().getClaims()).containsEntry("given_name", "Kalle");
  }

  @Test
  void withSigningOffAUserInfoResponseMayBeEncryptedOnly() throws Exception {
    this.start(c -> oidc(c).signUserInfo(false), new TestProvider("direct", LOA3));
    final Map<String, Object> json = this.tokenJson(params(USERINFO_ENC_CLIENT));
    final MockHttpServletResponse response =
        this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getContentType()).startsWith("application/jwt");
    final JWEObject jwe = JWEObject.parse(response.getContentAsString());
    assertThat(jwe.getHeader().getContentType()).isNull();
    jwe.decrypt(new RSADecrypter(CLIENT_ENC.getPrivateKey()));
    assertThat(jwe.getPayload().toJSONObject()).containsOnlyKeys("sub");
  }

  @Test
  void withSigningOffOnlyAClientThatAsksForSigningGetsASignedResponse() throws Exception {
    this.start(c -> oidc(c).signUserInfo(false), new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid profile");
    final Map<String, Object> json = this.tokenJson(params);
    final MockHttpServletResponse response =
        this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).startsWith("application/json");
    final Map<String, Object> claims = JSONObjectUtils.parse(response.getContentAsString());
    assertThat(claims).containsOnlyKeys("sub", "given_name", "family_name")
        .containsEntry("sub", SignedJWT.parse((String) json.get("id_token")).getJWTClaimsSet().getSubject());

    final Map<String, Object> ecJson = this.tokenJson(params(EC_CLIENT));
    final SignedJWT jwt =
        signedUserInfo(this.send(userInfoRequest("GET", (String) ecJson.get("access_token"), null)));
    assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
  }

  @Test
  void aClientWhoseUserInfoEncryptionCannotBeUsedGetsAnErrorAndNoClaims() throws Exception {
    final ListAppender<ILoggingEvent> appender = appender(ClientEncryption.class);
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(USERINFO_BAD_ENC_CLIENT);
    params.put("scope", "openid profile");
    final Map<String, Object> json = this.tokenJson(params);
    final MockHttpServletResponse response =
        this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getContentAsString()).doesNotContain("Kalle");
    assertBearerError(response, 400, "invalid_client_metadata");
    assertThat(appender.list).anyMatch(e -> e.getFormattedMessage().contains("Client configuration error"));
  }

  @Test
  void aSingleUseAccessTokenIsConsumedByTheFirstCall() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String token = (String) this.tokenJson(params(RSA_CLIENT)).get("access_token");
    assertThat(this.send(userInfoRequest("GET", token, null)).getStatus()).isEqualTo(200);
    assertBearerError(this.send(userInfoRequest("GET", token, null)), 401, "invalid_token");
    assertBearerError(this.send(userInfoRequest("POST", null, token)), 401, "invalid_token");
  }

  @Test
  void anAccessTokenThatIsNotSingleUseWorksUntilItExpires() throws Exception {
    this.start(c -> oidc(c).singleUseAccessTokens(false).accessTokenLifetime(Duration.ofMillis(700)),
        new TestProvider("direct", LOA3));
    final String token = (String) this.tokenJson(params(RSA_CLIENT)).get("access_token");
    assertThat(this.send(userInfoRequest("GET", token, null)).getStatus()).isEqualTo(200);
    assertThat(this.send(userInfoRequest("GET", token, null)).getStatus()).isEqualTo(200);
    Thread.sleep(800);
    assertBearerError(this.send(userInfoRequest("GET", token, null)), 401, "invalid_token");
  }

  @Test
  void userInfoRequestErrorsFollowRfc6750() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String token = (String) this.tokenJson(params(RSA_CLIENT)).get("access_token");

    // No token
    assertBearerError(this.send(userInfoRequest("GET", null, null)), 401, null);
    final MockHttpServletRequest basic = userInfoRequest("GET", null, null);
    basic.addHeader("Authorization", "Basic dXNlcjpwYXNz");
    assertBearerError(this.send(basic), 401, null);

    // In the query
    final MockHttpServletRequest query = userInfoRequest("GET", null, null);
    query.setQueryString("access_token=" + token);
    query.addParameter("access_token", token);
    assertBearerError(this.send(query), 400, "invalid_request");

    // Two ways
    assertBearerError(this.send(userInfoRequest("POST", token, token)), 400, "invalid_request");

    // Malformed
    final MockHttpServletRequest malformed = userInfoRequest("GET", null, null);
    malformed.addHeader("Authorization", "Bearer ");
    assertBearerError(this.send(malformed), 400, "invalid_request");

    // Unknown
    assertBearerError(this.send(userInfoRequest("GET", "unknown-token", null)), 401, "invalid_token");

    // None of the failures used up the token
    assertThat(this.send(userInfoRequest("GET", token, null)).getStatus()).isEqualTo(200);
  }

  @Test
  void anExpiredAccessTokenIsInvalid() throws Exception {
    this.start(c -> oidc(c).accessTokenLifetime(Duration.ofMillis(200)), new TestProvider("direct", LOA3));
    final String token = (String) this.tokenJson(params(RSA_CLIENT)).get("access_token");
    Thread.sleep(300);
    assertBearerError(this.send(userInfoRequest("GET", token, null)), 401, "invalid_token");
  }

  @Test
  void theAccessTokenOfAReusedCodeIsRevoked() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    final String token = (String) JSONObjectUtils.parse(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"),
        code, REDIRECT_URI, null).getContentAsString()).get("access_token");
    this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null);
    assertBearerError(this.send(userInfoRequest("GET", token, null)), 401, "invalid_token");
  }

  // Requested claim values

  @Test
  void anEssentialRequestedValueThatDoesNotMatchIsAccessDeniedAndRemovesTheSessionAuthentication()
      throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(c -> {}, provider);
    this.authorize(params(RSA_CLIENT));
    assertThat(provider.calls).isOne();

    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"id_token\":{\"" + PNR_CLAIM + "\":{\"essential\":true,\"value\":\"" + OTHER_PNR
        + "\"}}}");
    final Map<String, String> response = query(this.send(get(AUTHZ_PATH, params)));
    assertThat(response.get("error")).isEqualTo("access_denied");
    assertThat(response.get("state")).isEqualTo("state-1");
    assertThat(response).doesNotContainKey("code");
    assertThat(provider.calls).isEqualTo(2);

    this.authorize(params(RSA_CLIENT));
    assertThat(provider.calls).isEqualTo(3);
  }

  @Test
  void aVoluntaryRequestedValueThatDoesNotMatchProceedsWithTheActualValue() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"id_token\":{\"" + PNR_CLAIM + "\":{\"value\":\"" + OTHER_PNR + "\"}}}");
    assertThat(this.codeFlow(params).idToken().getClaims()).containsEntry(PNR_CLAIM, PNR);
  }

  @Test
  void severalRequestedValuesFailOnlyWhenNoneMatches() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"userinfo\":{\"given_name\":{\"essential\":true,\"values\":[\"Olle\",\"Kalle\"]}}}");
    assertThat(this.codeFlow(params).userInfo()).containsEntry("given_name", "Kalle");

    params.put("claims", "{\"userinfo\":{\"given_name\":{\"essential\":true,\"values\":[\"Olle\",\"Nisse\"]}}}");
    assertThat(query(this.send(get(AUTHZ_PATH, params))).get("error")).isEqualTo("access_denied");
  }

  @Test
  void aRequestedValueForAClaimTheUserDoesNotHaveProceeds() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"userinfo\":{\"email\":{\"essential\":true,\"value\":\"kalle@example.com\"}}}");
    assertThat(this.codeFlow(params).userInfo()).doesNotContainKey("email");
  }

  @Test
  void aScopeMarkingTheClaimEssentialMakesAVoluntaryValueEssential() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid " + PNR_SCOPE);
    params.put("claims", "{\"userinfo\":{\"" + PNR_CLAIM + "\":{\"value\":\"" + OTHER_PNR + "\"}}}");
    assertThat(query(this.send(get(AUTHZ_PATH, params))).get("error")).isEqualTo("access_denied");
  }

  @Test
  void aResumedAuthenticationIsCheckedAgainstTheRequestedValues() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(c -> {}, provider);
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("claims", "{\"id_token\":{\"" + PNR_CLAIM + "\":{\"essential\":true,\"value\":\"" + OTHER_PNR
        + "\"}}}");
    final MockHttpServletResponse redirect = this.send(get(AUTHZ_PATH, params));
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);
    provider.getAuthenticatorRepository().complete(new UserAuthentication(user(LOA3)),
        this.appRequest(AUTHN_PATH, authnId));
    final Map<String, String> response = query(this.send(this.appRequest(RESUME_PATH, authnId)));
    assertThat(response.get("error")).isEqualTo("access_denied");
    assertThat(response).doesNotContainKey("code");
  }

  // Token endpoint failures

  @Test
  void missingOrWrongClientAuthenticationIsInvalidClient() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");

    assertTokenError(this.token(Map.of("client_id", RSA_CLIENT), code, REDIRECT_URI, null), 401, "invalid_client");
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, OTHER, "rsa-key"), code, REDIRECT_URI, null), 401,
        "invalid_client");
    assertTokenError(this.token(privateKeyJwt("https://unknown.example.com", CLIENT_RSA, "rsa-key"), code,
        REDIRECT_URI, null), 401, "invalid_client");
  }

  @Test
  void aMethodOtherThanTheRegisteredOneIsInvalidClient() throws Exception {
    this.start(c -> oidc(c).clientAuthenticationMethods(Set.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT,
        ClientAuthenticationMethod.CLIENT_SECRET_POST)), new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertTokenError(this.token(Map.of("client_id", RSA_CLIENT, "client_secret", SECRET), code, REDIRECT_URI, null),
        401, "invalid_client");
    // And the other way around
    final String postCode = this.authorize(params(POST_CLIENT)).get("code");
    assertTokenError(this.token(privateKeyJwt(POST_CLIENT, CLIENT_RSA, "rsa-key"), postCode, REDIRECT_URI, null),
        401, "invalid_client");
  }

  @Test
  void invalidClientAssertionsAreRejected() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Instant now = Instant.now();
    final List<JWTClaimsSet> invalid = List.of(
        assertionClaims(RSA_CLIENT).audience("https://other.example.com").build(),
        assertionClaims(RSA_CLIENT).expirationTime(Date.from(now.minusSeconds(120))).build(),
        assertionClaims(RSA_CLIENT).expirationTime(null).build(),
        assertionClaims(RSA_CLIENT).issueTime(Date.from(now.plusSeconds(600))).build(),
        assertionClaims(RSA_CLIENT).jwtID(null).build(),
        assertionClaims(RSA_CLIENT).subject("https://other.example.com").build());
    for (final JWTClaimsSet claims : invalid) {
      final String code = this.authorize(params(RSA_CLIENT)).get("code");
      assertTokenError(this.token(assertion(RSA_CLIENT, sign(claims, CLIENT_RSA, "rsa-key")), code, REDIRECT_URI,
          null), 401, "invalid_client");
    }
    // The issuer is also accepted as audience
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertThat(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT).audience(BASE_URL).build(),
        CLIENT_RSA, "rsa-key")), code, REDIRECT_URI, null).getStatus()).isEqualTo(200);
  }

  @Test
  void aClientAssertionWithoutIatIsAccepted() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertThat(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT).issueTime(null).build(),
        CLIENT_RSA, "rsa-key")), code, REDIRECT_URI, null).getStatus()).isEqualTo(200);
  }

  @Test
  void anOldClientAssertionIsAcceptedWithoutMaximumAge() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Instant now = Instant.now();
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertThat(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT)
        .issueTime(Date.from(now.minus(Duration.ofDays(1)))).build(), CLIENT_RSA, "rsa-key")), code, REDIRECT_URI,
        null).getStatus()).isEqualTo(200);
  }

  @Test
  void theIatOfAClientAssertionIsCheckedAgainstTheMaximumAgeAndTheClockSkew() throws Exception {
    // The clock skew is the default, 30 seconds
    this.start(c -> oidc(c).maxJwtAge(Duration.ofMinutes(2)), new TestProvider("direct", LOA3));
    final Instant now = Instant.now();
    for (final Instant iat : List.of(now.minusSeconds(160), now.plusSeconds(40))) {
      final String code = this.authorize(params(RSA_CLIENT)).get("code");
      assertTokenError(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT).issueTime(Date.from(iat))
          .build(), CLIENT_RSA, "rsa-key")), code, REDIRECT_URI, null), 401, "invalid_client");
    }
    for (final Instant iat : List.of(now.minusSeconds(140), now.plusSeconds(20))) {
      final String code = this.authorize(params(RSA_CLIENT)).get("code");
      assertThat(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT).issueTime(Date.from(iat))
          .build(), CLIENT_RSA, "rsa-key")), code, REDIRECT_URI, null).getStatus()).isEqualTo(200);
    }
    // Without iat
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertThat(this.token(assertion(RSA_CLIENT, sign(assertionClaims(RSA_CLIENT).issueTime(null).build(),
        CLIENT_RSA, "rsa-key")), code, REDIRECT_URI, null).getStatus()).isEqualTo(200);
  }

  @Test
  void theMaximumAgeAppliesToClientSecretJwt() throws Exception {
    this.start(c -> oidc(c).maxJwtAge(Duration.ofMinutes(2))
        .clientAuthenticationMethods(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_JWT)),
        new TestProvider("direct", LOA3));
    final Instant now = Instant.now();
    String code = this.authorize(params(SECRET_JWT_CLIENT)).get("code");
    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
        assertionClaims(SECRET_JWT_CLIENT).issueTime(Date.from(now.minusSeconds(160))).build());
    jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
    assertTokenError(this.token(assertion(SECRET_JWT_CLIENT, jwt.serialize()), code, REDIRECT_URI, null), 401,
        "invalid_client");

    code = this.authorize(params(SECRET_JWT_CLIENT)).get("code");
    jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
        assertionClaims(SECRET_JWT_CLIENT).issueTime(Date.from(now.minusSeconds(140))).build());
    jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
    assertThat(this.token(assertion(SECRET_JWT_CLIENT, jwt.serialize()), code, REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
  }

  @Test
  void aClientAssertionMayOnlyBeUsedOnce() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> assertion = privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key");
    assertThat(this.token(assertion, this.authorize(params(RSA_CLIENT)).get("code"), REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
    assertTokenError(this.token(assertion, this.authorize(params(RSA_CLIENT)).get("code"), REDIRECT_URI, null), 401,
        "invalid_client");
  }

  @Test
  void aReusedCodeIsRejectedAndItsAccessTokenRevoked() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    final MockHttpServletResponse first =
        this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null);
    final String accessToken = (String) JSONObjectUtils.parse(first.getContentAsString()).get("access_token");
    assertThat(ACCESS_TOKENS.get(accessToken)).isNotNull();

    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null), 400,
        "invalid_grant");
    assertThat(ACCESS_TOKENS.get(accessToken)).isNull();
  }

  @Test
  void anUnknownOrExpiredCodeOrOneForAnotherClientIsInvalidGrant() throws Exception {
    this.start(c -> oidc(c).authorizationCodeLifetime(Duration.ofMillis(200)), new TestProvider("direct", LOA3));
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), "unknown", REDIRECT_URI, null),
        400, "invalid_grant");

    final String otherClientsCode = this.authorize(params(EC_CLIENT)).get("code");
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), otherClientsCode, REDIRECT_URI,
        null), 400, "invalid_grant");

    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    Thread.sleep(300);
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null), 400,
        "invalid_grant");
  }

  @Test
  void aDifferentRedirectUriIsInvalidGrant() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, REDIRECT_URI + "/other",
        null), 400, "invalid_grant");
    final String code2 = this.authorize(params(RSA_CLIENT)).get("code");
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code2, null, null), 400,
        "invalid_grant");
  }

  @Test
  void pkceIsChecked() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final CodeVerifier verifier = new CodeVerifier();
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("code_challenge", CodeChallenge.compute(CodeChallengeMethod.S256, verifier).getValue());
    params.put("code_challenge_method", "S256");

    // Missing verifier
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), this.authorize(params).get("code"),
        REDIRECT_URI, null), 400, "invalid_grant");
    // Wrong verifier
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), this.authorize(params).get("code"),
        REDIRECT_URI, new CodeVerifier().getValue()), 400, "invalid_grant");
    // Verifier without challenge
    assertTokenError(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"),
        this.authorize(params(RSA_CLIENT)).get("code"), REDIRECT_URI, verifier.getValue()), 400, "invalid_grant");
    // Correct
    assertThat(this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), this.authorize(params).get("code"),
        REDIRECT_URI, verifier.getValue()).getStatus()).isEqualTo(200);
  }

  @Test
  void anUnsupportedGrantTypeIsRejected() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> body = new LinkedHashMap<>(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"));
    body.put("grant_type", "refresh_token");
    body.put("refresh_token", "abc");
    assertTokenError(this.send(post(TOKEN_PATH, body, null)), 400, "unsupported_grant_type");
  }

  // Secret-based methods

  @Test
  void secretBasedMethodsWorkWhenEnabled() throws Exception {
    this.start(c -> oidc(c).clientAuthenticationMethods(Set.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT,
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST,
        ClientAuthenticationMethod.CLIENT_SECRET_JWT)), new TestProvider("direct", LOA3));

    // client_secret_basic
    String code = this.authorize(params(BASIC_CLIENT)).get("code");
    final MockHttpServletRequest basic = post(TOKEN_PATH, tokenParams(code, REDIRECT_URI, null),
        "Basic " + Base64.getEncoder().encodeToString(
            (UriUtils.encode(BASIC_CLIENT, StandardCharsets.UTF_8) + ":" + SECRET).getBytes(StandardCharsets.UTF_8)));
    assertThat(this.send(basic).getStatus()).isEqualTo(200);

    // client_secret_post
    code = this.authorize(params(POST_CLIENT)).get("code");
    assertThat(this.token(Map.of("client_id", POST_CLIENT, "client_secret", SECRET), code, REDIRECT_URI, null)
        .getStatus()).isEqualTo(200);
    code = this.authorize(params(POST_CLIENT)).get("code");
    assertTokenError(this.token(Map.of("client_id", POST_CLIENT, "client_secret", "wrong"), code, REDIRECT_URI,
        null), 401, "invalid_client");

    // client_secret_jwt
    code = this.authorize(params(SECRET_JWT_CLIENT)).get("code");
    final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
        assertionClaims(SECRET_JWT_CLIENT).build());
    jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
    assertThat(this.token(assertion(SECRET_JWT_CLIENT, jwt.serialize()), code, REDIRECT_URI, null).getStatus())
        .isEqualTo(200);
  }

  @Test
  void secretBasedMethodsAreRejectedWhenNotEnabled() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(POST_CLIENT)).get("code");
    assertTokenError(this.token(Map.of("client_id", POST_CLIENT, "client_secret", SECRET), code, REDIRECT_URI, null),
        401, "invalid_client");
  }

  // Configuration

  @Test
  void lifetimesAboveTheirLimitsLogAWarningAndStart() throws Exception {
    final ListAppender<ILoggingEvent> appender = appender(OidcProviderConfigurer.class);
    this.start(c -> oidc(c).authorizationCodeLifetime(Duration.ofMinutes(11))
        .idTokenLifetime(Duration.ofMinutes(6))
        .accessTokenLifetime(Duration.ofMinutes(2))
        .singleUseAccessTokens(false), new TestProvider("direct", LOA3));
    assertThat(appender.list).filteredOn(e -> e.getLevel() == ch.qos.logback.classic.Level.WARN)
        .extracting(ILoggingEvent::getFormattedMessage)
        .anyMatch(m -> m.contains("authorization code lifetime"))
        .anyMatch(m -> m.contains("ID token lifetime"));

    final MockHttpServletResponse tokenResponse = this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"),
        this.authorize(params(RSA_CLIENT)).get("code"), REDIRECT_URI, null);
    final Map<String, Object> json = JSONObjectUtils.parse(tokenResponse.getContentAsString());
    assertThat(((Number) json.get("expires_in")).longValue()).isEqualTo(120);
    final JWTClaimsSet claims = SignedJWT.parse((String) json.get("id_token")).getJWTClaimsSet();
    assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
        .isEqualTo(Duration.ofMinutes(6));
    assertThat(ACCESS_TOKENS.get((String) json.get("access_token")).singleUse()).isFalse();
  }

  // Audit

  @Test
  void aCompleteCodeFlowIsAuditedUnderOneCorrelationId() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("scope", "openid profile " + PNR_SCOPE);
    params.put("acr_values", LOA3);
    params.put("prompt", "login");
    final Tokens tokens = this.codeFlow(params);
    assertThat(CorrelationIDHolder.get()).isNull();

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_request_accepted",
        "authn_user_authenticated", "authn_authorization_response", "authn_success_response",
        "authn_userinfo_delivered");
    assertThat(audit.getCorrelationIds()).doesNotContainNull().containsOnly(audit.getCorrelationIds().getFirst());
    assertThat(audit.getEvents()).allSatisfy(e -> {
      assertThat(e.getPrincipal()).isEqualTo(RSA_CLIENT);
      assertThat(AuditCollector.data(e, "requester")).containsEntry("protocol", "oidc").containsEntry("id", RSA_CLIENT);
    });
    assertThat(AuditCollector.data(audit.get("authn_request_received"), "requester")).containsEntry("verified", false);
    assertThat(audit.getEvents().subList(1, 6))
        .allSatisfy(e -> assertThat(AuditCollector.data(e, "requester")).containsEntry("verified", true));

    // The OpenID Connect data
    assertThat(AuditCollector.data(audit.get("authn_request_accepted"), "authn_request"))
        .containsEntry("client_id", RSA_CLIENT)
        .containsEntry("redirect_uri", REDIRECT_URI)
        .containsEntry("response_type", "code")
        .containsEntry("response_mode", "query")
        .containsEntry("scope", List.of("openid", "profile", PNR_SCOPE))
        .containsEntry("acr_values", List.of(LOA3))
        .containsEntry("prompt", List.of("login"))
        .containsEntry("state", "state-1")
        .containsEntry("request_object", false);
    assertThat(AuditCollector.data(audit.get("authn_authorization_response"), "authorization_response"))
        .containsEntry("redirect_uri", REDIRECT_URI)
        .containsEntry("state", "state-1")
        .doesNotContainKey("code");
    assertThat(AuditCollector.data(audit.get("authn_success_response"), "response"))
        .containsEntry("sub", tokens.idToken().getSubject())
        .containsEntry("acr", LOA3)
        .containsEntry("id_token_signed", true)
        .containsEntry("id_token_encrypted", false);
    assertThat(AuditCollector.data(audit.get("authn_userinfo_delivered"), "response"))
        .containsEntry("sub", tokens.idToken().getSubject())
        .containsEntry("signed", true)
        .containsEntry("encrypted", false);

    // All delivered attributes, and the released claims of the ID token and the UserInfo response
    assertThat(attributeNames(audit.get("authn_user_authenticated"), "attributes"))
        .containsExactlyInAnyOrder(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME,
            AttributeIdentifiers.SURNAME);
    assertThat(attributeNames(audit.get("authn_success_response"), "released_attributes"))
        .containsExactly(PNR_CLAIM);
    assertThat(attributeNames(audit.get("authn_userinfo_delivered"), "released_attributes"))
        .containsExactlyInAnyOrder(PNR_CLAIM, "given_name", "family_name");
  }

  @Test
  void aRedirectFlowIsAuditedUnderOneCorrelationIdAcrossItsRequests() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(c -> {}, provider);
    final MockHttpServletResponse redirect = this.send(get(AUTHZ_PATH, params(RSA_CLIENT)));
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);
    provider.getAuthenticatorRepository().complete(new UserAuthentication(user(LOA3)),
        this.appRequest(AUTHN_PATH, authnId));
    final Map<String, String> response = query(this.send(this.appRequest(RESUME_PATH, authnId)));
    final MockHttpServletResponse tokenResponse =
        this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), response.get("code"), REDIRECT_URI, null);
    this.send(userInfoRequest("GET", (String) JSONObjectUtils.parse(tokenResponse.getContentAsString())
        .get("access_token"), null));

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_request_accepted",
        "authn_user_authenticated", "authn_authorization_response", "authn_success_response",
        "authn_userinfo_delivered");
    assertThat(audit.getCorrelationIds()).doesNotContainNull().containsOnly(audit.getCorrelationIds().getFirst());
    assertThat(CorrelationIDHolder.get()).isNull();
  }

  @Test
  void anErrorSentToTheRedirectUriIsAudited() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.error = new AuthenticationErrorException(AuthenticationError.CANCEL);
    this.start(c -> {}, provider);
    this.send(get(AUTHZ_PATH, params(RSA_CLIENT)));

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes())
        .containsExactly("authn_request_received", "authn_request_accepted", "authn_error_response");
    assertThat(audit.getCorrelationIds()).containsOnly(audit.getCorrelationIds().getFirst());
    final AuditEvent error = audit.get("authn_error_response");
    assertThat(error.getPrincipal()).isEqualTo(RSA_CLIENT);
    assertThat(error.getData().get("stage")).isEqualTo("user_authentication");
    assertThat(AuditCollector.data(error, "requester")).containsEntry("verified", true);
    assertThat(AuditCollector.data(error, "error")).containsEntry("code", "access_denied");
    assertThat(AuditCollector.data(error, "response"))
        .containsEntry("redirect_uri", REDIRECT_URI)
        .containsEntry("state", "state-1");
  }

  @Test
  void anInvalidRequestIsAuditedAsAnErrorFromTheRequestStage() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("response_type", "id_token");
    this.send(get(AUTHZ_PATH, params));

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_error_response");
    final AuditEvent error = audit.get("authn_error_response");
    assertThat(error.getData().get("stage")).isEqualTo("authn_request");
    assertThat(AuditCollector.data(error, "requester")).containsEntry("verified", true);
    assertThat(AuditCollector.data(error, "error")).containsEntry("code", "invalid_request");
  }

  @Test
  void anUnknownClientIsAuditedWithTheNamedClientAsPrincipal() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final MockHttpServletResponse response = this.send(get(AUTHZ_PATH, params("https://unknown.example.com")));
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getRedirectedUrl()).isNull();

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_unrecoverable_error");
    assertThat(audit.getCorrelationIds()).doesNotContainNull().containsOnly(audit.getCorrelationIds().getFirst());
    final AuditEvent error = audit.get("authn_unrecoverable_error");
    assertThat(error.getPrincipal()).isEqualTo("https://unknown.example.com");
    assertThat(error.getData().get("stage")).isEqualTo("authn_request");
    assertThat(AuditCollector.data(error, "requester")).containsEntry("verified", false);
    assertThat(AuditCollector.data(error, "error"))
        .containsEntry("code", OidcUnrecoverableError.UNKNOWN_CLIENT.getMessageCode());
    assertThat(CorrelationIDHolder.get()).isNull();
  }

  @Test
  void aRequestWithoutClientIsAuditedWithTheUnknownPrincipal() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.remove("client_id");
    assertThat(this.send(get(AUTHZ_PATH, params)).getStatus()).isEqualTo(400);

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_unrecoverable_error");
    assertThat(audit.getEvents()).allSatisfy(e -> {
      assertThat(e.getPrincipal()).isEqualTo("unknown");
      assertThat(AuditCollector.data(e, "requester")).containsEntry("verified", false).doesNotContainKey("id");
    });
  }

  @Test
  void anUnregisteredRedirectUriIsAuditedOnceWithTheNamedClient() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("redirect_uri", "https://evil.example.com/cb");
    final MockHttpServletResponse response = this.send(get(AUTHZ_PATH, params));
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getRedirectedUrl()).isNull();

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_unrecoverable_error");
    assertThat(AuditCollector.data(audit.get("authn_unrecoverable_error"), "error"))
        .containsEntry("code", OidcUnrecoverableError.INVALID_REDIRECT_URI.getMessageCode());
  }

  @Test
  void anUnsupportedResponseModeIsAuditedAsAnUnrecoverableError() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final Map<String, String> params = params(RSA_CLIENT);
    params.put("response_mode", "fragment");
    assertThat(this.send(get(AUTHZ_PATH, params)).getStatus()).isEqualTo(400);

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_request_received", "authn_unrecoverable_error");
    assertThat(audit.get("authn_unrecoverable_error").getPrincipal()).isEqualTo(RSA_CLIENT);
  }

  @Test
  void tokenEndpointErrorsAreAudited() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    final String code = this.authorize(params(RSA_CLIENT)).get("code");
    final String flow = this.audit().getCorrelationIds().getFirst();
    this.audit().clear();

    // An unknown code cannot be tied to a flow
    this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), "unknown-code", REDIRECT_URI, null);
    // A client that cannot be authenticated is not verified
    this.token(privateKeyJwt(RSA_CLIENT, OTHER, "rsa-key"), code, REDIRECT_URI, null);
    // A client that is not known
    this.token(privateKeyJwt("https://unknown.example.com", CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null);
    // A wrong redirect_uri, for a known code
    this.token(privateKeyJwt(RSA_CLIENT, CLIENT_RSA, "rsa-key"), code, "https://other.example.com", null);
    assertThat(CorrelationIDHolder.get()).isNull();

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsOnly("authn_error_response").hasSize(4);
    assertThat(audit.getEvents())
        .allSatisfy(e -> assertThat(e.getData().get("stage")).isEqualTo("token"));
    final List<AuditEvent> events = audit.getEvents();

    assertThat(events.get(0).getPrincipal()).isEqualTo(RSA_CLIENT);
    assertThat(AuditCollector.data(events.get(0), "requester")).containsEntry("verified", true);
    assertThat(AuditCollector.data(events.get(0), "error")).containsEntry("code", "invalid_grant");
    assertThat(AuditCollector.data(events.get(0), "response")).containsEntry("http_status", 400);
    assertThat(events.get(0).getCorrelationId().getValue()).isNotEqualTo(flow);

    assertThat(events.get(1).getPrincipal()).isEqualTo(RSA_CLIENT);
    assertThat(AuditCollector.data(events.get(1), "requester")).containsEntry("verified", false);
    assertThat(AuditCollector.data(events.get(1), "error")).containsEntry("code", "invalid_client");

    assertThat(events.get(2).getPrincipal()).isEqualTo("https://unknown.example.com");
    assertThat(AuditCollector.data(events.get(2), "requester")).containsEntry("verified", false);

    // The code is known, so the request is audited under the flow
    assertThat(events.get(3).getCorrelationId().getValue()).isEqualTo(flow);
    assertThat(AuditCollector.data(events.get(3), "requester")).containsEntry("verified", true);

    // Each request that was not tied to a flow got an ID of its own
    assertThat(audit.getCorrelationIds().subList(0, 3)).doesNotContainNull().doesNotHaveDuplicates();
  }

  @Test
  void userInfoErrorsAreAudited() throws Exception {
    this.start(c -> {}, new TestProvider("direct", LOA3));
    this.send(userInfoRequest("GET", "unknown-token", null));
    this.send(userInfoRequest("GET", null, null));

    final AuditCollector audit = this.audit();
    assertThat(audit.getTypes()).containsExactly("authn_error_response", "authn_error_response");
    assertThat(audit.getEvents()).allSatisfy(e -> {
      assertThat(e.getPrincipal()).isEqualTo("unknown");
      assertThat(e.getData().get("stage")).isEqualTo("userinfo");
      assertThat(AuditCollector.data(e, "requester"))
          .containsEntry("protocol", "oidc")
          .containsEntry("verified", false);
      assertThat(AuditCollector.data(e, "response")).containsEntry("http_status", 401);
    });
    assertThat(AuditCollector.data(audit.getEvents().get(0), "error")).containsEntry("code", "invalid_token");
    assertThat(AuditCollector.data(audit.getEvents().get(1), "error"))
        .containsEntry("code", UserInfoRequestProcessor.MISSING_TOKEN_AUDIT_CODE);
  }

  // Helpers

  private void start(final Consumer<AuthnServerConfigurer> c, final AbstractUserAuthenticationProvider... p) {
    customizer = c;
    providers = List.of(p);
    this.context = new AnnotationConfigWebApplicationContext();
    this.context.setServletContext(new MockServletContext());
    this.context.register(TestConfiguration.class);
    this.context.refresh();
  }

  private static OidcProviderConfigurer oidc(final AuthnServerConfigurer configurer) {
    return configurer.getProtocolConfigurer(OidcProviderConfigurer.class);
  }

  private MockHttpServletResponse send(final MockHttpServletRequest request) throws Exception {
    request.setSession(this.session);
    final Filter filter = this.context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private AuditCollector audit() {
    return this.context.getBean(AuditCollector.class);
  }

  @SuppressWarnings("unchecked")
  private static List<String> attributeNames(final AuditEvent event, final String name) {
    return ((List<Map<String, Object>>) event.getData().get(name)).stream()
        .map(a -> (String) a.get("name"))
        .toList();
  }

  private Map<String, String> authorize(final Map<String, String> params) throws Exception {
    final MockHttpServletResponse response = this.send(get(AUTHZ_PATH, params));
    final Map<String, String> result = query(response);
    assertThat(result).as("No code - %s", result).containsKey("code");
    return result;
  }

  private Tokens codeFlow(final Map<String, String> params) throws Exception {
    final Map<String, Object> json = this.tokenJson(params);
    final JWTClaimsSet claims = SignedJWT.parse((String) json.get("id_token")).getJWTClaimsSet();
    final MockHttpServletResponse response =
        this.send(userInfoRequest("GET", (String) json.get("access_token"), null));
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    final Map<String, Object> userInfo = signedUserInfo(response).getJWTClaimsSet().getClaims();
    assertThat(userInfo.get("sub")).isEqualTo(claims.getSubject());
    return new Tokens(claims, userInfo);
  }

  private Map<String, Object> tokenJson(final Map<String, String> params) throws Exception {
    final String code = this.authorize(params).get("code");
    final MockHttpServletResponse response =
        this.token(privateKeyJwt(params.get("client_id"), CLIENT_RSA, "rsa-key"), code, REDIRECT_URI, null);
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    return JSONObjectUtils.parse(response.getContentAsString());
  }

  private static MockHttpServletRequest userInfoRequest(final String method, final @Nullable String bearer,
      final @Nullable String bodyToken) {
    final MockHttpServletRequest request = new MockHttpServletRequest(method, USERINFO_PATH);
    request.setScheme("https");
    request.setServerName("op.example.com");
    request.setServerPort(443);
    if (bearer != null) {
      request.addHeader("Authorization", "Bearer " + bearer);
    }
    if (bodyToken != null) {
      request.setContentType("application/x-www-form-urlencoded");
      request.addParameter("access_token", bodyToken);
      request.setContent(("access_token=" + bodyToken).getBytes(StandardCharsets.UTF_8));
    }
    return request;
  }

  private static SignedJWT signedUserInfo(final MockHttpServletResponse response) throws Exception {
    assertThat(response.getContentType()).startsWith("application/jwt");
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    final SignedJWT jwt = SignedJWT.parse(response.getContentAsString());
    verifyByOp(jwt);
    return jwt;
  }

  private static void verifyByOp(final SignedJWT jwt) throws Exception {
    final boolean rsa = JWSAlgorithm.Family.RSA.contains(jwt.getHeader().getAlgorithm());
    assertThat(jwt.getHeader().getKeyID()).isEqualTo(rsa
        ? SigningKey.activeDefault(OP_RSA).getKeyId()
        : SigningKey.active(OP_EC).getKeyId());
    assertThat(jwt.verify(rsa
        ? new RSASSAVerifier((RSAPublicKey) OP_RSA.getPublicKey())
        : new ECDSAVerifier((ECPublicKey) OP_EC.getPublicKey()))).isTrue();
  }

  private static void assertBearerError(final MockHttpServletResponse response, final int status,
      final @Nullable String error) {
    assertThat(response.getStatus()).isEqualTo(status);
    final String header = response.getHeader("WWW-Authenticate");
    assertThat(header).startsWith("Bearer");
    if (error == null) {
      assertThat(header).doesNotContain("error=");
    }
    else {
      assertThat(header).contains("error=\"" + error + "\"");
    }
  }

  private MockHttpServletResponse token(final Map<String, String> clientAuthentication, final @Nullable String code,
      final @Nullable String redirectUri, final @Nullable String verifier) throws Exception {
    final Map<String, String> body = new LinkedHashMap<>(clientAuthentication);
    body.putAll(tokenParams(code, redirectUri, verifier));
    return this.send(post(TOKEN_PATH, body, null));
  }

  private static Map<String, String> tokenParams(final @Nullable String code, final @Nullable String redirectUri,
      final @Nullable String verifier) {
    final Map<String, String> params = new LinkedHashMap<>();
    params.put("grant_type", "authorization_code");
    if (code != null) {
      params.put("code", code);
    }
    if (redirectUri != null) {
      params.put("redirect_uri", redirectUri);
    }
    if (verifier != null) {
      params.put("code_verifier", verifier);
    }
    return params;
  }

  private MockHttpServletRequest appRequest(final String path, final String authnId) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setScheme("https");
    request.setSecure(true);
    request.setServerName("op.example.com");
    request.setServerPort(443);
    request.setServletPath(path);
    request.addParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, authnId);
    request.setSession(this.session);
    return request;
  }

  private static MockHttpServletRequest get(final String path, final Map<String, String> params) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    params.forEach(request::addParameter);
    return request;
  }

  private static MockHttpServletRequest post(final String path, final Map<String, String> params,
      final @Nullable String authorization) {
    final MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
    request.setScheme("https");
    request.setServerName("op.example.com");
    request.setServerPort(443);
    request.setContentType("application/x-www-form-urlencoded");
    params.forEach(request::addParameter);
    if (authorization != null) {
      request.addHeader("Authorization", authorization);
    }
    return request;
  }

  private static Map<String, String> params(final String clientId) {
    final Map<String, String> params = new LinkedHashMap<>();
    params.put("client_id", clientId);
    params.put("response_type", "code");
    params.put("scope", "openid");
    params.put("redirect_uri", REDIRECT_URI);
    params.put("state", "state-1");
    return params;
  }

  private static Map<String, String> query(final MockHttpServletResponse response) {
    assertThat(response.getRedirectedUrl()).as("No redirect").isNotNull().startsWith(REDIRECT_URI);
    final Map<String, String> result = new HashMap<>();
    UriComponentsBuilder.fromUriString(response.getRedirectedUrl()).build().getQueryParams()
        .forEach((k, v) -> result.put(k, UriUtils.decode(v.getFirst(), StandardCharsets.UTF_8)));
    return result;
  }

  private static Map<String, String> formValues(final String page) {
    final Map<String, String> values = new HashMap<>();
    final Matcher matcher = Pattern.compile("name=\"([^\"]+)\" value=\"([^\"]*)\"").matcher(page);
    while (matcher.find()) {
      values.put(matcher.group(1), matcher.group(2));
    }
    return values;
  }

  private static SignedJWT idToken(final MockHttpServletResponse response) throws Exception {
    return SignedJWT.parse((String) JSONObjectUtils.parse(response.getContentAsString()).get("id_token"));
  }

  private static void assertTokenError(final MockHttpServletResponse response, final int status, final String error)
      throws Exception {
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(status);
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    final Map<String, Object> json = JSONObjectUtils.parse(response.getContentAsString());
    assertThat(json.get("error")).isEqualTo(error);
    assertThat(json.get("error_description")).isNotNull();
  }

  private static JWTClaimsSet.Builder assertionClaims(final String clientId) {
    final Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .issuer(clientId)
        .subject(clientId)
        .audience(TOKEN_ENDPOINT)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(60)))
        .jwtID(UUID.randomUUID().toString());
  }

  private static Map<String, String> privateKeyJwt(final String clientId, final PkiCredential key,
      final @Nullable String kid) throws Exception {
    return assertion(clientId, sign(assertionClaims(clientId).build(), key, kid));
  }

  private static Map<String, String> assertion(final String clientId, final String jwt) {
    return Map.of("client_id", clientId,
        "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion", jwt);
  }

  private static String sign(final JWTClaimsSet claims, final PkiCredential key, final @Nullable String kid)
      throws Exception {
    final boolean rsa = key.getPublicKey() instanceof RSAPublicKey;
    final SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(rsa ? JWSAlgorithm.RS256 : JWSAlgorithm.ES256).keyID(kid).build(), claims);
    jwt.sign(rsa ? new RSASSASigner(key.getPrivateKey()) : new ECDSASigner(key.getPrivateKey(), Curve.P_256));
    return jwt.serialize();
  }

  private static ListAppender<ILoggingEvent> appender(final Class<?> type) {
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(type)).addAppender(appender);
    return appender;
  }

  private static RSAKey rsaJwk(final PkiCredential credential, final String kid, final @Nullable KeyUse use) {
    return new RSAKey.Builder((RSAPublicKey) credential.getPublicKey()).keyID(kid).keyUse(use).build();
  }

  private static ECKey ecJwk(final PkiCredential credential, final String kid) {
    return new ECKey.Builder(Curve.P_256, (ECPublicKey) credential.getPublicKey()).keyID(kid).build();
  }

  private static List<OidcClientRecord> clients() {
    final List<OidcClientRecord> clients = new ArrayList<>();
    final JWKSet keys = new JWKSet(List.of(rsaJwk(CLIENT_RSA, "rsa-key", null), ecJwk(CLIENT_EC, "ec-key")));

    clients.add(OidcClientRecord.of(RSA_CLIENT, metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, keys)));

    final OIDCClientMetadata ec = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, keys);
    ec.setIDTokenJWSAlg(JWSAlgorithm.ES256);
    ec.setUserInfoJWSAlg(JWSAlgorithm.ES256);
    clients.add(OidcClientRecord.of(EC_CLIENT, ec));

    final OIDCClientMetadata jwksUriClient = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, null);
    jwksUriClient.setJWKSetURI(URI.create(jwksUri));
    clients.add(OidcClientRecord.of(JWKS_URI_CLIENT, jwksUriClient));

    final OIDCClientMetadata enc = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT,
        new JWKSet(List.of(rsaJwk(CLIENT_RSA, "rsa-key", KeyUse.SIGNATURE),
            rsaJwk(CLIENT_ENC, "enc-key", KeyUse.ENCRYPTION))));
    enc.setIDTokenJWEAlg(JWEAlgorithm.RSA_OAEP_256);
    enc.setIDTokenJWEEnc(EncryptionMethod.A256GCM);
    clients.add(OidcClientRecord.of(ENC_CLIENT, enc));

    final OIDCClientMetadata badEnc = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, keys);
    badEnc.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
    clients.add(OidcClientRecord.of(BAD_ENC_CLIENT, badEnc));

    final OIDCClientMetadata userInfoEnc = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT,
        new JWKSet(List.of(rsaJwk(CLIENT_RSA, "rsa-key", KeyUse.SIGNATURE),
            rsaJwk(CLIENT_ENC, "enc-key", KeyUse.ENCRYPTION))));
    userInfoEnc.setUserInfoJWEAlg(JWEAlgorithm.RSA_OAEP_256);
    userInfoEnc.setUserInfoJWEEnc(EncryptionMethod.A256GCM);
    clients.add(OidcClientRecord.of(USERINFO_ENC_CLIENT, userInfoEnc));

    final OIDCClientMetadata userInfoBadEnc = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, keys);
    userInfoBadEnc.setUserInfoJWEAlg(JWEAlgorithm.RSA1_5);
    clients.add(OidcClientRecord.of(USERINFO_BAD_ENC_CLIENT, userInfoBadEnc));

    for (final Map.Entry<String, ClientAuthenticationMethod> e : Map.of(
        BASIC_CLIENT, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        POST_CLIENT, ClientAuthenticationMethod.CLIENT_SECRET_POST,
        SECRET_JWT_CLIENT, ClientAuthenticationMethod.CLIENT_SECRET_JWT).entrySet()) {
      final OIDCClientMetadata metadata = metadata(e.getValue(), null);
      metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, SECRET);
      clients.add(OidcClientRecord.of(e.getKey(), metadata));
    }
    return clients;
  }

  private static OIDCClientMetadata metadata(final ClientAuthenticationMethod method, final @Nullable JWKSet keys) {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setRedirectionURI(URI.create(REDIRECT_URI));
    metadata.setTokenEndpointAuthMethod(method);
    if (keys != null) {
      metadata.setJWKSet(keys);
    }
    return metadata;
  }

  private static AuthenticatedUser user(final String authnContext) {
    return new AuthenticatedUser(List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, PNR),
        GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Kalle"),
        GenericAttribute.of(AttributeIdentifiers.SURNAME, "Kula")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, authnContext, Instant.now(), "127.0.0.1");
  }

  /** The ID token claims and the UserInfo claims of a code flow. */
  private record Tokens(JWTClaimsSet idToken, Map<String, Object> userInfo) {
  }

  /** A provider that authenticates the user directly. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    private final String name;

    private final List<String> authnContexts;

    AuthenticationErrorException error;

    int calls = 0;

    TestProvider(final String name, final String... authnContexts) {
      this.name = name;
      this.authnContexts = List.of(authnContexts);
    }

    @Override
    protected @NonNull Authentication authenticate(final @NonNull UserAuthenticationInputToken token,
        final @NonNull List<String> authnContextUris) {
      this.calls++;
      if (this.error != null) {
        throw this.error;
      }
      return new UserAuthentication(user(authnContextUris.getFirst()));
    }

    @Override
    public @NonNull String getName() {
      return this.name;
    }

    @Override
    public @NonNull List<String> getSupportedAuthnContextUris() {
      return this.authnContexts;
    }
  }

  /** A provider that authenticates the user on pages of its own. */
  static class TestRedirectProvider extends AbstractUserRedirectAuthenticationProvider {

    private final List<String> authnContexts;

    TestRedirectProvider(final String... authnContexts) {
      super(AUTHN_PATH, RESUME_PATH);
      this.authnContexts = List.of(authnContexts);
    }

    @Override
    public boolean supportsUserAuthenticationToken(final @Nullable Authentication authentication) {
      return authentication instanceof UserAuthentication;
    }

    @Override
    protected @NonNull UserAuthentication createUserAuthentication(final @NonNull ResumedAuthenticationToken token) {
      return (UserAuthentication) token.getAuthnToken();
    }

    @Override
    public @NonNull String getName() {
      return "redirect";
    }

    @Override
    public @NonNull List<String> getSupportedAuthnContextUris() {
      return this.authnContexts;
    }
  }

}
