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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;
import jakarta.servlet.RequestDispatcher;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;

import se.oidc.nimbus.claims.ParameterConstants;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.scope.TestAuthenticationProvider;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequiredMarksRequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.WhitelistRequesterPredicate;

/**
 * Tests for the processing of OpenID Connect authentication requests, through the filter chain built by the
 * configurers.
 *
 * @author Martin Lindström
 */
class OidcAuthnRequestProcessingTest {

  private static final String BASE_URL = "https://op.example.com";

  private static final String AUTHZ_PATH = "/oidc/authorize";

  private static final String AUTHZ_ENDPOINT = BASE_URL + AUTHZ_PATH;

  private static final String CLIENT_ID = "https://rp.example.com";

  private static final String OTHER_CLIENT_ID = "https://app.example.com";

  private static final String PUBLIC_CLIENT_ID = "https://public.example.com";

  private static final String DEFAULT_ACR_CLIENT_ID = "https://default-acr.example.com";

  private static final String ALG_CLIENT_ID = "https://alg.example.com";

  private static final String REDIRECT_URI = "https://rp.example.com/callback";

  private static final String REQUEST_URI = "https://rp.example.com/requests/1";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private static final String UNSUPPORTED_LOA = "http://id.elegnamnden.se/loa/1.0/loa2";

  private static final String PNR_SCOPE = "https://id.oidc.se/scope/naturalPersonNumber";

  private static final String SIGN_SCOPE = "https://id.oidc.se/scope/sign";

  private static final String SIGN_APPROVAL_SCOPE = "https://id.oidc.se/scope/signApproval";

  private static final String TRUST_MARK = "https://tm.example.com/public-sector";

  private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  private static final PkiCredential OP_SIGN = KeyTestSupport.rsa("op-sign", 2048);

  private static final PkiCredential OP_ENCRYPT = KeyTestSupport.rsa("op-encrypt", 2048);

  private static final PkiCredential CLIENT_KEY = KeyTestSupport.rsa("client", 2048);

  private static final PkiCredential OTHER_KEY = KeyTestSupport.rsa("other", 2048);

  /** The customization of the configurers for the current test. */
  private static Consumer<AuthnServerConfigurer> customizer;

  /** The client registry backend of the current test. */
  private static TestBackend backend;

  /** The request objects that the request URI fetcher serves. */
  private static final Map<URI, String> REQUEST_OBJECTS = new HashMap<>();

  /** The URIs that the fetcher has been asked for. */
  private static final List<URI> FETCHED = new ArrayList<>();

  /** The result of the processing. */
  private static final AtomicReference<UserAuthenticationInputToken> RESULT = new AtomicReference<>();

  private AnnotationConfigWebApplicationContext context;

  /** The configuration of the server. */
  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .clientRegistryBackend(backend)
          .authenticationProvider(new TestAuthenticationProvider("test", List.of(LOA3, LOA4),
              List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME), List.of()))
          .protocol(new OidcProviderConfigurer()
              .signingKeys(List.of(SigningKey.activeDefault(OP_SIGN)))
              .decryptionKeys(List.of(DecryptionKey.active(OP_ENCRYPT)))
              .scopes(List.of("openid", "profile", PNR_SCOPE, SIGN_SCOPE, SIGN_APPROVAL_SCOPE))
              .authnRequestProcessor(c -> c
                  .requestUriFetcher(uri -> {
                    FETCHED.add(uri);
                    final String requestObject = REQUEST_OBJECTS.get(uri);
                    if (requestObject == null) {
                      throw new IOException("Not found");
                    }
                    return requestObject;
                  })
                  .successHandler((request, response, authentication) ->
                      RESULT.set((UserAuthenticationInputToken) authentication))));
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      return http.build();
    }
  }

  @AfterEach
  void close() {
    if (this.context != null) {
      this.context.close();
      this.context = null;
    }
    RESULT.set(null);
    REQUEST_OBJECTS.clear();
    FETCHED.clear();
  }

  // Valid requests

  @Test
  void aGetRequestWithPlainParametersGivesTheAuthenticationRequirements() throws Exception {
    this.start(c -> c.supportsUserMessage(true));
    final Map<String, String> params = params();
    params.put("scope", "openid " + PNR_SCOPE + " https://example.com/unknown");
    params.put("acr_values", LOA4 + " " + UNSUPPORTED_LOA + " " + LOA3);
    params.put("prompt", "login consent");
    params.put("max_age", "600");
    params.put("login_hint", "197705232382");
    params.put("ui_locales", "sv en");
    params.put("nonce", "n-0S6_WzA2Mj");
    params.put("claims", "{\"id_token\":{\"given_name\":{\"essential\":true}}}");
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, userMessage().toJSONString());
    params.put(ParameterConstants.REQUESTED_PROVIDER_PARAM_NAME, "https://idp.example.com");

    final UserAuthenticationInputToken token = this.process(get(params));

    assertThat(token.getRequester().protocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(token.getRequester().identifier()).isEqualTo(CLIENT_ID);
    assertThat(token.getRequestId()).isNull();
    final OidcAuthenticationRequirements requirements = requirements(token);
    assertThat(requirements.getScopes()).containsExactly("openid", PNR_SCOPE);
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA4, UNSUPPORTED_LOA, LOA3);
    assertThat(requirements.isVoluntaryAuthnContexts()).isTrue();
    assertThat(requirements.isForceAuthn()).isTrue();
    assertThat(requirements.isPassiveAuthn()).isFalse();
    assertThat(requirements.isConsentRequired()).isTrue();
    assertThat(requirements.getMaxAuthnAge()).isEqualTo(Duration.ofSeconds(600));
    assertThat(requirements.getLoginHint()).isEqualTo("197705232382");
    assertThat(requirements.getUiLocales()).containsExactly("sv", "en");
    assertThat(requirements.getRequestedAuthnProviders()).containsExactly("https://idp.example.com");
    assertThat(requirements.getRequestedAttributes()).extracting(GenericRequestedAttribute::getIdentifier)
        .contains(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME);
    assertThat(requirements.getRequestedAttributes())
        .filteredOn(a -> AttributeIdentifiers.GIVEN_NAME.equals(a.getIdentifier()))
        .allMatch(GenericRequestedAttribute::isEssential);
    final GenericUserMessage userMessage = requirements.getUserMessage();
    assertThat(userMessage).isNotNull();
    assertThat(userMessage.getMimeType()).isEqualTo(MessageMimeType.TEXT_MARKDOWN);
    assertThat(userMessage.getMessage("sv").getText()).isEqualTo("Hej");
    assertThat(userMessage.getMessage("en").getText()).isEqualTo("Hello");
    assertThat(requirements.toString()).doesNotContain("197705232382");

    final OidcAuthnRequestData data = (OidcAuthnRequestData) token.getProtocolRequestData();
    assertThat(data).isNotNull();
    assertThat(data.responseTarget().redirectUri()).isEqualTo(REDIRECT_URI);
    assertThat(data.responseTarget().state()).isEqualTo("state-1");
    assertThat(data.responseTarget().responseMode()).isEqualTo("query");
    assertThat(data.nonce()).isEqualTo("n-0S6_WzA2Mj");
    assertThat(data.scopes()).contains("https://example.com/unknown");
    assertThat(data.claimsRequest()).contains("given_name");
  }

  @Test
  void aPostRequestIsProcessed() throws Exception {
    this.start(c -> {});
    final UserAuthenticationInputToken token = this.process(post(params()));
    assertThat(requirements(token).getScopes()).containsExactly("openid");
    assertThat(requirements(token).isForceAuthn()).isFalse();
  }

  @Test
  void aSignedRequestObjectReplacesTheParameters() throws Exception {
    this.start(c -> {});
    final JWTClaimsSet claims = requestObjectClaims()
        .claim("scope", "openid profile")
        .claim("state", "state-from-ro")
        .claim("max_age", 0)
        .claim("claims", Map.of("id_token", Map.of("acr", Map.of("essential", true, "values", List.of(LOA3)))))
        .build();
    final Map<String, String> params = new LinkedHashMap<>();
    params.put("client_id", CLIENT_ID);
    params.put("response_type", "code");
    params.put("scope", "openid");
    params.put("state", "outer-state");
    params.put("request", sign(claims, CLIENT_KEY));

    final UserAuthenticationInputToken token = this.process(post(params));

    final OidcAuthenticationRequirements requirements = requirements(token);
    assertThat(requirements.getScopes()).containsExactly("openid", "profile");
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA3);
    assertThat(requirements.isForceAuthn()).isTrue();
    assertThat(((OidcAuthnRequestData) token.getProtocolRequestData()).responseTarget().state())
        .isEqualTo("state-from-ro");
  }

  @Test
  void anEncryptedRequestObjectIsDecrypted() throws Exception {
    this.start(c -> {});
    final JWTClaimsSet claims = requestObjectClaims().claim("login_hint", "hint").build();
    final Map<String, String> params = Map.of("client_id", CLIENT_ID, "request",
        encrypt(new Payload(SignedJWT.parse(sign(claims, CLIENT_KEY)))));

    assertThat(requirements(this.process(post(params))).getLoginHint()).isEqualTo("hint");
  }

  @Test
  void anEncryptedUnsignedRequestObjectIsAcceptedByDefault() throws Exception {
    this.start(c -> {});
    final JWTClaimsSet claims = requestObjectClaims().claim("login_hint", "hint").build();
    final Map<String, String> params = Map.of("client_id", CLIENT_ID, "request",
        encrypt(new Payload(new PlainJWT(claims).serialize())));

    assertThat(requirements(this.process(post(params))).getLoginHint()).isEqualTo("hint");
  }

  @Test
  void aRequestObjectEncryptedForAnotherKeyIsRejected() throws Exception {
    this.start(c -> {});
    final JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT").build(), new Payload(sign(requestObjectClaims().build(), CLIENT_KEY)));
    jwe.encrypt(new RSAEncrypter((RSAPublicKey) OTHER_KEY.getPublicKey()));
    final Map<String, String> params = params();
    params.put("request", jwe.serialize());

    assertError(this.send(get(params)), "invalid_request_object", "state-1");
  }

  @Test
  void aRegisteredRequestUriIsFetched() throws Exception {
    this.start(c -> {});
    REQUEST_OBJECTS.put(URI.create(REQUEST_URI),
        sign(requestObjectClaims().claim("login_hint", "from-uri").build(), CLIENT_KEY));
    final Map<String, String> params = Map.of("client_id", CLIENT_ID, "request_uri", REQUEST_URI + "#hash");

    assertThat(requirements(this.process(get(params))).getLoginHint()).isEqualTo("from-uri");
    assertThat(FETCHED).containsExactly(URI.create(REQUEST_URI));
  }

  @Test
  void anUnregisteredRequestUriIsNotFetched() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("request_uri", "https://attacker.example.com/ro");

    assertError(this.send(get(params)), "invalid_request_uri", "state-1");
    assertThat(FETCHED).isEmpty();
  }

  @Test
  void aRequestUriFromAClientWithoutRegisteredRequestUrisIsNotFetched() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params(OTHER_CLIENT_ID);
    params.put("request_uri", REQUEST_URI);

    assertError(this.send(get(params)), "invalid_request_uri", "state-1");
    assertThat(FETCHED).isEmpty();
  }

  @Test
  void aFailedFetchIsAnError() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("request_uri", REQUEST_URI);

    assertError(this.send(get(params)), "invalid_request_uri", "state-1");
    assertThat(FETCHED).containsExactly(URI.create(REQUEST_URI));
  }

  @Test
  void anInvalidRequestObjectWithoutUsableRedirectUriIsUnrecoverable() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = Map.of("client_id", CLIENT_ID, "request", "not-a-jwt");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_AUTHN_REQUEST, 400);
  }

  @Test
  void requestObjectClaimsAreChecked() throws Exception {
    this.start(c -> {});
    final Instant now = Instant.now();
    final List<JWTClaimsSet> invalid = List.of(
        requestObjectClaims().issuer("https://other.example.com").build(),
        requestObjectClaims().audience("https://other.example.com").build(),
        requestObjectClaims().claim("client_id", "https://other.example.com").build(),
        requestObjectClaims().expirationTime(Date.from(now.minusSeconds(600))).build(),
        requestObjectClaims().notBeforeTime(Date.from(now.plusSeconds(600))).build(),
        new JWTClaimsSet.Builder(requestObjectClaims().build()).issuer(null).build());
    for (final JWTClaimsSet claims : invalid) {
      final Map<String, String> params = params();
      params.put("request", sign(claims, CLIENT_KEY));
      assertError(this.send(post(params)), "invalid_request_object", "state-1");
    }
    // The audience may also be the authorization endpoint
    final Map<String, String> params = params();
    params.put("request", sign(requestObjectClaims().audience(AUTHZ_ENDPOINT).build(), CLIENT_KEY));
    this.process(post(params));
  }

  @Test
  void aRequestObjectSignedWithAnotherKeyIsRejected() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("request", sign(requestObjectClaims().build(), OTHER_KEY));
    assertError(this.send(post(params)), "invalid_request_object", "state-1");
  }

  // Settings

  @Test
  void unsignedRequestObjectsAreAcceptedByDefaultAndRejectedWhenSignedOnesAreRequired() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("request", new PlainJWT(requestObjectClaims().build()).serialize());
    this.process(post(params));
    this.close();

    this.start(c -> oidc(c).requireSignedRequestObject(true));
    assertError(this.send(post(params)), "invalid_request_object", "state-1");
    params.put("request", sign(requestObjectClaims().build(), CLIENT_KEY));
    this.process(post(params));
  }

  @Test
  void aClientWithRegisteredSigningAlgorithmMustSignWithIt() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params(ALG_CLIENT_ID);
    params.put("request", new PlainJWT(requestObjectClaims(ALG_CLIENT_ID).build()).serialize());
    assertError(this.send(post(params)), "invalid_request_object", "state-1");

    params.put("request", sign(requestObjectClaims(ALG_CLIENT_ID).build(), CLIENT_KEY, JWSAlgorithm.RS512));
    assertError(this.send(post(params)), "invalid_request_object", "state-1");

    params.put("request", sign(requestObjectClaims(ALG_CLIENT_ID).build(), CLIENT_KEY));
    this.process(post(params));
  }

  @Test
  void pkceIsOptionalByDefault() throws Exception {
    this.start(c -> {});
    this.process(get(params()));

    final Map<String, String> params = params();
    params.put("code_challenge", CHALLENGE);
    params.put("code_challenge_method", "S256");
    final OidcAuthnRequestData data = (OidcAuthnRequestData) this.process(get(params)).getProtocolRequestData();
    assertThat(data.codeChallenge()).isEqualTo(CHALLENGE);
    assertThat(data.codeChallengeMethod()).isEqualTo("S256");
  }

  @Test
  void aPublicClientIsAClientConfigurationError() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params(PUBLIC_CLIENT_ID);
    params.put("code_challenge", CHALLENGE);
    params.put("code_challenge_method", "S256");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION, 500);
  }

  @Test
  void pkceMayBeRequiredForAllClients() throws Exception {
    this.start(c -> oidc(c).requirePkce(true));
    assertError(this.send(get(params())), "invalid_request", "state-1");
    final Map<String, String> params = params();
    params.put("code_challenge", CHALLENGE);
    params.put("code_challenge_method", "S256");
    this.process(get(params));
  }

  @Test
  void plainPkceIsAlwaysRejected() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("code_challenge", VERIFIER);
    params.put("code_challenge_method", "plain");
    assertError(this.send(get(params)), "invalid_request", "state-1");

    // No method means plain
    params.remove("code_challenge_method");
    assertError(this.send(get(params)), "invalid_request", "state-1");
  }

  @Test
  void stateIsRequiredByDefault() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.remove("state");
    assertError(this.send(get(params)), "invalid_request", null);
  }

  @Test
  void stateMayBeOptional() throws Exception {
    this.start(c -> oidc(c).requireState(false));
    final Map<String, String> params = params();
    params.remove("state");
    final UserAuthenticationInputToken token = this.process(get(params));
    assertThat(((OidcAuthnRequestData) token.getProtocolRequestData()).responseTarget().state()).isNull();

    // An error response has no state
    params.put("code_challenge", VERIFIER);
    params.put("code_challenge_method", "plain");
    final MockHttpServletResponse response = this.send(get(params));
    assertError(response, "invalid_request", null);
    assertThat(query(response)).doesNotContainKey("state");
  }

  // Errors

  @Test
  void anUnknownClientIsUnrecoverable() throws Exception {
    this.start(c -> {});
    this.assertUnrecoverable(get(params("https://unknown.example.com")), OidcUnrecoverableError.UNKNOWN_CLIENT, 400);
  }

  @Test
  void aMissingClientIdIsUnrecoverable() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.remove("client_id");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_AUTHN_REQUEST, 400);
  }

  @Test
  void aRegistryFailureIsToldApartFromAnUnknownClient() throws Exception {
    this.start(c -> {});
    backend.failing = true;
    this.assertUnrecoverable(get(params()), OidcUnrecoverableError.CLIENT_LOOKUP_FAILED, 503);
  }

  @Test
  void anInvalidOrMissingRedirectUriIsUnrecoverable() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("redirect_uri", "https://rp.example.com/other");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_REDIRECT_URI, 400);
    params.put("redirect_uri", REDIRECT_URI + "/");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_REDIRECT_URI, 400);
    params.remove("redirect_uri");
    this.assertUnrecoverable(get(params), OidcUnrecoverableError.INVALID_REDIRECT_URI, 400);
  }

  @Test
  void laterFailuresAreSentToTheRedirectUriWithQuery() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("response_type", "token");
    final MockHttpServletResponse response = this.send(get(params));
    assertError(response, "unsupported_response_type", "state-1");
    assertThat(response.getRedirectedUrl()).startsWith(REDIRECT_URI + "?");
  }

  @Test
  void laterFailuresAreSentToTheRedirectUriWithFormPost() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("response_mode", "form_post");
    params.put("scope", "profile");
    final MockHttpServletResponse response = this.send(post(params));
    assertThat(response.getRedirectedUrl()).isNull();
    final String page = response.getContentAsString();
    assertThat(page).contains("action=\"" + REDIRECT_URI + "\"")
        .contains("name=\"error\" value=\"invalid_request\"")
        .contains("name=\"state\" value=\"state-1\"");
  }

  @Test
  void anUnsupportedResponseModeGivesStatus400() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("response_mode", "fragment");
    final MockHttpServletResponse response = this.send(get(params));
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getRedirectedUrl()).isNull();
    assertThat(RESULT.get()).isNull();
  }

  @Test
  void promptNoneIsPassiveAndCannotBeCombined() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("prompt", "none");
    final OidcAuthenticationRequirements requirements = requirements(this.process(get(params)));
    assertThat(requirements.isPassiveAuthn()).isTrue();
    assertThat(requirements.isForceAuthn()).isFalse();

    params.put("prompt", "none login");
    assertError(this.send(get(params)), "invalid_request", "state-1");
  }

  @Test
  void anInvalidMaxAgeIsAnError() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("max_age", "-5");
    assertError(this.send(get(params)), "invalid_request", "state-1");
  }

  @Test
  void essentialAcrValuesThatCannotBeMetAreRejected() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("claims", acrClaim(true, UNSUPPORTED_LOA));
    assertError(this.send(get(params)), "unmet_authentication_requirements", "state-1");

    // Essential values are required, and the unsupported ones are left out
    params.put("claims", acrClaim(true, UNSUPPORTED_LOA, LOA4));
    params.put("acr_values", LOA3);
    final OidcAuthenticationRequirements requirements = requirements(this.process(get(params)));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA4);
    assertThat(requirements.isVoluntaryAuthnContexts()).isFalse();
  }

  @Test
  void acrValuesAreVoluntary() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("acr_values", UNSUPPORTED_LOA);
    OidcAuthenticationRequirements requirements = requirements(this.process(get(params)));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(UNSUPPORTED_LOA);
    assertThat(requirements.isVoluntaryAuthnContexts()).isTrue();

    // Values of the claims parameter that are not essential are also voluntary, and win over acr_values
    params.put("claims", acrClaim(false, LOA4));
    requirements = requirements(this.process(get(params)));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA4);
    assertThat(requirements.isVoluntaryAuthnContexts()).isTrue();
  }

  @Test
  void theDefaultAcrValuesOfTheClientApplyOnlyWithoutRequestedAcr() throws Exception {
    this.start(c -> {});
    OidcAuthenticationRequirements requirements = requirements(this.process(get(params(DEFAULT_ACR_CLIENT_ID))));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(UNSUPPORTED_LOA, LOA4);
    assertThat(requirements.isVoluntaryAuthnContexts()).isTrue();

    final Map<String, String> params = params(DEFAULT_ACR_CLIENT_ID);
    params.put("acr_values", LOA3);
    assertThat(requirements(this.process(get(params))).getAuthnContextRequirements()).containsExactly(LOA3);

    params.remove("acr_values");
    params.put("claims", "{\"id_token\":{\"acr\":null}}");
    requirements = requirements(this.process(get(params)));
    assertThat(requirements.getAuthnContextRequirements()).isEmpty();

    // A client without defaults gets no authentication contexts
    assertThat(requirements(this.process(get(params()))).getAuthnContextRequirements()).isEmpty();
  }

  @Test
  void aValidIdTokenHintGivesTheSubject() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("id_token_hint", idToken(BASE_URL, CLIENT_ID, OP_SIGN, Instant.now().minusSeconds(3600)));
    assertThat(requirements(this.process(get(params))).getIdTokenHintSubject()).isEqualTo("subject-1");
  }

  @Test
  void anIdTokenHintNotIssuedByThisOpForTheClientIsRejected() throws Exception {
    this.start(c -> {});
    for (final String hint : List.of(
        idToken(BASE_URL, CLIENT_ID, OTHER_KEY, Instant.now().plusSeconds(60)),
        idToken("https://other.example.com", CLIENT_ID, OP_SIGN, Instant.now().plusSeconds(60)),
        idToken(BASE_URL, OTHER_CLIENT_ID, OP_SIGN, Instant.now().plusSeconds(60)),
        new PlainJWT(new JWTClaimsSet.Builder().subject("s").build()).serialize())) {
      final Map<String, String> params = params();
      params.put("id_token_hint", hint);
      assertError(this.send(get(params)), "invalid_request", "state-1");
    }
  }

  @Test
  void aUserMessageIsIgnoredWhenUserMessagesAreNotSupported() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, userMessage().toJSONString());
    assertThat(requirements(this.process(get(params))).getUserMessage()).isNull();

    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, "not json");
    assertThat(requirements(this.process(get(params))).getUserMessage()).isNull();
  }

  @Test
  void anInvalidUserMessageIsRejectedWhenUserMessagesAreSupported() throws Exception {
    this.start(c -> oidc(c).supportsUserMessage(true));
    final Map<String, String> params = params();
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, "not json");
    assertError(this.send(get(params)), "invalid_request", "state-1");

    final JSONObject html = userMessage();
    html.put("mime_type", "text/html");
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, html.toJSONString());
    assertError(this.send(get(params)), "invalid_request", "state-1");

    // Not Base64
    final JSONObject notBase64 = new JSONObject();
    notBase64.put("message#sv", "Hej på dig");
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, notBase64.toJSONString());
    assertError(this.send(get(params)), "invalid_request", "state-1");

    // Empty
    final JSONObject empty = new JSONObject();
    empty.put("message", "");
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, empty.toJSONString());
    assertError(this.send(get(params)), "invalid_request", "state-1");
  }

  @Test
  void aUserMessageIsHandedOnWithItsText() throws Exception {
    this.start(c -> oidc(c).supportsUserMessage(true));
    final Map<String, String> params = params();
    final JSONObject message = new JSONObject();
    message.put("message", encode("Välkommen – åäö"));
    message.put("message#en", encode(" "));
    params.put(ParameterConstants.USER_MESSAGE_PARAM_NAME, message.toJSONString());

    final GenericUserMessage userMessage = requirements(this.process(get(params))).getUserMessage();
    assertThat(userMessage).isNotNull();
    assertThat(userMessage.getMimeType()).isEqualTo(MessageMimeType.TEXT_PLAIN);
    assertThat(userMessage.getDefaultMessage()).isNotNull();
    assertThat(userMessage.getDefaultMessage().getText()).isEqualTo("Välkommen – åäö");
    assertThat(userMessage.getDefaultMessage().message()).isEqualTo(encode("Välkommen – åäö"));
    assertThat(userMessage.getMessage("en").getText()).isEqualTo(" ");
  }

  @Test
  void aUserMessageInARequestObjectIsRead() throws Exception {
    this.start(c -> oidc(c).supportsUserMessage(true));
    final Map<String, String> params = params();
    params.put("request", sign(requestObjectClaims()
        .claim(ParameterConstants.USER_MESSAGE_PARAM_NAME, userMessage()).build(), CLIENT_KEY));
    assertThat(requirements(this.process(post(params))).getUserMessage()).isNotNull();
  }

  @Test
  void aSignRequestAsASignedParameterGivesTheSignMessage() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("scope", "openid " + SIGN_SCOPE);
    params.put("prompt", "login consent");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME,
        sign(new JWTClaimsSet.Builder(JWTClaimsSet.parse(signRequest(true))).issuer(CLIENT_ID).build(), CLIENT_KEY));

    final GenericSignMessage signMessage = requirements(this.process(post(params))).getSignMessage();
    assertThat(signMessage).isNotNull();
    assertThat(signMessage.isMustShow()).isTrue();
    assertThat(signMessage.getTbsData()).isEqualTo(encode("to be signed"));
    assertThat(signMessage.getMessage("en").getText()).isEqualTo("I sign");
  }

  @Test
  void aSignRequestInASignedRequestObjectIsRead() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("request", sign(requestObjectClaims()
        .claim("scope", "openid " + SIGN_APPROVAL_SCOPE)
        .claim("prompt", "login consent")
        .claim(ParameterConstants.SIGN_REQUEST_PARAM_NAME, signRequest(false)).build(), CLIENT_KEY));
    final GenericSignMessage signMessage = requirements(this.process(post(params))).getSignMessage();
    assertThat(signMessage).isNotNull();
    assertThat(signMessage.getTbsData()).isNull();
  }

  @Test
  void invalidSignRequestsAreRejected() throws Exception {
    this.start(c -> {});

    // Missing consent
    Map<String, String> params = params();
    params.put("scope", "openid " + SIGN_SCOPE);
    params.put("prompt", "login");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME,
        sign(JWTClaimsSet.parse(signRequest(true)), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // Missing parameter
    params.put("prompt", "login consent");
    params.remove(ParameterConstants.SIGN_REQUEST_PARAM_NAME);
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // Not signed
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME,
        new PlainJWT(JWTClaimsSet.parse(signRequest(true))).serialize());
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // No tbs_data for sign
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest(false)), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // tbs_data for approval
    params.put("scope", "openid " + SIGN_APPROVAL_SCOPE);
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest(true)), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // In an unsigned request object
    params = params();
    params.put("request", new PlainJWT(requestObjectClaims()
        .claim("scope", "openid " + SIGN_APPROVAL_SCOPE)
        .claim("prompt", "login consent")
        .claim(ParameterConstants.SIGN_REQUEST_PARAM_NAME, signRequest(false)).build()).serialize());
    assertError(this.send(post(params)), "invalid_request", "state-1");
  }

  @Test
  void signRequestsWithInvalidContentsAreRejected() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("scope", "openid " + SIGN_SCOPE);
    params.put("prompt", "login consent");

    // tbs_data is not Base64
    Map<String, Object> signRequest = signRequest(true);
    signRequest.put("tbs_data", "not Base64!");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // tbs_data is empty
    signRequest.put("tbs_data", "");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // tbs_data is not a string
    signRequest.put("tbs_data", 1234);
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // No sign_message
    signRequest = signRequest(true);
    signRequest.remove("sign_message");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // sign_message is not an object
    signRequest.put("sign_message", "I sign");
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // The message is not Base64
    signRequest.put("sign_message", new JSONObject(Map.of("message#en", "I sign!")));
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");

    // The sign message is HTML
    signRequest.put("sign_message", new JSONObject(Map.of("message#en", encode("I sign"), "mime_type", "text/html")));
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));
    assertError(this.send(post(params)), "invalid_request", "state-1");
  }

  @Test
  void aSignMessageIsHandedOnWithItsText() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put("scope", "openid " + SIGN_APPROVAL_SCOPE);
    params.put("prompt", "login consent");
    final Map<String, Object> signRequest = new HashMap<>();
    signRequest.put("sign_message", new JSONObject(Map.of(
        "message", encode("Jag godkänner – åäö"), "message#en", encode("I approve"), "mime_type", "text/markdown")));
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, sign(JWTClaimsSet.parse(signRequest), CLIENT_KEY));

    final GenericSignMessage signMessage = requirements(this.process(post(params))).getSignMessage();
    assertThat(signMessage).isNotNull();
    assertThat(signMessage.getTbsData()).isNull();
    assertThat(signMessage.getMimeType()).isEqualTo(MessageMimeType.TEXT_MARKDOWN);
    assertThat(signMessage.getDefaultMessage()).isNotNull();
    assertThat(signMessage.getDefaultMessage().getText()).isEqualTo("Jag godkänner – åäö");
    assertThat(signMessage.getMessage("en").getText()).isEqualTo("I approve");
  }

  @Test
  void aSignRequestWithoutSignScopeIsIgnored() throws Exception {
    this.start(c -> {});
    final Map<String, String> params = params();
    params.put(ParameterConstants.SIGN_REQUEST_PARAM_NAME, "anything");
    assertThat(requirements(this.process(get(params))).getSignMessage()).isNull();
  }

  // Requester acceptance

  @Test
  void aWhitelistAcceptsAndRejects() throws Exception {
    this.start(c -> c.configurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.OIDC, List.of(CLIENT_ID))));
    this.process(get(params()));
    final Map<String, String> params = params(OTHER_CLIENT_ID);
    params.put("code_challenge", CHALLENGE);
    params.put("code_challenge_method", "S256");
    assertError(this.send(get(params)), "unauthorized_client", "state-1");
  }

  @Test
  void requiredTrustMarksAreRequestedOnDemandBeforeRejecting() throws Exception {
    this.start(c -> c.configurableRequesterAcceptance()
        .addPredicate(new RequiredMarksRequesterPredicate(AuthenticationProtocol.OIDC, List.of(List.of(TRUST_MARK))))
        .mode(AuthenticationProtocol.OIDC, ConfigurableRequesterAcceptance.Mode.ALL));
    assertError(this.send(get(params())), "unauthorized_client", "state-1");
    assertThat(backend.requestedMarks).containsExactly(TRUST_MARK);

    backend.requestedMarks.clear();
    backend.obtainableMarks.add(TRUST_MARK);
    this.process(get(params()));
    assertThat(backend.requestedMarks).containsExactly(TRUST_MARK);
  }

  @Test
  void aRegistryFailureDuringAcceptanceIsUnrecoverable() throws Exception {
    this.start(c -> c.configurableRequesterAcceptance()
        .addPredicate(new RequiredMarksRequesterPredicate(AuthenticationProtocol.OIDC, List.of(List.of(TRUST_MARK)))));
    backend.failOnRequestMark = true;
    this.assertUnrecoverable(get(params()), OidcUnrecoverableError.CLIENT_LOOKUP_FAILED, 503);
  }

  // Helpers

  private void start(final Consumer<AuthnServerConfigurer> c) {
    backend = new TestBackend();
    customizer = c;
    this.context = new AnnotationConfigWebApplicationContext();
    this.context.setServletContext(new MockServletContext());
    this.context.register(TestConfiguration.class);
    this.context.refresh();
  }

  private static OidcProviderConfigurer oidc(final AuthnServerConfigurer configurer) {
    return configurer.getProtocolConfigurer(OidcProviderConfigurer.class);
  }

  private MockHttpServletResponse send(final MockHttpServletRequest request) throws Exception {
    RESULT.set(null);
    final Filter filter = this.context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private UserAuthenticationInputToken process(final MockHttpServletRequest request) throws Exception {
    final MockHttpServletResponse response = this.send(request);
    assertThat(RESULT.get()).as("The request was not processed - %s", response.getRedirectedUrl()).isNotNull();
    return RESULT.get();
  }

  /**
   * Asserts that the request ends at the error page with the expected status, and is never redirected.
   */
  private void assertUnrecoverable(final MockHttpServletRequest request, final OidcUnrecoverableError error,
      final int status) throws Exception {
    final MockHttpServletResponse response = this.send(request);
    assertThat(response.getStatus()).isEqualTo(status);
    assertThat(response.getRedirectedUrl()).isNull();
    assertThat(response.getHeader("Location")).isNull();
    assertThat(request.getAttribute(RequestDispatcher.ERROR_EXCEPTION))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class, e -> assertThat(e.getError()).isEqualTo(error));
    assertThat(RESULT.get()).isNull();
  }

  private static void assertError(final MockHttpServletResponse response, final String error,
      final @Nullable String state) {
    assertThat(RESULT.get()).isNull();
    final Map<String, String> query = query(response);
    assertThat(query.get("error")).isEqualTo(error);
    assertThat(query.get("error_description")).isNotBlank();
    assertThat(query.get("state")).isEqualTo(state);
  }

  private static Map<String, String> query(final MockHttpServletResponse response) {
    assertThat(response.getRedirectedUrl()).as("No redirect").isNotNull().startsWith(REDIRECT_URI);
    final MultiValueMap<String, String> params =
        UriComponentsBuilder.fromUriString(response.getRedirectedUrl()).build().getQueryParams();
    final Map<String, String> result = new HashMap<>();
    params.forEach((k, v) -> result.put(k, UriUtils.decode(v.getFirst(), StandardCharsets.UTF_8)));
    return result;
  }

  private static OidcAuthenticationRequirements requirements(final UserAuthenticationInputToken token) {
    return (OidcAuthenticationRequirements) token.getAuthnRequirements();
  }

  private static Map<String, String> params() {
    return params(CLIENT_ID);
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

  private static MockHttpServletRequest get(final Map<String, String> params) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHZ_PATH);
    params.forEach(request::addParameter);
    return request;
  }

  private static MockHttpServletRequest post(final Map<String, String> params) {
    final MockHttpServletRequest request = new MockHttpServletRequest("POST", AUTHZ_PATH);
    request.setContentType("application/x-www-form-urlencoded");
    params.forEach(request::addParameter);
    return request;
  }

  private static JWTClaimsSet.Builder requestObjectClaims() {
    return requestObjectClaims(CLIENT_ID);
  }

  private static JWTClaimsSet.Builder requestObjectClaims(final String clientId) {
    return new JWTClaimsSet.Builder()
        .issuer(clientId)
        .audience(BASE_URL)
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
        .claim("client_id", clientId)
        .claim("response_type", "code")
        .claim("scope", "openid")
        .claim("redirect_uri", REDIRECT_URI)
        .claim("state", "state-1");
  }

  private static String sign(final JWTClaimsSet claims, final PkiCredential key) throws Exception {
    return sign(claims, key, JWSAlgorithm.RS256);
  }

  private static String sign(final JWTClaimsSet claims, final PkiCredential key, final JWSAlgorithm algorithm)
      throws Exception {
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).keyID("client-key").build(), claims);
    jwt.sign(new RSASSASigner(key.getPrivateKey()));
    return jwt.serialize();
  }

  private static String encrypt(final Payload payload) throws Exception {
    final JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT").keyID(DecryptionKey.active(OP_ENCRYPT).getKeyId()).build(), payload);
    jwe.encrypt(new RSAEncrypter((RSAPublicKey) OP_ENCRYPT.getPublicKey()));
    return jwe.serialize();
  }

  private static String idToken(final String issuer, final String audience, final PkiCredential key,
      final Instant expires) throws Exception {
    final JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(issuer).audience(audience).subject("subject-1")
        .issueTime(Date.from(expires.minusSeconds(300))).expirationTime(Date.from(expires))
        .build();
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);
    jwt.sign(new RSASSASigner(key.getPrivateKey()));
    return jwt.serialize();
  }

  private static String acrClaim(final boolean essential, final String... values) {
    final JSONObject acr = new JSONObject();
    if (essential) {
      acr.put("essential", true);
    }
    acr.put("values", List.of(values));
    return new JSONObject(Map.of("id_token", new JSONObject(Map.of("acr", acr)))).toJSONString();
  }

  private static JSONObject userMessage() {
    final JSONObject message = new JSONObject();
    message.put("message#sv", encode("Hej"));
    message.put("message#en", encode("Hello"));
    message.put("mime_type", "text/markdown");
    return message;
  }

  private static Map<String, Object> signRequest(final boolean withTbsData) {
    final JSONObject signMessage = new JSONObject();
    signMessage.put("message#en", encode("I sign"));
    final Map<String, Object> signRequest = new HashMap<>();
    if (withTbsData) {
      signRequest.put("tbs_data", encode("to be signed"));
    }
    signRequest.put("sign_message", signMessage);
    return signRequest;
  }

  private static String encode(final String text) {
    return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
  }

  private static OIDCClientMetadata metadata(final ClientAuthenticationMethod authMethod,
      final @Nullable JWSAlgorithm requestObjectAlg, final boolean withRequestUris) {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setRedirectionURI(URI.create(REDIRECT_URI));
    metadata.setTokenEndpointAuthMethod(authMethod);
    metadata.setJWKSet(new JWKSet(new RSAKey.Builder((RSAPublicKey) CLIENT_KEY.getPublicKey())
        .keyID("client-key").build()));
    metadata.setRequestObjectJWSAlg(requestObjectAlg);
    if (withRequestUris) {
      metadata.setRequestObjectURIs(Set.of(URI.create(REQUEST_URI)));
    }
    return metadata;
  }

  /**
   * A client registry backend with two confidential clients, a public client, a client that has registered a request
   * object signing algorithm and a client with default acr values. Trust marks can be made obtainable on demand.
   */
  private static class TestBackend implements ClientRegistryBackend {

    boolean failing = false;

    boolean failOnRequestMark = false;

    final List<String> obtainableMarks = new ArrayList<>();

    final List<String> requestedMarks = new ArrayList<>();

    @Override
    public @NonNull String getName() {
      return "test";
    }

    @Override
    public @NonNull AuthenticationProtocol getProtocol() {
      return AuthenticationProtocol.OIDC;
    }

    @Override
    public @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException {
      if (this.failing) {
        throw new ClientRegistryException("Backend failure");
      }
      final Set<String> marks = Set.copyOf(this.obtainableMarks.stream()
          .filter(this.requestedMarks::contains).toList());
      return switch (identifier) {
        case CLIENT_ID -> new OidcClientRecord(CLIENT_ID,
            metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, null, true), marks).toRequesterRecord();
        case OTHER_CLIENT_ID -> new OidcClientRecord(OTHER_CLIENT_ID,
            metadata(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, false), marks).toRequesterRecord();
        case PUBLIC_CLIENT_ID -> new OidcClientRecord(PUBLIC_CLIENT_ID,
            metadata(ClientAuthenticationMethod.NONE, null, false), marks).toRequesterRecord();
        case DEFAULT_ACR_CLIENT_ID -> {
          final OIDCClientMetadata metadata = metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, null, false);
          metadata.setDefaultACRs(List.of(new ACR(UNSUPPORTED_LOA), new ACR(LOA4)));
          yield new OidcClientRecord(DEFAULT_ACR_CLIENT_ID, metadata, marks).toRequesterRecord();
        }
        case ALG_CLIENT_ID -> new OidcClientRecord(ALG_CLIENT_ID,
            metadata(ClientAuthenticationMethod.PRIVATE_KEY_JWT, JWSAlgorithm.RS256, false), marks)
            .toRequesterRecord();
        default -> null;
      };
    }

    @Override
    public @Nullable RequesterRecord requestMark(final @NonNull String identifier, final @NonNull String mark)
        throws ClientRegistryException {
      if (this.failOnRequestMark) {
        throw new ClientRegistryException("Trust mark issuer failure");
      }
      this.requestedMarks.add(mark);
      return this.lookup(identifier);
    }
  }

}
