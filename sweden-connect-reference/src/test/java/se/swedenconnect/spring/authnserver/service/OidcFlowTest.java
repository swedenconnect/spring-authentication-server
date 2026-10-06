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

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import net.minidev.json.JSONObject;
import se.oidc.nimbus.claims.ClaimConstants;

/**
 * End-to-end tests of OpenID Connect flows through the user picker, with the complete profile: authorization, token
 * and UserInfo.
 *
 * @author Martin Lindström
 */
class OidcFlowTest extends AbstractCompleteProfileTest {

  static final String CLIENT_ID = "https://rp.test.local";

  static final String REDIRECT_URI = "https://rp.test.local/callback";

  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  static final String USER = "197705232382";

  static final String COORDINATION_NUMBER_USER = "197010632391";

  static final String NATURAL_PERSON_NUMBER = "https://id.oidc.se/scope/naturalPersonNumber";

  static final PrivateKey CLIENT_KEY = loadClientKey();

  @Test
  void codeFlowWithChoiceOfLevelOfAssuranceAndLockedUser() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request = authorizationRequest("openid " + NATURAL_PERSON_NUMBER);
    request.put("acr_values", LOA3 + " " + LOA2);
    request.put("claims", "{\"id_token\":{\"%s\":{\"value\":\"%s\"}}}"
        .formatted(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME, USER));

    final HttpResponse<String> page = browser.follow(browser.get(authorizeUrl(request)), BASE_URL);
    assertThat(page.statusCode()).isEqualTo(200);
    final String html = page.body();
    // The client name and logo from its metadata, the requested levels of assurance, and the locked user
    assertThat(html).contains("Test Client").contains("https://rp.test.local/logo.svg");
    assertThat(html).contains("requests your authentication");
    assertThat(TestBrowser.optionValues(html, "selectLoa")).containsExactly(LOA3, LOA2);
    assertThat(TestBrowser.startTag(html, "selectSimulatedUser")).contains("disabled");
    assertThat(TestBrowser.selectedOption(html, "selectSimulatedUser")).isEqualTo(USER);

    final Map<String, String> response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA2));
    assertThat(response).containsEntry("state", request.get("state")).containsKey("code");

    // Token
    final OIDCTokenResponse tokens = this.token(response.get("code"));
    final SignedJWT idToken = (SignedJWT) tokens.getOIDCTokens().getIDToken();
    assertThat(idToken.verify(new RSASSAVerifier(this.opKey(idToken.getHeader().getKeyID())))).isTrue();
    final JWTClaimsSet idClaims = idToken.getJWTClaimsSet();
    assertThat(idClaims.getIssuer()).isEqualTo(BASE_URL);
    assertThat(idClaims.getAudience()).containsExactly(CLIENT_ID);
    assertThat(idClaims.getStringClaim("nonce")).isEqualTo(request.get("nonce"));
    assertThat(idClaims.getStringClaim("acr")).isEqualTo(LOA2);
    assertThat(idClaims.getStringClaim(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME)).isEqualTo(USER);

    // UserInfo
    final JWTClaimsSet userInfo = this.userInfo(tokens.getOIDCTokens().getBearerAccessToken());
    assertThat(userInfo.getSubject()).isEqualTo(idClaims.getSubject());
    assertThat(userInfo.getStringClaim(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME)).isEqualTo(USER);
  }

  @Test
  void aUserWithACoordinationNumberGetsTheCoordinationNumberClaim() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request = authorizationRequest("openid " + NATURAL_PERSON_NUMBER);
    request.put("acr_values", LOA3);

    final HttpResponse<String> page = browser.follow(browser.get(authorizeUrl(request)), BASE_URL);
    assertThat(page.statusCode()).isEqualTo(200);
    final Map<String, String> response = this.complete(browser, page.body(), Map.of(
        "action", "ok",
        "personalIdentityNumber", COORDINATION_NUMBER_USER,
        "loa", LOA3));

    final OIDCTokenResponse tokens = this.token(response.get("code"));
    final JWTClaimsSet idClaims = tokens.getOIDCTokens().getIDToken().getJWTClaimsSet();
    assertThat(idClaims.getStringClaim(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME))
        .isEqualTo(COORDINATION_NUMBER_USER);
    assertThat(idClaims.getClaim(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME)).isNull();
  }

  @Test
  void aUserIsAuthenticatedAtLoa4() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request = authorizationRequest("openid " + NATURAL_PERSON_NUMBER);
    request.put("acr_values", LOA4);

    final HttpResponse<String> page = browser.follow(browser.get(authorizeUrl(request)), BASE_URL);
    assertThat(page.statusCode()).isEqualTo(200);
    // A single level of assurance is not offered as a choice
    assertThat(TestBrowser.inputValue(page.body(), "loa")).isEqualTo(LOA4);

    final Map<String, String> response = this.complete(browser, page.body(), Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA4));
    final OIDCTokenResponse tokens = this.token(response.get("code"));
    assertThat(tokens.getOIDCTokens().getIDToken().getJWTClaimsSet().getStringClaim("acr")).isEqualTo(LOA4);
  }

  @Test
  void signatureRequestShowsTheSignMessage() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request =
        authorizationRequest("openid https://id.oidc.se/scope/sign " + NATURAL_PERSON_NUMBER);
    request.put("prompt", "login consent");
    request.put("https://id.oidc.se/param/signRequest", this.signRequest("I sign the *contract*"));

    final String html = browser.follow(browser.get(authorizeUrl(request)), BASE_URL).body();
    assertThat(html).contains("requests your signature").contains("sign-message").contains("<em>contract</em>");
    assertThat(TestBrowser.startTag(html, "selectSimulatedUser")).doesNotContain("disabled");

    final Map<String, String> response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA3,
        "signMessageDisplayed", "true"));
    final OIDCTokenResponse tokens = this.token(response.get("code"));
    final JWTClaimsSet idClaims = tokens.getOIDCTokens().getIDToken().getJWTClaimsSet();
    assertThat(idClaims.getStringClaim("acr")).isEqualTo(LOA3);
    assertThat(this.userInfo(tokens.getOIDCTokens().getBearerAccessToken())
        .getStringClaim(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME)).isEqualTo(USER);
  }

  @Test
  void theFormPostResponseModeUsesTheResponsePage() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request = authorizationRequest("openid " + NATURAL_PERSON_NUMBER);
    request.put("response_mode", "form_post");
    final String html = browser.follow(browser.get(authorizeUrl(request)), BASE_URL).body();

    final Map<String, String> parameters = new HashMap<>(Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA3));
    parameters.put("authnId", TestBrowser.inputValue(html, "authnId"));
    final HttpResponse<String> page = browser.follow(
        browser.post(BASE_URL + TestBrowser.formAction(html), parameters), BASE_URL);
    assertThat(page.statusCode()).isEqualTo(200);
    assertThat(TestBrowser.formAction(page.body())).isEqualTo(REDIRECT_URI);
    assertThat(TestBrowser.inputValue(page.body(), "state")).isEqualTo(request.get("state"));
    assertThat(this.token(TestBrowser.inputValue(page.body(), "code")).getOIDCTokens().getIDToken()).isNotNull();
  }

  @Test
  void aSimulatedErrorIsSentToTheClient() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final Map<String, String> request = authorizationRequest("openid " + NATURAL_PERSON_NUMBER);
    final String html = browser.follow(browser.get(authorizeUrl(request)), BASE_URL).body();
    final Map<String, String> response = this.complete(browser, html, Map.of(
        "action", "error",
        "error", "AUTHN_FAILED",
        "errorMessage", "Simulated failure"));
    assertThat(response)
        .containsEntry("error", "access_denied")
        .containsEntry("error_description", "Simulated failure")
        .containsEntry("state", request.get("state"));
  }

  /**
   * Posts the user picker and returns the parameters of the response at the redirect URI of the client.
   */
  private Map<String, String> complete(final TestBrowser browser, final String html, final Map<String, String> form)
      throws Exception {
    final Map<String, String> parameters = new HashMap<>(form);
    parameters.put("authnId", TestBrowser.inputValue(html, "authnId"));
    final HttpResponse<String> response = browser.follow(
        browser.post(BASE_URL + TestBrowser.formAction(html), parameters), BASE_URL);
    assertThat(TestBrowser.isRedirect(response)).isTrue();
    final String location = TestBrowser.location(response);
    assertThat(location).startsWith(REDIRECT_URI);
    return TestBrowser.queryParameters(location);
  }

  private OIDCTokenResponse token(final String code) throws Exception {
    final URI tokenEndpoint = URI.create(BASE_URL + "/oidc/token");
    final Date now = new Date();
    final SignedJWT assertion = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rp-key").build(),
        new JWTClaimsSet.Builder()
            .issuer(CLIENT_ID)
            .subject(CLIENT_ID)
            .audience(tokenEndpoint.toString())
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + 60_000))
            .jwtID(UUID.randomUUID().toString())
            .build());
    assertion.sign(new RSASSASigner(CLIENT_KEY));
    final TokenRequest request = new TokenRequest(tokenEndpoint, new PrivateKeyJWT(assertion),
        new AuthorizationCodeGrant(new AuthorizationCode(code), URI.create(REDIRECT_URI)));
    final HTTPRequest httpRequest = request.toHTTPRequest();
    httpRequest.setSSLSocketFactory(TestBrowser.SSL_CONTEXT.getSocketFactory());
    final HTTPResponse httpResponse = httpRequest.send();
    assertThat(httpResponse.getStatusCode()).isEqualTo(200);
    return OIDCTokenResponseParser.parse(httpResponse).toSuccessResponse() instanceof final OIDCTokenResponse r
        ? r
        : null;
  }

  private JWTClaimsSet userInfo(final BearerAccessToken accessToken) throws Exception {
    final HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET, URI.create(BASE_URL + "/oidc/userinfo"));
    request.setAuthorization(accessToken.toAuthorizationHeader());
    request.setSSLSocketFactory(TestBrowser.SSL_CONTEXT.getSocketFactory());
    final HTTPResponse response = request.send();
    assertThat(response.getStatusCode()).isEqualTo(200);
    final SignedJWT jwt = SignedJWT.parse(response.getBody());
    assertThat(jwt.verify(new RSASSAVerifier(this.opKey(jwt.getHeader().getKeyID())))).isTrue();
    return jwt.getJWTClaimsSet();
  }

  private RSAPublicKey opKey(final String keyId) throws Exception {
    final JWKSet jwks = JWKSet.parse(new TestBrowser().get(BASE_URL + "/oidc/jwks").body());
    return ((RSAKey) jwks.getKeyByKeyId(keyId)).toRSAPublicKey();
  }

  private String signRequest(final String markdown) throws Exception {
    final JSONObject signMessage = new JSONObject();
    signMessage.put("message#en", encode(markdown));
    signMessage.put("mime_type", "text/markdown");
    final JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(CLIENT_ID)
        .audience(BASE_URL)
        .issueTime(new Date())
        .claim("tbs_data", encode("data to be signed"))
        .claim("sign_message", signMessage)
        .build();
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rp-key").build(), claims);
    jwt.sign(new RSASSASigner(CLIENT_KEY));
    return jwt.serialize();
  }

  private static Map<String, String> authorizationRequest(final String scope) {
    final Map<String, String> request = new LinkedHashMap<>();
    request.put("response_type", "code");
    request.put("client_id", CLIENT_ID);
    request.put("redirect_uri", REDIRECT_URI);
    request.put("scope", scope);
    request.put("state", "state-" + System.nanoTime());
    request.put("nonce", "nonce-" + System.nanoTime());
    return request;
  }

  private static String authorizeUrl(final Map<String, String> request) {
    return BASE_URL + "/oidc/authorize?" + request.entrySet().stream()
        .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
  }

  private static String encode(final String text) {
    return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
  }

  private static PrivateKey loadClientKey() {
    try (final InputStream is = new ClassPathResource("complete/test-clients.p12").getInputStream()) {
      final KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(is, "secret".toCharArray());
      return (PrivateKey) keyStore.getKey("rp", "secret".toCharArray());
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
