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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.AUTHN_PATH;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.CLIENT;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.RESUME_PATH;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.SP;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.inputToken;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.redirectToken;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;

/**
 * Tests for {@link RedirectForAuthenticationToken}.
 *
 * @author Martin Lindström
 */
class RedirectForAuthenticationTokenTest {

  @Test
  void theTokenCarriesTheAuthenticationAndThePaths() {
    final RedirectForAuthenticationToken token = redirectToken("abc123", SP);

    assertThat(token.getAuthnId()).isEqualTo("abc123");
    assertThat(token.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(token.getAuthnContextUris()).containsExactly(LOA3);
    assertThat(token.getAuthnPath()).isEqualTo(AUTHN_PATH);
    assertThat(token.getResumeAuthnPath()).isEqualTo(RESUME_PATH);
    assertThat(token.isAuthenticated()).isFalse();
    assertThat(token.getAuthorities()).isEmpty();
    assertThat(token.getPrincipal()).isEqualTo(SP);
    assertThat(token.getName()).isNotNull();
    assertThat(token.getCredentials()).isEqualTo("");
    assertThat(token.getDetails()).isNull();
    assertThat(token.toString()).contains("abc123");
  }

  @Test
  void theProtocolIsTheOneOfTheRequester() {
    assertThat(redirectToken("abc123", CLIENT).getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
  }

  @Test
  void theIdentifierIsAppendedToThePaths() {
    final RedirectForAuthenticationToken token = redirectToken("abc123", SP);
    assertThat(token.getRedirectPath()).isEqualTo("/authn/login?authnId=abc123");
    assertThat(token.getResumeRedirectPath()).isEqualTo("/authn/resume?authnId=abc123");
  }

  @Test
  void anIdentifierThatNeedsEncodingIsEncoded() {
    assertThat(RedirectForAuthenticationToken.pathWithAuthnId("/a", "x y&z"))
        .isEqualTo("/a?authnId=x+y%26z");
  }

  @Test
  void theIdentifierIsReadFromTheRequest() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(RedirectForAuthenticationToken.getAuthnId(request)).isNull();

    request.setParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, "  ");
    assertThat(RedirectForAuthenticationToken.getAuthnId(request)).isNull();

    request.setParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, "abc123");
    assertThat(RedirectForAuthenticationToken.getAuthnId(request)).isEqualTo("abc123");
  }

  @Test
  void aMissingIdentifierOrABadPathIsRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new RedirectForAuthenticationToken("", inputToken(SP), List.of(), AUTHN_PATH, RESUME_PATH));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new RedirectForAuthenticationToken("id", inputToken(SP), List.of(), "authn", RESUME_PATH));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new RedirectForAuthenticationToken("id", inputToken(SP), List.of(), AUTHN_PATH, "/r?x=1"));
  }

  @Test
  void theTokenMustNotBeMarkedAsAuthenticated() {
    final RedirectForAuthenticationToken token = redirectToken("abc123", SP);
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> token.setAuthenticated(true));
  }

  @Test
  void theTokenSurvivesSerialization() throws Exception {
    final RedirectForAuthenticationToken token =
        SerializationTestSupport.roundTrip(redirectToken("abc123", SP));

    assertThat(token.getAuthnId()).isEqualTo("abc123");
    assertThat(token.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(token.getAuthnContextUris()).containsExactly(LOA3);
    assertThat(token.getAuthnInputToken().getRequestId()).isEqualTo("_1a2b3c");
    assertThat(token.getAuthnInputToken().getRequester()).isEqualTo(SP);
    assertThat(token.getResumeRedirectPath()).isEqualTo("/authn/resume?authnId=abc123");
  }

}
