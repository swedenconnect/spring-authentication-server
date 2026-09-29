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
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.CLIENT;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.SP;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.redirectToken;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Tests for {@link ResumedAuthenticationToken}.
 *
 * @author Martin Lindström
 */
class ResumedAuthenticationTokenTest {

  @Test
  void aResultTokenCarriesTheResultAndTheOriginalInput() {
    final UserAuthentication result = new UserAuthentication(user());
    final ResumedAuthenticationToken token = new ResumedAuthenticationToken(redirectToken("abc123", SP), result);

    assertThat(token.getAuthnId()).isEqualTo("abc123");
    assertThat(token.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(token.getAuthnInputToken().getRequester()).isEqualTo(SP);
    assertThat(token.getAuthnContextUris()).containsExactly(LOA3);
    assertThat(token.getRedirectToken().getAuthnId()).isEqualTo("abc123");
    assertThat(token.getAuthnToken()).isSameAs(result);
    assertThat(token.getError()).isNull();
    assertThat(token.isError()).isFalse();
    assertThat(token.isAuthenticated()).isTrue();
    assertThat(token.getName()).isEqualTo(result.getName());
    assertThat(token.getPrincipal()).isSameAs(result.getPrincipal());
    assertThat(token.getAuthorities()).isEmpty();
    assertThat(token.getCredentials()).isEqualTo("");
    assertThat(token.getDetails()).isSameAs(result.getDetails());
  }

  @Test
  void anErrorTokenCarriesTheErrorAndTheOriginalInput() {
    final AuthenticationErrorException error = new AuthenticationErrorException(AuthenticationError.CANCEL);
    final ResumedAuthenticationToken token = new ResumedAuthenticationToken(redirectToken("xyz", CLIENT), error);

    assertThat(token.getAuthnId()).isEqualTo("xyz");
    assertThat(token.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(token.getAuthnToken()).isNull();
    assertThat(token.getError()).isSameAs(error);
    assertThat(token.isError()).isTrue();
    assertThat(token.isAuthenticated()).isFalse();
    assertThat(token.getAuthorities()).isEmpty();
    assertThat(token.getCredentials()).isNull();
    assertThat(token.getDetails()).isNull();
    assertThat(token.getPrincipal()).isEqualTo(CLIENT);
    assertThat(token.getName()).isNotNull();
    assertThat(token.toString()).contains("User cancelled authentication");
  }

  @Test
  void theServletRequestIsCarriedAlong() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final ResumedAuthenticationToken token =
        new ResumedAuthenticationToken(redirectToken("abc123", SP), new UserAuthentication(user()));

    assertThat(token.getServletRequest()).isNull();
    token.setServletRequest(request);
    assertThat(token.getServletRequest()).isSameAs(request);
  }

  @Test
  void theTokenMustNotBeMarkedAsAuthenticated() {
    final ResumedAuthenticationToken token =
        new ResumedAuthenticationToken(redirectToken("abc123", SP), new UserAuthentication(user()));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> token.setAuthenticated(true));
  }

}
