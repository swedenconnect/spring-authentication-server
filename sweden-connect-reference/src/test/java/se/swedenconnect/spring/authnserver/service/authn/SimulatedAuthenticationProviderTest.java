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
package se.swedenconnect.spring.authnserver.service.authn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUser;

/**
 * Tests for {@link SimulatedAuthenticationProvider}.
 *
 * @author Martin Lindström
 */
class SimulatedAuthenticationProviderTest {

  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private final SimulatedAuthenticationProvider provider = new SimulatedAuthenticationProvider("Simulated",
      "/extauth", "/resume", List.of(LOA3), List.of("http://id.elegnamnden.se/ec/1.0/loa3-pnr"));

  @Test
  void theProviderDeclaresWhatItOffers() {
    assertThat(this.provider.getName()).isEqualTo("Simulated");
    assertThat(this.provider.getAuthnPath()).isEqualTo("/extauth");
    assertThat(this.provider.getResumeAuthnPath()).isEqualTo("/resume");
    assertThat(this.provider.getSupportedAuthnContextUris()).containsExactly(LOA3);
    assertThat(this.provider.getEntityCategories()).containsExactly("http://id.elegnamnden.se/ec/1.0/loa3-pnr");
    assertThat(this.provider.getSupportedAttributes()).contains(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.DATE_OF_BIRTH);
    assertThat(this.provider.getSupportedScopes()).contains("openid", "https://id.oidc.se/scope/sign",
        "https://id.oidc.se/scope/signApproval", "https://id.oidc.se/scope/naturalPersonNumber");
    assertThat(this.provider.supportsUserAuthenticationToken(token(user(), null))).isTrue();
    assertThat(this.provider.supportsUserAuthenticationToken(new TestingAuthenticationToken("a", "b"))).isFalse();
  }

  @Test
  void theSelectedUserBecomesTheAuthenticatedUser() {
    final SimulatedAuthenticationToken token = token(user(), null);
    final AuthenticatedUser user = this.provider.createUserAuthentication(resumed(token)).getAuthenticatedUser();

    assertThat(user.getUsername()).isEqualTo("197705232382");
    assertThat(user.getPrimaryAttribute()).isEqualTo(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
    assertThat(user.getAuthnContextUri()).isEqualTo(LOA3);
    assertThat(user.getAuthnInstant()).isEqualTo(token.getAuthnInstant());
    assertThat(user.getClientIpAddress()).isEqualTo("127.0.0.1");
    assertThat(user.getAttribute(AttributeIdentifiers.GIVEN_NAME).getValue()).isEqualTo("Frida");
    assertThat(user.getAttribute(AttributeIdentifiers.SURNAME).getValue()).isEqualTo("Kranstege");
    assertThat(user.getAttribute(AttributeIdentifiers.DISPLAY_NAME).getValue()).isEqualTo("Frida Kranstege");
    assertThat(user.getAttribute(AttributeIdentifiers.DATE_OF_BIRTH).getValue()).isEqualTo(LocalDate.of(1977, 5, 23));
    assertThat(user.isSignMessageDisplayed()).isFalse();
  }

  @Test
  void aDisplayedSignMessageIsRecorded() {
    final UserAuthentication authentication = this.provider.createUserAuthentication(resumed(token(user(), "sv")));
    assertThat(authentication.getAuthenticatedUser().isSignMessageDisplayed()).isTrue();
    assertThat(authentication.getAuthenticatedUser().getSignMessageLanguage()).isEqualTo("sv");
    assertThat(authentication.isReuseForSso()).isFalse();
  }

  @Test
  void attributesWithoutValuesAreLeftOut() {
    final SimulatedUser user = new SimulatedUser();
    user.setPersonalNumber("abcdefghijkl");
    user.setGivenName("Frida");
    final AuthenticatedUser result =
        this.provider.createUserAuthentication(resumed(token(user, null))).getAuthenticatedUser();
    assertThat(result.getAttribute(AttributeIdentifiers.SURNAME)).isNull();
    assertThat(result.getAttribute(AttributeIdentifiers.DATE_OF_BIRTH)).isNull();
  }

  @Test
  void anotherTokenIsRejected() {
    assertThatThrownBy(() -> this.provider.createUserAuthentication(new ResumedAuthenticationToken(redirectToken(),
        new TestingAuthenticationToken("a", "b"))))
        .isInstanceOf(AuthenticationErrorException.class);
  }

  @Test
  void invalidSettingsAreRejected() {
    assertThatThrownBy(() -> new SimulatedAuthenticationProvider(" ", "/a", "/b", List.of(LOA3), null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new SimulatedAuthenticationProvider("x", "/a", "/b", List.of(), null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(new SimulatedAuthenticationProvider("x", "/a", "/b", List.of(LOA3), null).getEntityCategories())
        .isEmpty();
  }

  static SimulatedUser user() {
    final SimulatedUser user = new SimulatedUser();
    user.setPersonalNumber("197705232382");
    user.setGivenName("Frida");
    user.setSurname("Kranstege");
    return user;
  }

  private static SimulatedAuthenticationToken token(final SimulatedUser user, final String signMessageLanguage) {
    final SimulatedAuthenticationToken token = new SimulatedAuthenticationToken(user, LOA3, Instant.now(), "127.0.0.1");
    if (signMessageLanguage != null) {
      token.setSignMessageDisplayed(signMessageLanguage);
    }
    return token;
  }

  private static ResumedAuthenticationToken resumed(final SimulatedAuthenticationToken token) {
    return new ResumedAuthenticationToken(redirectToken(), token);
  }

  private static RedirectForAuthenticationToken redirectToken() {
    return new RedirectForAuthenticationToken("id", new UserAuthenticationInputToken(new AuthenticationRequirements(),
        new Requester(AuthenticationProtocol.SAML, "https://sp.example.com")), List.of(LOA3), "/extauth", "/resume");
  }

}
