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
package se.swedenconnect.spring.authnserver.authentication.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.oidcRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.samlRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Tests for {@link UserAuthenticationInputToken}.
 *
 * @author Martin Lindström
 */
class UserAuthenticationInputTokenTest {

  @Test
  void theTokenCarriesWhatTheProviderNeeds() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    final Requester requester = samlRequester("https://sp.example.com/sp");
    final UserAuthenticationInputToken token =
        new UserAuthenticationInputToken(requirements, requester, "_1a2b3c", "the-request");

    assertThat(token.getAuthnRequirements()).isSameAs(requirements);
    assertThat(token.getRequester()).isSameAs(requester);
    assertThat(token.getRequestId()).isEqualTo("_1a2b3c");
    assertThat(token.getProtocolRequestData()).isEqualTo("the-request");
    assertThat(token.getPrincipal()).isSameAs(requester);
    assertThat(token.getCredentials()).isEqualTo("");
    assertThat(token.isAuthenticated()).isFalse();
    assertThat(token.getLogString()).contains("https://sp.example.com/sp", "_1a2b3c");
    assertThat(token).hasToString(token.getLogString());
  }

  @Test
  void aRequestWithoutAnIdentifierIsTheOpenIdConnectCase() {
    final UserAuthenticationInputToken token =
        new UserAuthenticationInputToken(new AuthenticationRequirements(), oidcRequester("client-1"));

    assertThat(token.getRequestId()).isNull();
    assertThat(token.getProtocolRequestData()).isNull();
    assertThat(token.getLogString()).contains("client-1").doesNotContain("request:");
  }

  @Test
  void thePreviousAuthenticationIsSetBeforeTheProviderIsCalled() {
    final UserAuthenticationInputToken token =
        new UserAuthenticationInputToken(new AuthenticationRequirements(), oidcRequester("client-1"));
    assertThat(token.getPreviousAuthentication()).isNull();

    final UserAuthentication previous = new UserAuthentication(user());
    token.setPreviousAuthentication(previous);
    assertThat(token.getPreviousAuthentication()).isSameAs(previous);

    token.setPreviousAuthentication(null);
    assertThat(token.getPreviousAuthentication()).isNull();
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void theRequirementsAndTheRequesterAreRequired() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new UserAuthenticationInputToken(null, oidcRequester("client-1")))
        .withMessage("authnRequirements must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new UserAuthenticationInputToken(new AuthenticationRequirements(), null))
        .withMessage("requester must not be null");
  }

}
