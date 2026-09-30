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
package se.swedenconnect.spring.authnserver.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.samlRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link UserAuthenticationFlow}.
 *
 * @author Martin Lindström
 */
class UserAuthenticationFlowTest {

  private static final String CONTEXT_KEY = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void theProvidersAreAskedInOrderAndTheFirstResultIsUsed() throws Exception {
    final List<String> asked = new ArrayList<>();
    final UserAuthentication result = new UserAuthentication(user());
    final UserAuthenticationFlow flow = new UserAuthenticationFlow(List.of(
        provider("first", asked, null), provider("second", asked, result), provider("third", asked, null)));
    final UserAuthenticationInputToken token = token();

    assertThat(flow.authenticate(token, new MockHttpServletRequest(), new MockHttpServletResponse()))
        .isSameAs(result);
    assertThat(asked).containsExactly("first", "second");
    assertThat(result.getAuthnRequirements()).isSameAs(token.getAuthnRequirements());
    assertThat(result.getProtocolRequestData()).isEqualTo("request-data");
  }

  @Test
  void whenNoProviderHandlesTheRequestTheErrorIsNoAuthnContext() {
    final UserAuthenticationFlow flow =
        new UserAuthenticationFlow(List.of(provider("first", new ArrayList<>(), null)));
    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> flow.authenticate(token(), new MockHttpServletRequest(), new MockHttpServletResponse()))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.NO_AUTHN_CONTEXT));
  }

  @Test
  void aProviderThatAsksForARedirectWithoutBeingARedirectProviderIsAnInternalError() {
    final UserAuthenticationProvider provider = new TestProvider("odd") {
      @Override
      public @Nullable Authentication authenticateUser(final @Nonnull UserAuthenticationInputToken token) {
        return new RedirectForAuthenticationToken("id", token, List.of(LOA3), "/authn", "/resume");
      }
    };
    final UserAuthenticationFlow flow = new UserAuthenticationFlow(List.of(provider));
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> flow.authenticate(token(), new MockHttpServletRequest(), new MockHttpServletResponse()));
  }

  @Test
  void theAuthenticationInTheSessionIsGivenToTheProviders() throws Exception {
    final UserAuthentication previous = new UserAuthentication(user());
    SecurityContextHolder.setContext(new SecurityContextImpl(previous));
    final UserAuthenticationFlow flow =
        new UserAuthenticationFlow(List.of(provider("first", new ArrayList<>(), previous)));
    final UserAuthenticationInputToken token = token();
    flow.authenticate(token, new MockHttpServletRequest(), new MockHttpServletResponse());
    assertThat(token.getPreviousAuthentication()).isSameAs(previous);
  }

  @Test
  void aReusableAuthenticationIsSavedInTheSessionWithoutTheRequestData() {
    final UserAuthenticationFlow flow = new UserAuthenticationFlow(List.of());
    final UserAuthentication authentication = new UserAuthentication(user());
    authentication.setAuthnRequirements(new AuthenticationRequirements());
    authentication.setProtocolRequestData("data");
    final MockHttpServletRequest request = new MockHttpServletRequest();

    flow.saveAuthentication(authentication, request, new MockHttpServletResponse());
    assertThat(authentication.getAuthnRequirements()).isNull();
    assertThat(authentication.getProtocolRequestData()).isNull();
    assertThat(((SecurityContextImpl) request.getSession().getAttribute(CONTEXT_KEY)).getAuthentication())
        .isSameAs(authentication);
  }

  @Test
  void anAuthenticationThatMayNotBeReusedClearsTheSession() {
    final UserAuthenticationFlow flow = new UserAuthenticationFlow(List.of());
    final MockHttpServletRequest request = new MockHttpServletRequest();
    flow.saveAuthentication(new UserAuthentication(user()), request, new MockHttpServletResponse());
    assertThat(request.getSession().getAttribute(CONTEXT_KEY)).isNotNull();

    final UserAuthentication notReusable = new UserAuthentication(user());
    notReusable.setReuseForSso(false);
    flow.saveAuthentication(notReusable, request, new MockHttpServletResponse());
    assertThat(request.getSession().getAttribute(CONTEXT_KEY)).isNull();
  }

  private static UserAuthenticationInputToken token() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setAuthnContextRequirements(List.of(LOA3));
    return new UserAuthenticationInputToken(requirements, samlRequester("https://sp.example.com"), "_id",
        "request-data");
  }

  private static UserAuthenticationProvider provider(final String name, final List<String> asked,
      final @Nullable Authentication result) {
    return new TestProvider(name) {
      @Override
      public @Nullable Authentication authenticateUser(final @Nonnull UserAuthenticationInputToken token) {
        asked.add(name);
        return result;
      }
    };
  }

  private abstract static class TestProvider implements UserAuthenticationProvider {

    private final String name;

    TestProvider(final String name) {
      this.name = name;
    }

    @Override
    public @Nonnull String getName() {
      return this.name;
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return List.of(LOA3);
    }
  }

}
