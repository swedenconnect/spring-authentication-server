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
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.CLIENT;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.SP;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.redirectToken;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.request;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractUserRedirectAuthenticationProviderTest.TestProvider;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link AbstractAuthenticationController}.
 *
 * @author Martin Lindström
 */
class AbstractAuthenticationControllerTest {

  /** A controller that only uses what the base class offers. */
  static class TestController extends AbstractAuthenticationController<TestProvider> {

    private final TestProvider provider;

    TestController(final TestProvider provider) {
      this.provider = provider;
    }

    @Override
    protected @Nonnull TestProvider getProvider() {
      return this.provider;
    }

    @Override
    public @Nonnull RedirectForAuthenticationToken getInputToken(final @Nonnull HttpServletRequest request) {
      return super.getInputToken(request);
    }

    @Override
    public @Nonnull ModelAndView complete(final @Nonnull HttpServletRequest request,
        final @Nonnull Authentication authentication) {
      return super.complete(request, authentication);
    }

    @Override
    public @Nonnull ModelAndView complete(final @Nonnull HttpServletRequest request,
        final @Nonnull AuthenticationErrorException error) {
      return super.complete(request, error);
    }

    @Override
    public @Nonnull ModelAndView cancel(final @Nonnull HttpServletRequest request) {
      return super.cancel(request);
    }
  }

  private TestProvider provider;

  private TestController controller;

  private MockHttpSession session;

  @BeforeEach
  void setUp() {
    this.provider = new TestProvider();
    this.controller = new TestController(this.provider);
    this.session = new MockHttpSession();
  }

  @Test
  void theControllerGetsTheInputOfTheCurrentAuthentication() {
    final RedirectForAuthenticationToken token = redirectToken("one", SP);
    this.provider.getFlowRepository().start(token, request(this.session, "one"));

    assertThat(this.controller.getInputToken(request(this.session, "one"))).isSameAs(token);
  }

  @Test
  void aRequestThatBelongsToNoAuthenticationIsAnInvalidSession() {
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> this.controller.getInputToken(request(this.session, "one")))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INVALID_SESSION));
  }

  @Test
  void completingWithAResultReachesTheResumeWithIt() {
    this.provider.getFlowRepository().start(redirectToken("one", SP), request(this.session, "one"));

    final UserAuthentication result = new UserAuthentication(user());
    final ModelAndView view = this.controller.complete(request(this.session, "one"), result);
    assertThat(view.getViewName()).isEqualTo("redirect:/authn/resume?authnId=one");

    final ResumedAuthenticationToken resumed =
        this.provider.getFlowRepository().resume(request(this.session, "one"));
    assertThat(resumed.getAuthnToken()).isSameAs(result);
    assertThat(resumed.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
  }

  @Test
  void completingWithAnErrorReachesTheResumeWithIt() {
    this.provider.getFlowRepository().start(redirectToken("one", CLIENT), request(this.session, "one"));

    final AuthenticationErrorException error =
        new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "no card in the reader");
    final ModelAndView view = this.controller.complete(request(this.session, "one"), error);
    assertThat(view.getViewName()).isEqualTo("redirect:/authn/resume?authnId=one");

    final ResumedAuthenticationToken resumed =
        this.provider.getFlowRepository().resume(request(this.session, "one"));
    assertThat(resumed.getError()).isSameAs(error);
    assertThat(resumed.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
  }

  @Test
  void cancellingReachesTheResumeAsTheCancelError() {
    this.provider.getFlowRepository().start(redirectToken("one", SP), request(this.session, "one"));

    final ModelAndView view = this.controller.cancel(request(this.session, "one"));
    assertThat(view.getViewName()).isEqualTo("redirect:/authn/resume?authnId=one");

    final ResumedAuthenticationToken resumed =
        this.provider.getFlowRepository().resume(request(this.session, "one"));
    assertThat(resumed.getError()).isNotNull();
    assertThat(resumed.getError().getError()).isEqualTo(AuthenticationError.CANCEL);
  }

  @Test
  void twoAuthenticationsAreCompletedEachWithItsOwnResult() {
    this.provider.getFlowRepository().start(redirectToken("saml", SP), request(this.session, "saml"));
    this.provider.getFlowRepository().start(redirectToken("oidc", CLIENT), request(this.session, "oidc"));

    final UserAuthentication samlResult = new UserAuthentication(user());
    assertThat(this.controller.complete(request(this.session, "saml"), samlResult).getViewName())
        .isEqualTo("redirect:/authn/resume?authnId=saml");
    assertThat(this.controller.cancel(request(this.session, "oidc")).getViewName())
        .isEqualTo("redirect:/authn/resume?authnId=oidc");

    final ResumedAuthenticationToken samlResumed =
        this.provider.getFlowRepository().resume(request(this.session, "saml"));
    assertThat(samlResumed.getAuthnToken()).isSameAs(samlResult);
    assertThat(samlResumed.getAuthnInputToken().getRequester()).isEqualTo(SP);

    final ResumedAuthenticationToken oidcResumed =
        this.provider.getFlowRepository().resume(request(this.session, "oidc"));
    assertThat(oidcResumed.isError()).isTrue();
    assertThat(oidcResumed.getAuthnInputToken().getRequester()).isEqualTo(CLIENT);
  }

  @Test
  void completingAnAuthenticationThatIsNotInProgressIsAnInvalidSession() {
    final UserAuthentication result = new UserAuthentication(user());
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> this.controller.complete(request(this.session, "one"), result));
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> this.controller.cancel(request(this.session, null)));
  }

}
