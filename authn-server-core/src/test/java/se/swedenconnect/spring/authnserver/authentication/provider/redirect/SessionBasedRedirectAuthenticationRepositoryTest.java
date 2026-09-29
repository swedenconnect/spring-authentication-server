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

import java.time.Duration;
import java.time.Instant;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link SessionBasedRedirectAuthenticationRepository} and {@link RedirectAuthenticationState}.
 *
 * @author Martin Lindström
 */
class SessionBasedRedirectAuthenticationRepositoryTest {

  private final SessionBasedRedirectAuthenticationRepository repository =
      new SessionBasedRedirectAuthenticationRepository();

  @Test
  void anAuthenticationIsStartedCompletedAndResumed() {
    final MockHttpSession session = new MockHttpSession();
    final RedirectForAuthenticationToken redirectToken = redirectToken("one", SP);
    this.repository.start(redirectToken, request(session, "one"));

    final MockHttpServletRequest controllerRequest = request(session, "one");
    assertThat(this.repository.getInputToken(controllerRequest)).isSameAs(redirectToken);
    assertThat(this.repository.getProtocol(controllerRequest)).isEqualTo(AuthenticationProtocol.SAML);

    final UserAuthentication result = new UserAuthentication(user());
    this.repository.complete(result, controllerRequest);

    final MockHttpServletRequest resumeRequest = request(session, "one");
    final ResumedAuthenticationToken resumed = this.repository.resume(resumeRequest);
    assertThat(resumed.getAuthnId()).isEqualTo("one");
    assertThat(resumed.getAuthnToken()).isSameAs(result);
    assertThat(resumed.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(resumed.getServletRequest()).isSameAs(resumeRequest);
  }

  @Test
  void anErrorIsCarriedToTheResume() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", CLIENT), request(session, "one"));

    final AuthenticationErrorException error =
        new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "the reader was unplugged");
    this.repository.complete(error, request(session, "one"));

    final ResumedAuthenticationToken resumed = this.repository.resume(request(session, "one"));
    assertThat(resumed.isError()).isTrue();
    assertThat(resumed.getError()).isSameAs(error);
    assertThat(resumed.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
  }

  @Test
  void twoAuthenticationsInTheSameSessionDoNotAffectEachOther() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("saml", SP), request(session, "saml"));
    this.repository.start(redirectToken("oidc", CLIENT), request(session, "oidc"));

    assertThat(this.repository.getProtocol(request(session, "saml"))).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(this.repository.getProtocol(request(session, "oidc"))).isEqualTo(AuthenticationProtocol.OIDC);

    final UserAuthentication samlResult = new UserAuthentication(user());
    this.repository.complete(samlResult, request(session, "saml"));
    this.repository.complete(new AuthenticationErrorException(AuthenticationError.CANCEL), request(session, "oidc"));

    final ResumedAuthenticationToken samlResumed = this.repository.resume(request(session, "saml"));
    assertThat(samlResumed.getAuthnToken()).isSameAs(samlResult);
    assertThat(samlResumed.getAuthnInputToken().getRequester()).isEqualTo(SP);

    final ResumedAuthenticationToken oidcResumed = this.repository.resume(request(session, "oidc"));
    assertThat(oidcResumed.getError()).isNotNull();
    assertThat(oidcResumed.getError().getError()).isEqualTo(AuthenticationError.CANCEL);
    assertThat(oidcResumed.getAuthnInputToken().getRequester()).isEqualTo(CLIENT);
  }

  @Test
  void aMissingIdentifierIsAnInvalidSession() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));
    this.repository.complete(new UserAuthentication(user()), request(session, "one"));

    assertInvalidSession(() -> this.repository.resume(request(session, null)));
  }

  @Test
  void anUnknownIdentifierIsAnInvalidSession() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));

    assertInvalidSession(() -> this.repository.resume(request(session, "another")));
  }

  @Test
  void anAuthenticationWithoutAnOutcomeIsAnInvalidSession() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));

    assertInvalidSession(() -> this.repository.resume(request(session, "one")));
  }

  @Test
  void anAlreadyResumedAuthenticationIsAnInvalidSession() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));
    this.repository.complete(new UserAuthentication(user()), request(session, "one"));

    assertThat(this.repository.resume(request(session, "one"))).isNotNull();
    assertInvalidSession(() -> this.repository.resume(request(session, "one")));
  }

  @Test
  void anExpiredAuthenticationIsAnInvalidSession() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));
    this.repository.complete(new UserAuthentication(user()), request(session, "one"));

    expire(this.repository);
    assertThat(this.repository.getInputToken(request(session, "one"))).isNull();
    assertThat(this.repository.getProtocol(request(session, "one"))).isNull();
    assertInvalidSession(() -> this.repository.resume(request(session, "one")));
  }

  @Test
  void anAuthenticationWithoutASessionIsAnInvalidSession() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.setParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, "one");
    assertInvalidSession(() -> this.repository.resume(request));
  }

  @Test
  void expiredAuthenticationsAreRemovedWhenANewOneIsStarted() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("old", SP), request(session, "old"));

    expire(this.repository);
    this.repository.start(redirectToken("new", SP), request(session, "new"));

    assertThat(session.getAttribute(SessionBasedRedirectAuthenticationRepository.SESSION_KEY))
        .asInstanceOf(InstanceOfAssertFactories.MAP)
        .containsOnlyKeys("new");
  }

  @Test
  void anAuthenticationThatIsGivenUpIsCleared() {
    final MockHttpSession session = new MockHttpSession();
    this.repository.start(redirectToken("one", SP), request(session, "one"));
    this.repository.clear(request(session, "one"));

    assertThat(this.repository.getInputToken(request(session, "one"))).isNull();
    this.repository.clear(request(session, "one"));
    this.repository.clear(request(session, null));
  }

  @Test
  void completingAnAuthenticationThatIsNotInProgressIsARefusal() {
    final MockHttpSession session = new MockHttpSession();
    final UserAuthentication result = new UserAuthentication(user());

    assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(() -> this.repository.complete(result, request(session, "one")));
    assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(() -> this.repository.complete(result, request(session, null)));

    this.repository.start(redirectToken("one", SP), request(session, "one"));
    expire(this.repository);
    assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(() -> this.repository.complete(result, request(session, "one")));
  }

  @Test
  void theMaximumAgeDefaultsToThirtyMinutesAndMustBePositive() {
    assertThat(this.repository.getMaxAge()).isEqualTo(Duration.ofMinutes(30));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> this.repository.setMaxAge(Duration.ZERO));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> this.repository.setMaxAge(Duration.ofSeconds(-1)));
  }

  @Test
  void aStoredAuthenticationSurvivesSerialization() throws Exception {
    final RedirectAuthenticationState state =
        new RedirectAuthenticationState(redirectToken("one", SP), Instant.now());
    assertThat(state.isCompleted()).isFalse();
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(state::toResumedToken);

    state.complete(new UserAuthentication(user()));
    final RedirectAuthenticationState restored = SerializationTestSupport.roundTrip(state);

    assertThat(restored.getAuthnId()).isEqualTo("one");
    assertThat(restored.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(restored.getStarted()).isEqualTo(state.getStarted());
    assertThat(restored.isCompleted()).isTrue();
    assertThat(restored.getError()).isNull();
    assertThat(restored.toResumedToken().getAuthnToken()).isNotNull();
    assertThat(restored.getRedirectToken().getAuthnInputToken().getRequester()).isEqualTo(SP);
    assertThat(restored.toString()).contains("one");
  }

  @Test
  void anOutcomeReplacesAnEarlierOne() {
    final RedirectAuthenticationState state =
        new RedirectAuthenticationState(redirectToken("one", SP), Instant.now());

    state.complete(new UserAuthentication(user()));
    state.complete(new AuthenticationErrorException(AuthenticationError.CANCEL));
    assertThat(state.getResult()).isNull();
    assertThat(state.getError()).isNotNull();

    state.complete(new UserAuthentication(user()));
    assertThat(state.getResult()).isNotNull();
    assertThat(state.getError()).isNull();
  }

  /**
   * Makes every authentication that has already been started expire.
   *
   * @param repository the repository
   */
  private static void expire(final SessionBasedRedirectAuthenticationRepository repository) {
    repository.setMaxAge(Duration.ofMillis(1));
    try {
      Thread.sleep(5);
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static void assertInvalidSession(final ThrowingCallable callable) {
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(callable)
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INVALID_SESSION));
  }

}
