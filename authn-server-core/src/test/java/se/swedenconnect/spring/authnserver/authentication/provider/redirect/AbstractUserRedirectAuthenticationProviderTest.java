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
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA2;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA4;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.authentication;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.AUTHN_PATH;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.RESUME_PATH;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.SP;
import static se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectTestSupport.redirectToken;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.List;
import java.util.Objects;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationUse;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.SwedenConnectPostAuthenticationProcessor;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;

/**
 * Tests for {@link AbstractUserRedirectAuthenticationProvider}.
 *
 * @author Martin Lindström
 */
class AbstractUserRedirectAuthenticationProviderTest {

  static final List<String> REQUESTED = List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);

  /** A redirect provider whose controller delivers the result as a {@link UserAuthentication}. */
  static class TestProvider extends AbstractUserRedirectAuthenticationProvider {

    TestProvider() {
      this(AUTHN_PATH, RESUME_PATH);
    }

    TestProvider(final String authnPath, final String resumeAuthnPath) {
      super(authnPath, resumeAuthnPath);
    }

    @Override
    public @Nonnull String getName() {
      return "test-redirect-provider";
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return List.of(LOA3, LOA4);
    }

    @Override
    public boolean supportsUserAuthenticationToken(final @Nullable Authentication authentication) {
      return authentication instanceof UserAuthentication;
    }

    @Override
    protected @Nonnull UserAuthentication createUserAuthentication(
        final @Nonnull ResumedAuthenticationToken token) {
      return (UserAuthentication) Objects.requireNonNull(token.getAuthnToken());
    }
  }

  static UserAuthenticationInputToken token(final AuthenticationRequirements requirements) {
    return new UserAuthenticationInputToken(requirements, SP, "_1a2b3c", "the-request");
  }

  static AuthenticationRequirements requirements(final String... authnContexts) {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setAuthnContextRequirements(List.of(authnContexts));
    requirements.setRequestedAttributes(
        List.of(GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    return requirements;
  }

  @Test
  void theProviderRedirectsInsteadOfAuthenticating() {
    final TestProvider provider = new TestProvider();
    final Authentication result = provider.authenticateUser(token(requirements(LOA4, LOA3)));

    assertThat(result).isInstanceOf(RedirectForAuthenticationToken.class);
    final RedirectForAuthenticationToken redirectToken = (RedirectForAuthenticationToken) result;
    assertThat(redirectToken.getAuthnId()).isNotBlank();
    assertThat(redirectToken.getAuthnContextUris()).containsExactly(LOA4, LOA3);
    assertThat(redirectToken.getAuthnPath()).isEqualTo(AUTHN_PATH);
    assertThat(redirectToken.getResumeAuthnPath()).isEqualTo(RESUME_PATH);
    assertThat(redirectToken.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(redirectToken.getRedirectPath()).startsWith(AUTHN_PATH + "?authnId=");
  }

  @Test
  void everyAuthenticationGetsAnIdentifierOfItsOwn() {
    final TestProvider provider = new TestProvider();
    final String first = ((RedirectForAuthenticationToken) Objects.requireNonNull(
        provider.authenticateUser(token(requirements(LOA3))))).getAuthnId();
    final String second = ((RedirectForAuthenticationToken) Objects.requireNonNull(
        provider.authenticateUser(token(requirements(LOA3))))).getAuthnId();

    assertThat(first).isNotEqualTo(second);
    assertThat(first).hasSizeGreaterThanOrEqualTo(32);
  }

  @Test
  void aProviderThatSupportsNoneOfTheRequestedContextsDoesNotRedirect() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.authenticateUser(token(requirements(LOA2)))).isNull();
  }

  @Test
  void aPreviousAuthenticationIsReusedWithoutARedirect() {
    final TestProvider provider = new TestProvider();
    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    final UserAuthenticationInputToken inputToken = token(requirements(LOA3));
    inputToken.setPreviousAuthentication(previous);

    assertThat(provider.authenticateUser(inputToken)).isSameAs(previous);
  }

  @Test
  void aPassiveRequestThatCannotBeAnsweredFailsWithoutARedirect() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setPassiveAuthn(true);

    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticateUser(token(requirements)))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.PASSIVE_NOT_POSSIBLE));
  }

  @Test
  void aResumedResultIsGivenTheRequirementsTheRequestDataAndItsUsageRecord() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    final UserAuthenticationInputToken inputToken = token(requirements);
    final RedirectForAuthenticationToken redirectToken = (RedirectForAuthenticationToken) Objects.requireNonNull(
        provider.authenticateUser(inputToken));

    final UserAuthentication result = new UserAuthentication(user());
    final UserAuthentication resumed =
        provider.resumeAuthentication(new ResumedAuthenticationToken(redirectToken, result));

    assertThat(resumed).isSameAs(result);
    assertThat(resumed.getAuthnRequirements()).isSameAs(requirements);
    assertThat(resumed.getProtocolRequestData()).isEqualTo("the-request");

    final AuthenticationUse original = resumed.getUsageTrack().getOriginalAuthentication();
    assertThat(original).isNotNull();
    assertThat(original.protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(original.requester()).isEqualTo(SP.identifier());
    assertThat(original.requestId()).isEqualTo("_1a2b3c");
    assertThat(original.requestedAttributes()).containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
  }

  @Test
  void resumingWithAnErrorThrowsIt() {
    final TestProvider provider = new TestProvider();
    final AuthenticationErrorException error = new AuthenticationErrorException(AuthenticationError.CANCEL);

    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.resumeAuthentication(
            new ResumedAuthenticationToken(redirectToken("abc123", SP), error)))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.CANCEL));
  }

  @Test
  void theResumedResultRunsThroughThePostAuthenticationProcessing() {
    final TestProvider provider = new TestProvider();
    provider.setServerPostAuthenticationProcessors(AuthenticationProtocol.SAML,
        List.of(new SwedenConnectPostAuthenticationProcessor()));
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setSignMessage(GenericSignMessage.ofText("sv", "Jag godkanner"));
    final RedirectForAuthenticationToken redirectToken =
        new RedirectForAuthenticationToken("abc123", token(requirements), List.of(LOA3), AUTHN_PATH, RESUME_PATH);

    final ResumedAuthenticationToken resumed =
        new ResumedAuthenticationToken(redirectToken, new UserAuthentication(user()));

    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.resumeAuthentication(resumed))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED));
  }

  @Test
  void theProviderTakesBothInputTokensAndResumedTokens() {
    final TestProvider provider = new TestProvider();

    assertThat(provider.supports(UserAuthenticationInputToken.class)).isTrue();
    assertThat(provider.supports(ResumedAuthenticationToken.class)).isTrue();
    assertThat(provider.supports(TestingAuthenticationToken.class)).isFalse();

    assertThat(provider.authenticate(token(requirements(LOA3))))
        .isInstanceOf(RedirectForAuthenticationToken.class);
    assertThat(provider.authenticate(new TestingAuthenticationToken("who", ""))).isNull();

    final UserAuthentication result = new UserAuthentication(user());
    assertThat(provider.authenticate(new ResumedAuthenticationToken(redirectToken("abc123", SP), result)))
        .isSameAs(result);
  }

  @Test
  void aResultThatTheProviderCanNotUseIsLeftToAnotherProvider() {
    final TestProvider provider = new TestProvider();
    final ResumedAuthenticationToken resumed = new ResumedAuthenticationToken(redirectToken("abc123", SP),
        new TestingAuthenticationToken("who", ""));

    assertThat(provider.authenticate(resumed)).isNull();
  }

  @Test
  void anErrorIsHandledWhicheverProviderResultTheControllerWouldHaveDelivered() {
    final TestProvider provider = new TestProvider();
    final ResumedAuthenticationToken resumed = new ResumedAuthenticationToken(redirectToken("abc123", SP),
        new AuthenticationErrorException(AuthenticationError.FRAUD));

    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticate(resumed))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.FRAUD));
  }

  @Test
  void theSessionBasedStorageIsTheDefaultAndCanBeReplaced() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.getFlowRepository()).isInstanceOf(SessionBasedRedirectAuthenticationRepository.class);
    assertThat(provider.getAuthenticatorRepository()).isSameAs(provider.getFlowRepository());

    final RedirectAuthenticationRepository other = new SessionBasedRedirectAuthenticationRepository();
    provider.setRepository(other);
    assertThat(provider.getFlowRepository()).isSameAs(other);
    assertThat(provider.getAuthenticatorRepository()).isSameAs(other);
  }

  @Test
  void thePathsAreChecked() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TestProvider("authn", RESUME_PATH));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TestProvider(AUTHN_PATH, null));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TestProvider(AUTHN_PATH, "/resume?x=1"));
    assertThat(new TestProvider(" /authn ", RESUME_PATH).getAuthnPath()).isEqualTo("/authn");
  }

}
