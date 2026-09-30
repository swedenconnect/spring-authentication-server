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
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.IDENTITY_NUMBER;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA2;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA4;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.authentication;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.oidcRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.samlRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import jakarta.annotation.Nonnull;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationUse;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.sso.SsoDecision;
import se.swedenconnect.spring.authnserver.sso.SsoDenialKind;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

/**
 * Tests for {@link AbstractUserAuthenticationProvider}.
 *
 * @author Martin Lindström
 */
class AbstractUserAuthenticationProviderTest {

  static final Requester SP = samlRequester("https://sp.example.com/sp");

  static final List<String> REQUESTED = List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);

  /** A provider that authenticates at the first acceptable context and counts its invocations. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    int authenticateCalls = 0;

    boolean displaySignMessage = false;

    @Override
    public @Nonnull String getName() {
      return "test-provider";
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return List.of(LOA3, LOA4);
    }

    @Override
    protected @Nonnull Authentication authenticate(final @Nonnull UserAuthenticationInputToken token,
        final @Nonnull List<String> authnContextUris) {
      this.authenticateCalls++;
      final UserAuthentication authentication =
          new UserAuthentication(user(authnContextUris.getFirst(), Instant.now()));
      if (this.displaySignMessage) {
        authentication.getAuthenticatedUser().setSignMessageDisplayed(true, "sv");
      }
      return authentication;
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
  void aProviderThatSupportsNoneOfTheRequestedContextsDoesNotHandleTheRequest() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.authenticateUser(token(requirements(LOA2)))).isNull();
    assertThat(provider.authenticateCalls).isZero();
  }

  @Test
  void theRequestersOrderOfPreferenceIsKept() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.authenticateUser(token(requirements(LOA4, LOA3))))
        .isInstanceOf(UserAuthentication.class)
        .satisfies(r -> assertThat(((UserAuthentication) r).getAuthenticatedUser().getAuthnContextUri())
            .isEqualTo(LOA4));
  }

  @Test
  void everySupportedContextAppliesWhenNoneIsRequested() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.authenticateUser(token(new AuthenticationRequirements())))
        .isInstanceOf(UserAuthentication.class)
        .satisfies(r -> assertThat(((UserAuthentication) r).getAuthenticatedUser().getAuthnContextUri())
            .isEqualTo(LOA3));
  }

  @Test
  void aNewAuthenticationGetsTheRequirementsTheRequestDataAndTheOriginalUsageRecord() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    final UserAuthentication result =
        Objects.requireNonNull((UserAuthentication) provider.authenticateUser(token(requirements)));

    assertThat(result.getAuthnRequirements()).isSameAs(requirements);
    assertThat(result.getProtocolRequestData()).isEqualTo("the-request");
    assertThat(result.isSsoApplied()).isFalse();

    final AuthenticationUse original = result.getUsageTrack().getOriginalAuthentication();
    assertThat(original).isNotNull();
    assertThat(original.protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(original.requester()).isEqualTo(SP.identifier());
    assertThat(original.requestId()).isEqualTo("_1a2b3c");
    assertThat(original.requestedAttributes()).containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
  }

  @Test
  void aPreviousAuthenticationIsReusedAndItsUseRecorded() {
    final TestProvider provider = new TestProvider();
    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    final UserAuthenticationInputToken token = token(requirements(LOA3));
    token.setPreviousAuthentication(previous);

    assertThat(provider.authenticateUser(token)).isSameAs(previous);
    assertThat(provider.authenticateCalls).isZero();
    assertThat(previous.isSsoApplied()).isTrue();
    assertThat(previous.getUsageTrack().size()).isEqualTo(2);
  }

  @Test
  void forceAuthenticationNeverReusesAnAuthentication() {
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setForceAuthn(true);
    assertThat(deniedFor(requirements, authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.FORCE_AUTHN);
  }

  @Test
  void aMaximumAuthenticationAgeOfZeroNeverReusesAnAuthentication() {
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setMaxAuthnAge(Duration.ZERO);
    assertThat(deniedFor(requirements, authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.FORCE_AUTHN);
  }

  @Test
  void anAuthenticationOlderThanTheRequestedMaximumAgeIsNotReused() {
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setMaxAuthnAge(Duration.ofMinutes(5));
    final UserAuthentication previous =
        authentication(user(LOA3, Instant.now().minus(Duration.ofMinutes(6))), SP, REQUESTED);
    assertThat(deniedFor(requirements, previous)).isEqualTo(SsoDenialReason.MAX_AUTHN_AGE_EXCEEDED);
  }

  @Test
  void anAuthenticationThatMayNotBeReusedIsNotReused() {
    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    previous.setReuseForSso(false);
    assertThat(deniedFor(requirements(LOA3), previous)).isEqualTo(SsoDenialReason.NOT_REUSABLE);
  }

  @Test
  void aDisplayedSignMessageMakesTheAuthenticationUnusableForSingleSignOn() {
    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    previous.getAuthenticatedUser().setSignMessageDisplayed(true, "sv");
    assertThat(deniedFor(requirements(LOA3), previous)).isEqualTo(SsoDenialReason.NOT_REUSABLE);
  }

  @Test
  void aRequestThatCarriesASignMessageNeverReusesAnAuthentication() {
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setSignMessage(GenericSignMessage.ofText("sv", "Jag godkanner"));
    assertThat(deniedFor(requirements, authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.SIGN_MESSAGE);
  }

  @Test
  void aRequestedAttributeValueThatDoesNotMatchTheUserNeverReusesAnAuthentication() {
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setRequestedAttributes(List.of(new GenericRequestedAttribute(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, false, List.of("199001011234"), null)));
    assertThat(deniedFor(requirements, authentication(user(), SP,
        List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)))).isEqualTo(SsoDenialReason.ATTRIBUTE_VALUE_MISMATCH);
  }

  @Test
  void aRequestedAttributeValueThatMatchesTheUserReusesTheAuthentication() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setRequestedAttributes(List.of(new GenericRequestedAttribute(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, false, List.of(IDENTITY_NUMBER), null)));
    final UserAuthentication previous =
        authentication(user(), SP, List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));
    final UserAuthenticationInputToken token = token(requirements);
    token.setPreviousAuthentication(previous);

    assertThat(provider.authenticateUser(token)).isSameAs(previous);
  }

  @Test
  void aRequestedValueForAnAttributeTheUserDoesNotHaveSaysNothing() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setRequestedAttributes(List.of(new GenericRequestedAttribute(
        AttributeIdentifiers.EMAIL, false, List.of("agda@example.com"), null)));
    final UserAuthentication previous = authentication(user(), SP, List.of(AttributeIdentifiers.EMAIL));
    final UserAuthenticationInputToken token = token(requirements);
    token.setPreviousAuthentication(previous);

    assertThat(provider.authenticateUser(token)).isSameAs(previous);
  }

  @Test
  void aPassiveRequestThatCannotBeAnsweredFromAPreviousAuthenticationFails() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setPassiveAuthn(true);

    final AuthenticationErrorException exception = assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticateUser(token(requirements)))
        .actual();
    assertThat(exception.getError()).isEqualTo(AuthenticationError.PASSIVE_NOT_POSSIBLE);
    assertThat(exception.getSsoDenialReason()).isEqualTo(SsoDenialReason.NO_PREVIOUS_AUTHENTICATION)
        .satisfies(reason -> assertThat(reason.getKind()).isEqualTo(SsoDenialKind.LOGIN_REQUIRED));
    assertThat(provider.authenticateCalls).isZero();
  }

  @Test
  void aPassiveRequestRefusedBecauseOfAnotherSetOfAttributesNeedsInteraction() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setPassiveAuthn(true);
    requirements.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER),
        GenericRequestedAttribute.of(AttributeIdentifiers.EMAIL)));
    final UserAuthenticationInputToken token = token(requirements);
    token.setPreviousAuthentication(authentication(user(), SP, REQUESTED));

    final AuthenticationErrorException exception = assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticateUser(token))
        .actual();
    assertThat(exception.getSsoDenialReason()).isEqualTo(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES)
        .satisfies(reason -> assertThat(reason.getKind()).isEqualTo(SsoDenialKind.INTERACTION_REQUIRED));
  }

  @Test
  void aPassiveRequestIsAnsweredFromAPreviousAuthenticationWhenItMayBeReused() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setPassiveAuthn(true);
    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    final UserAuthenticationInputToken token = token(requirements);
    token.setPreviousAuthentication(previous);

    assertThat(provider.authenticateUser(token)).isSameAs(previous);
  }

  @Test
  void aProviderPolicyTakesPrecedenceOverTheServerDefault() {
    final TestProvider provider = new TestProvider();
    provider.setServerSsoPolicy(SsoPolicy.none());
    assertThat(provider.getSsoPolicy().isEnabled()).isFalse();

    provider.setSsoPolicy(SsoPolicy.defaultPolicy());
    assertThat(provider.getSsoPolicy().isEnabled()).isTrue();

    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    final UserAuthenticationInputToken token = token(requirements(LOA3));
    token.setPreviousAuthentication(previous);
    assertThat(provider.authenticateUser(token)).isSameAs(previous);

    provider.setSsoPolicy(null);
    assertThat(provider.getSsoPolicy().isEnabled()).isFalse();
  }

  @Test
  void theProtocolPolicyWinsOverTheServerDefaultAndTheProviderPolicyWinsOverBoth() {
    final TestProvider provider = new TestProvider();
    provider.setServerSsoPolicy(SsoPolicy.none());
    provider.setServerSsoPolicy(AuthenticationProtocol.SAML, SsoPolicy.forSessionLifetime());

    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML).getTimeLimit()).isNull();
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.OIDC).isEnabled()).isFalse();

    final UserAuthentication previous = authentication(user(), SP, REQUESTED);
    final UserAuthenticationInputToken token = token(requirements(LOA3));
    token.setPreviousAuthentication(previous);
    assertThat(provider.authenticateUser(token)).isSameAs(previous);

    final SsoPolicy own = SsoPolicy.none();
    provider.setSsoPolicy(own);
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML)).isSameAs(own);
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.OIDC)).isSameAs(own);

    provider.setSsoPolicy(null);
    provider.setServerSsoPolicy(AuthenticationProtocol.SAML, null);
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML).isEnabled()).isFalse();
  }

  @Test
  void theServerDefaultAppliesWhenTheProviderHasNoPolicyOfItsOwn() {
    final TestProvider provider = new TestProvider();
    provider.setServerSsoPolicy(SsoPolicy.none());
    assertThat(deniedFor(provider, requirements(LOA3), authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.NOT_ALLOWED);
  }

  @Test
  void anAuthenticationForAnotherRequesterIsNotReusedByDefault() {
    final TestProvider provider = new TestProvider();
    final UserAuthentication previous = authentication(user(), oidcRequester("client-1"), REQUESTED);
    assertThat(deniedFor(provider, requirements(LOA3), previous)).isEqualTo(SsoDenialReason.OTHER_REQUESTER);
  }

  @Test
  void anAuthenticationUnderAnotherContextIsNotReused() {
    final TestProvider provider = new TestProvider();
    final UserAuthentication previous = authentication(user(LOA4, Instant.now()), SP, REQUESTED);
    assertThat(deniedFor(provider, requirements(LOA3), previous)).isEqualTo(SsoDenialReason.OTHER_AUTHN_CONTEXT);
  }

  @Test
  void singleSignOnNeedsAtLeastOneVoterToAllowIt() {
    final TestProvider provider = new TestProvider();
    provider.getSsoVoters().clear();
    provider.getSsoVoters().add((previous, requirements, requester, contexts) -> SsoDecision.abstain());

    assertThat(deniedFor(provider, requirements(LOA3), authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.NOT_ALLOWED);
  }

  @Test
  void anApplicationVoterCanRefuseSingleSignOn() {
    final TestProvider provider = new TestProvider();
    provider.getSsoVoters().add(
        (previous, requirements, requester, contexts) -> SsoDecision.deny(SsoDenialReason.NOT_ALLOWED));
    assertThat(deniedFor(provider, requirements(LOA3), authentication(user(), SP, REQUESTED)))
        .isEqualTo(SsoDenialReason.NOT_ALLOWED);
  }

  @Test
  void aSignMessageThatHadToBeShownButWasNotFailsTheRequest() {
    final TestProvider provider = new TestProvider();
    final AuthenticationRequirements requirements = requirements(LOA3);
    requirements.setSignMessage(GenericSignMessage.ofText("sv", "Jag godkanner"));

    final AuthenticationErrorException exception = assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticateUser(token(requirements)))
        .actual();
    assertThat(exception.getError()).isEqualTo(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED);

    provider.displaySignMessage = true;
    assertThat(provider.authenticateUser(token(requirements))).isNotNull();
  }

  @Test
  void applicationPostProcessingRunsOnTheResult() {
    final TestProvider provider = new TestProvider();
    provider.getPostAuthenticationProcessors().add(authentication -> {
      throw new AuthenticationErrorException(AuthenticationError.NOT_AUTHORIZED, "no");
    });
    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> provider.authenticateUser(token(requirements(LOA3))))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.NOT_AUTHORIZED));
  }

  @Test
  void theProviderPlugsIntoSpringSecurity() {
    final TestProvider provider = new TestProvider();
    assertThat(provider.supports(UserAuthenticationInputToken.class)).isTrue();
    assertThat(provider.supports(UserAuthentication.class)).isFalse();
    assertThat(provider.authenticate(token(requirements(LOA3)))).isInstanceOf(UserAuthentication.class);
    assertThat(provider.authenticate(new UserAuthentication(user()))).isNull();
    assertThat(provider.getName()).isEqualTo("test-provider");
  }

  private static SsoDenialReason deniedFor(final AuthenticationRequirements requirements,
      final UserAuthentication previous) {
    return deniedFor(new TestProvider(), requirements, previous);
  }

  private static SsoDenialReason deniedFor(final TestProvider provider,
      final AuthenticationRequirements requirements, final UserAuthentication previous) {
    final UserAuthenticationInputToken token = token(requirements);
    token.setPreviousAuthentication(previous);
    final SsoDecision decision = provider.decideSso(token, provider.filterRequestedAuthnContextUris(token));
    assertThat(decision.isDenied()).isTrue();
    return decision.reason();
  }

}
