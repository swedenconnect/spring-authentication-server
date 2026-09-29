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
package se.swedenconnect.spring.authnserver.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA2;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.authentication;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.oidcRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.samlRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Tests for the built-in {@link SsoVoter}s.
 *
 * @author Martin Lindström
 */
class SsoVoterTest {

  static final Requester SP = samlRequester("https://sp.example.com/sp");

  static final List<String> REQUESTED = List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);

  @Test
  void thePolicyVoterAllowsWhenThePolicyIsSatisfied() {
    final SsoPolicyVoter voter = new SsoPolicyVoter(SsoPolicy.defaultPolicy());
    assertThat(voter.vote(authentication(user(), SP, REQUESTED), new AuthenticationRequirements(), SP, List.of(LOA3)))
        .isEqualTo(SsoDecision.allow());
  }

  @Test
  void thePolicyVoterDeniesWhenSingleSignOnIsTurnedOff() {
    final SsoPolicyVoter voter = new SsoPolicyVoter(SsoPolicy.none());
    assertThat(voter.vote(authentication(user(), SP, REQUESTED), new AuthenticationRequirements(), SP, List.of(LOA3))
        .reason()).isEqualTo(SsoDenialReason.NOT_ALLOWED);
  }

  @Test
  void thePolicyVoterDeniesAnAuthenticationThatIsTooOld() {
    final UserAuthentication old =
        authentication(user(LOA3, Instant.now().minus(Duration.ofMinutes(61))), SP, REQUESTED);
    final SsoPolicyVoter voter = new SsoPolicyVoter(SsoPolicy.defaultPolicy());
    assertThat(voter.vote(old, new AuthenticationRequirements(), SP, List.of(LOA3)).reason())
        .isEqualTo(SsoDenialReason.TIME_LIMIT_EXCEEDED);
  }

  @Test
  void thePolicyVoterHasNoTimeLimitForTheSessionLifetimePolicy() {
    final UserAuthentication old = authentication(user(LOA3, Instant.now().minus(Duration.ofDays(2))), SP, REQUESTED);
    final SsoPolicyVoter voter = new SsoPolicyVoter(SsoPolicy.forSessionLifetime());
    assertThat(voter.vote(old, new AuthenticationRequirements(), SP, List.of(LOA3)).isAllowed()).isTrue();
  }

  @Test
  void thePolicyVoterDeniesAnotherRequesterWhenTheSameRequesterIsRequired() {
    final UserAuthentication authentication = authentication(user(), SP, REQUESTED);
    final SsoPolicyVoter voter = new SsoPolicyVoter(SsoPolicy.defaultPolicy());

    assertThat(voter.vote(authentication, new AuthenticationRequirements(),
        samlRequester("https://other.example.com/sp"), List.of(LOA3)).reason())
            .isEqualTo(SsoDenialReason.OTHER_REQUESTER);
    assertThat(voter.vote(authentication, new AuthenticationRequirements(),
        oidcRequester("https://sp.example.com/sp"), List.of(LOA3)).reason())
            .isEqualTo(SsoDenialReason.OTHER_REQUESTER);
  }

  @Test
  void anotherRequesterIsAllowedWhenTheRuleIsTurnedOff() {
    final SsoPolicy policy = SsoPolicy.defaultPolicy();
    policy.setSameRequesterRequired(false);
    final SsoPolicyVoter voter = new SsoPolicyVoter(policy);
    assertThat(voter.vote(authentication(user(), SP, REQUESTED), new AuthenticationRequirements(),
        oidcRequester("client-1"), List.of(LOA3)).isAllowed()).isTrue();
  }

  @Test
  void thePolicyVoterReadsThePolicyForEveryRequest() {
    final SsoPolicy[] policy = { SsoPolicy.defaultPolicy() };
    final SsoPolicyVoter voter = new SsoPolicyVoter(() -> policy[0]);
    final UserAuthentication authentication = authentication(user(), SP, REQUESTED);

    assertThat(voter.vote(authentication, new AuthenticationRequirements(), SP, List.of(LOA3)).isAllowed()).isTrue();
    policy[0] = SsoPolicy.none();
    assertThat(voter.vote(authentication, new AuthenticationRequirements(), SP, List.of(LOA3)).isDenied()).isTrue();
  }

  @Test
  void theAuthnContextVoterRequiresTheSameAuthenticationContext() {
    final AuthnContextSsoVoter voter = new AuthnContextSsoVoter();
    final UserAuthentication authentication = authentication(user(), SP, REQUESTED);

    assertThat(voter.vote(authentication, new AuthenticationRequirements(), SP, List.of(LOA2, LOA3)).isAllowed())
        .isTrue();
    assertThat(voter.vote(authentication, new AuthenticationRequirements(), SP, List.of(LOA2)).reason())
        .isEqualTo(SsoDenialReason.OTHER_AUTHN_CONTEXT);
  }

  @Test
  void theRequestedAttributesVoterDeniesAnotherSetOfAttributes() {
    final RequestedAttributesSsoVoter voter = new RequestedAttributesSsoVoter();
    final UserAuthentication authentication = authentication(user(), SP, REQUESTED);

    final AuthenticationRequirements same = new AuthenticationRequirements();
    same.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    assertThat(voter.vote(authentication, same, SP, List.of(LOA3))).isEqualTo(SsoDecision.abstain());

    final AuthenticationRequirements more = new AuthenticationRequirements();
    more.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER),
        GenericRequestedAttribute.of(AttributeIdentifiers.EMAIL)));
    assertThat(voter.vote(authentication, more, SP, List.of(LOA3)).reason())
        .isEqualTo(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES);
  }

  @Test
  void theOrderOfTheRequestedAttributesDoesNotMatter() {
    final RequestedAttributesSsoVoter voter = new RequestedAttributesSsoVoter();
    final UserAuthentication authentication = authentication(user(), SP,
        List.of(AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME));

    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.GIVEN_NAME),
        GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME)));
    assertThat(voter.vote(authentication, requirements, SP, List.of(LOA3)).isDenied()).isFalse();
  }

  @Test
  void votersHaveNoOpinionAboutAResultThatHasNotBeenUsed() {
    final UserAuthentication unused = new UserAuthentication(user());
    assertThat(new RequestedAttributesSsoVoter()
        .vote(unused, new AuthenticationRequirements(), SP, List.of(LOA3))).isEqualTo(SsoDecision.abstain());
    assertThat(new SsoPolicyVoter(SsoPolicy.defaultPolicy())
        .vote(unused, new AuthenticationRequirements(), SP, List.of(LOA3)).isAllowed()).isTrue();
  }

}
