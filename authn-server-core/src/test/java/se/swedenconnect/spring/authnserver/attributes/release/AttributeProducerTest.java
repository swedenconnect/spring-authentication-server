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
package se.swedenconnect.spring.authnserver.attributes.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.SP;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.authentication;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.identifiers;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.requirements;

import java.time.Instant;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.AuthenticationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.sso.RequestedAttributesSsoVoter;

/**
 * Tests for {@link DefaultAttributeProducer} and {@link ReleaseAllAttributeProducer}.
 *
 * @author Martin Lindström
 */
class AttributeProducerTest {

  private final DefaultAttributeProducer defaultProducer = new DefaultAttributeProducer();

  private final ReleaseAllAttributeProducer releaseAllProducer = new ReleaseAllAttributeProducer();

  /** A provider reusing a previous authentication whenever it may. */
  private static class TestProvider extends AbstractUserAuthenticationProvider {

    @Override
    public @NonNull String getName() {
      return "test-provider";
    }

    @Override
    public @NonNull List<String> getSupportedAuthnContextUris() {
      return List.of(AuthenticationTestSupport.LOA3);
    }

    @Override
    protected @NonNull Authentication authenticate(final @NonNull UserAuthenticationInputToken token,
        final @NonNull List<String> authnContextUris) {
      return new UserAuthentication(
          AuthenticationTestSupport.user(authnContextUris.getFirst(), Instant.now()));
    }
  }

  @Test
  void theDefaultProducerReleasesWhatWasRequested() {
    final UserAuthentication authentication =
        authentication(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME);

    assertThat(identifiers(this.defaultProducer.releaseAttributes(authentication)))
        .containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME);
  }

  @Test
  void theDefaultProducerLeavesOutWhatWasNotRequested() {
    final UserAuthentication authentication = authentication(AttributeIdentifiers.SURNAME);

    assertThat(identifiers(this.defaultProducer.releaseAttributes(authentication)))
        .containsExactly(AttributeIdentifiers.SURNAME);
  }

  @Test
  void theDefaultProducerReleasesNothingWhenNothingWasRequested() {
    assertThat(this.defaultProducer.releaseAttributes(authentication())).isEmpty();
  }

  @Test
  void aRequestedAttributeThatTheUserDoesNotHaveIsNotReleased() {
    final UserAuthentication authentication =
        authentication(AttributeIdentifiers.SURNAME, AttributeIdentifiers.DATE_OF_BIRTH);

    assertThat(identifiers(this.defaultProducer.releaseAttributes(authentication)))
        .containsExactly(AttributeIdentifiers.SURNAME);
  }

  @Test
  void missingRequirementsIsAnInternalError() {
    final UserAuthentication authentication = authentication(AttributeIdentifiers.SURNAME);
    authentication.clearAuthnRequirements();

    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> this.defaultProducer.releaseAttributes(authentication))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INTERNAL));
  }

  @Test
  void theReleaseAllProducerReleasesEverything() {
    assertThat(identifiers(this.releaseAllProducer.releaseAttributes(authentication())))
        .containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME,
            AttributeIdentifiers.SURNAME);
  }

  @Test
  void theReleaseAllProducerNeedsNoRequirements() {
    final UserAuthentication authentication = authentication();
    authentication.clearAuthnRequirements();

    assertThat(this.releaseAllProducer.releaseAttributes(authentication)).isNotEmpty();
  }

  @Test
  void afterSsoTheReleaseFollowsTheNewRequest() {
    final TestProvider provider = new TestProvider();

    // A request asking for another set of attributes normally rules single sign-on out, so that voter is dropped
    // here to get a reused authentication answering a request that asks for something else.
    //
    provider.getSsoVoters().removeIf(RequestedAttributesSsoVoter.class::isInstance);

    // The first request asks for the personal identity number.
    //
    final UserAuthenticationInputToken first = new UserAuthenticationInputToken(
        withContext(requirements(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)), SP, "_first", null);
    final UserAuthentication authentication = (UserAuthentication) provider.authenticateUser(first);
    assertThat(authentication).isNotNull();
    assertThat(identifiers(this.defaultProducer.releaseAttributes(authentication)))
        .containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);

    // The second request, answered with the same authentication, asks for the name.
    //
    final UserAuthenticationInputToken second = new UserAuthenticationInputToken(
        withContext(requirements(AttributeIdentifiers.GIVEN_NAME, AttributeIdentifiers.SURNAME)), SP, "_second", null);
    second.setPreviousAuthentication(authentication);

    assertThat(provider.authenticateUser(second)).isSameAs(authentication);
    assertThat(authentication.isSsoApplied()).isTrue();
    assertThat(identifiers(this.defaultProducer.releaseAttributes(authentication)))
        .containsExactly(AttributeIdentifiers.GIVEN_NAME, AttributeIdentifiers.SURNAME);
  }

  private static se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements withContext(
      final se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements requirements) {
    requirements.setAuthnContextRequirements(List.of(AuthenticationTestSupport.LOA3));
    return requirements;
  }

}
