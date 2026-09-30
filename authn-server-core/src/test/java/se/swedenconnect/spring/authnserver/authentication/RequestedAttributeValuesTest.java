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
package se.swedenconnect.spring.authnserver.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.IDENTITY_NUMBER;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.user;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Tests for {@link RequestedAttributeValues}.
 *
 * @author Martin Lindström
 */
class RequestedAttributeValuesTest {

  private static final String OTHER_NUMBER = "196911292032";

  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

  @BeforeEach
  void setUp() {
    this.appender.start();
    ((Logger) LoggerFactory.getLogger(RequestedAttributeValues.class)).addAppender(this.appender);
  }

  @AfterEach
  void tearDown() {
    ((Logger) LoggerFactory.getLogger(RequestedAttributeValues.class)).detachAppender(this.appender);
  }

  @Test
  void anEssentialValueThatDoesNotMatchIsUnknownPrincipal() {
    assertThatThrownBy(() -> check(pnr(true, OTHER_NUMBER)))
        .isInstanceOfSatisfying(AuthenticationErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(AuthenticationError.UNKNOWN_PRINCIPAL));
    assertLoggedWithoutValues();
  }

  @Test
  void aVoluntaryValueThatDoesNotMatchIsLoggedAndProceeds() {
    assertThatNoException().isThrownBy(() -> check(pnr(false, OTHER_NUMBER)));
    assertThat(this.appender.list).singleElement().satisfies(e -> {
      assertThat(e.getLevel()).isEqualTo(Level.INFO);
      assertThat(e.getFormattedMessage()).contains("voluntary");
    });
    assertLoggedWithoutValues();
  }

  @Test
  void severalValuesFailOnlyWhenNoneMatches() {
    assertThatNoException().isThrownBy(() -> check(pnr(true, OTHER_NUMBER, IDENTITY_NUMBER)));
    assertThat(this.appender.list).isEmpty();
    assertThatThrownBy(() -> check(pnr(true, OTHER_NUMBER, "199001012385")))
        .isInstanceOf(AuthenticationErrorException.class);
  }

  @Test
  void anAttributeTheUserDoesNotHaveProceedsWhetherEssentialOrNot() {
    for (final boolean essential : List.of(true, false)) {
      assertThatNoException().isThrownBy(() -> check(new GenericRequestedAttribute(
          AttributeIdentifiers.EMAIL, essential, List.of("agda@example.com"), null)));
    }
    assertThat(this.appender.list).hasSize(2)
        .allSatisfy(e -> assertThat(e.getFormattedMessage()).contains("does not have it"));
    assertLoggedWithoutValues();
  }

  @Test
  void anEssentialAttributeWithVoluntaryValuesProceeds() {
    final GenericRequestedAttribute attribute = new GenericRequestedAttribute(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true, List.of(OTHER_NUMBER), false, null);
    assertThat(attribute.isEssential()).isTrue();
    assertThat(attribute.isRequestedValuesEssential()).isFalse();
    assertThatNoException().isThrownBy(() -> check(attribute));
  }

  @Test
  void attributesWithoutValuesAreNotChecked() {
    assertThatNoException().isThrownBy(
        () -> check(GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true)));
    assertThat(this.appender.list).isEmpty();
  }

  @Test
  void aPreviousAuthenticationIsContradictedByAnyMismatchButNotByAMissingAttribute() {
    assertThat(RequestedAttributeValues.contradicts(requirements(pnr(false, OTHER_NUMBER)), user())).isTrue();
    assertThat(RequestedAttributeValues.contradicts(requirements(pnr(true, OTHER_NUMBER, IDENTITY_NUMBER)), user()))
        .isFalse();
    assertThat(RequestedAttributeValues.contradicts(requirements(new GenericRequestedAttribute(
        AttributeIdentifiers.EMAIL, true, List.of("agda@example.com"), null)), user())).isFalse();
  }

  private void assertLoggedWithoutValues() {
    assertThat(this.appender.list).isNotEmpty().allSatisfy(e -> {
      assertThat(e.getFormattedMessage()).doesNotContain(OTHER_NUMBER).doesNotContain(IDENTITY_NUMBER)
          .doesNotContain("agda@example.com");
    });
  }

  private static void check(final GenericRequestedAttribute attribute) {
    RequestedAttributeValues.check(requirements(attribute), user(), "log-string");
  }

  private static AuthenticationRequirements requirements(final GenericRequestedAttribute attribute) {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setRequestedAttributes(List.of(attribute));
    return requirements;
  }

  private static GenericRequestedAttribute pnr(final boolean essential, final String... values) {
    return new GenericRequestedAttribute(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, essential, List.of(values),
        null);
  }

}
