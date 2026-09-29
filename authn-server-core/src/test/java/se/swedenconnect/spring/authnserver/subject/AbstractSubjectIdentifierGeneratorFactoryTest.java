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
package se.swedenconnect.spring.authnserver.subject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.AuthenticationTestSupport;
import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Tests for {@link AbstractSubjectIdentifierGeneratorFactory}.
 *
 * @author Martin Lindström
 */
class AbstractSubjectIdentifierGeneratorFactoryTest {

  private static final String ISSUER = "https://idp.example.com";

  private static final AuthenticatedUser USER = AuthenticationTestSupport.user();

  private static final Requester REQUESTER = AuthenticationTestSupport.samlRequester("https://sp.example.com");

  /** A generator that only brings in the computation of the base class. */
  private static class TestGenerator extends AbstractSubjectIdentifierGenerator {

    @Serial
    private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

    TestGenerator(final String issuerQualifier) {
      super(issuerQualifier);
    }
  }

  /** A factory handing out {@link TestGenerator}s. */
  private static class TestFactory extends AbstractSubjectIdentifierGeneratorFactory {

    TestFactory(final String issuerQualifier) {
      super(issuerQualifier);
    }

    TestGenerator getGenerator() {
      return this.configure(new TestGenerator(this.getIssuerQualifier()));
    }
  }

  @Test
  void theSecretIsPassedToTheGenerator() {
    final TestFactory withoutSecret = new TestFactory(ISSUER);
    final TestFactory withSecret = new TestFactory(ISSUER);
    withSecret.setSecret("secret".getBytes(StandardCharsets.UTF_8));

    assertThat(withSecret.getGenerator().getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(withoutSecret.getGenerator().getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theHashAlgorithmIsPassedToTheGenerator() {
    final TestFactory factory = new TestFactory(ISSUER);
    factory.setHashAlgorithm("SHA-512");
    assertThat(Base64.getDecoder().decode(factory.getGenerator().getSubjectIdentifier(USER, REQUESTER)))
        .hasSize(64);
  }

  @Test
  void theIssuerQualifierIsRequired() {
    assertThatIllegalArgumentException().isThrownBy(() -> new TestFactory(null));
    assertThatIllegalArgumentException().isThrownBy(() -> new TestFactory(" "));
  }

  @Test
  void theHashAlgorithmMustBeSet() {
    final TestFactory factory = new TestFactory(ISSUER);
    assertThatIllegalArgumentException().isThrownBy(() -> factory.setHashAlgorithm(null));
  }

}
