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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.spring.authnserver.AuthenticationTestSupport;
import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link AbstractSubjectIdentifierGenerator}.
 *
 * @author Martin Lindström
 */
class AbstractSubjectIdentifierGeneratorTest {

  private static final String ISSUER = "https://idp.example.com";

  private static final String SP1 = "https://sp1.example.com";

  private static final String SP2 = "https://sp2.example.com";

  private static final byte[] SECRET = "the-server-secret".getBytes(StandardCharsets.UTF_8);

  private static final AuthenticatedUser USER = AuthenticationTestSupport.user();

  private static final Requester REQUESTER = AuthenticationTestSupport.samlRequester(SP1);

  /** A generator that only brings in the computation of the base class. */
  private static class TestGenerator extends AbstractSubjectIdentifierGenerator {

    @Serial
    private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

    TestGenerator(final String issuerQualifier, final String requesterQualifier) {
      super(issuerQualifier, requesterQualifier);
    }
  }

  private static TestGenerator generator(final String requesterQualifier) {
    return new TestGenerator(ISSUER, requesterQualifier);
  }

  private static TestGenerator generator(final String requesterQualifier, final byte[] secret) {
    final TestGenerator generator = generator(requesterQualifier);
    generator.setSecret(secret);
    return generator;
  }

  @Test
  void theIdentifierIsStable() {
    final String first = generator(SP1).getSubjectIdentifier(USER, REQUESTER);
    final String second = generator(SP1).getSubjectIdentifier(USER, REQUESTER);
    assertThat(first).isNotEmpty().isEqualTo(second);
  }

  @Test
  void theIdentifierDoesNotRevealTheUserId() {
    final String identifier = generator(SP1).getSubjectIdentifier(USER, REQUESTER);
    assertThat(identifier).doesNotContain(AuthenticationTestSupport.IDENTITY_NUMBER);
    assertThat(new String(Base64.getDecoder().decode(identifier), StandardCharsets.ISO_8859_1))
        .doesNotContain(AuthenticationTestSupport.IDENTITY_NUMBER);
  }

  @Test
  void theRequesterQualifierChangesTheIdentifier() {
    assertThat(generator(SP1).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP2).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void withoutARequesterQualifierTheIdentifierIsTheSameForAllRequesters() {
    assertThat(generator(null).getSubjectIdentifier(USER, AuthenticationTestSupport.samlRequester(SP1)))
        .isEqualTo(generator(null).getSubjectIdentifier(USER, AuthenticationTestSupport.samlRequester(SP2)));
  }

  @Test
  void theIssuerQualifierChangesTheIdentifier() {
    assertThat(new TestGenerator(ISSUER, SP1).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(new TestGenerator("https://other-idp.example.com", SP1).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theUserChangesTheIdentifier() {
    final AuthenticatedUser other = Mockito.mock(AuthenticatedUser.class);
    Mockito.when(other.getUsername()).thenReturn("198906121234");
    assertThat(generator(SP1).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP1).getSubjectIdentifier(other, REQUESTER));
  }

  @Test
  void theSecretChangesTheIdentifier() {
    final String withoutSecret = generator(SP1).getSubjectIdentifier(USER, REQUESTER);
    final String withSecret = generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER);
    assertThat(withSecret).isNotEqualTo(withoutSecret);
  }

  @Test
  void withASecretTheIdentifierIsStable() {
    assertThat(generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void twoSecretsGiveTwoIdentifiers() {
    assertThat(generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP1, "another-secret".getBytes(StandardCharsets.UTF_8))
            .getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void withASecretTheRequesterQualifierStillChangesTheIdentifier() {
    assertThat(generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP2, SECRET).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void withASecretTheIdentifierDoesNotRevealTheUserId() {
    final String identifier = generator(SP1, SECRET).getSubjectIdentifier(USER, REQUESTER);
    assertThat(identifier).doesNotContain(AuthenticationTestSupport.IDENTITY_NUMBER);
  }

  @Test
  void clearingTheSecretRestoresThePlainHash() {
    final TestGenerator generator = generator(SP1, SECRET);
    generator.setSecret(null);
    assertThat(generator.getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(generator(SP1).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theSecretIsCopied() {
    final byte[] secret = SECRET.clone();
    final TestGenerator generator = generator(SP1, secret);
    final String before = generator.getSubjectIdentifier(USER, REQUESTER);
    Arrays.fill(secret, (byte) 0);
    assertThat(generator.getSubjectIdentifier(USER, REQUESTER)).isEqualTo(before);
  }

  @Test
  void theHashAlgorithmChangesTheIdentifier() {
    final TestGenerator generator = generator(SP1);
    generator.setHashAlgorithm("SHA-512");
    assertThat(generator.getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP1).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theHashAlgorithmIsUsedForTheMacToo() {
    final TestGenerator generator = generator(SP1, SECRET);
    generator.setHashAlgorithm("SHA-512");
    final String identifier = generator.getSubjectIdentifier(USER, REQUESTER);
    assertThat(Base64.getDecoder().decode(identifier)).hasSize(64);
  }

  @Test
  void aGeneratorSurvivesSerialization() throws Exception {
    final TestGenerator generator = generator(SP1, SECRET);
    final String expected = generator.getSubjectIdentifier(USER, REQUESTER);
    assertThat(SerializationTestSupport.roundTrip(generator).getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(expected);
  }

  @Test
  void anUnknownHashAlgorithmIsAnInternalError() {
    final TestGenerator generator = generator(SP1);
    generator.setHashAlgorithm("NoSuchHash");
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> generator.getSubjectIdentifier(USER, REQUESTER))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INTERNAL));
  }

  @Test
  void aMissingUserIdIsAnInternalError() {
    final AuthenticatedUser user = Mockito.mock(AuthenticatedUser.class);
    Mockito.when(user.getUsername()).thenReturn("");
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> generator(SP1).getSubjectIdentifier(user, REQUESTER))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INTERNAL));
  }

  @Test
  void theIssuerQualifierIsRequired() {
    assertThatIllegalArgumentException().isThrownBy(() -> new TestGenerator(null, SP1));
    assertThatIllegalArgumentException().isThrownBy(() -> new TestGenerator(" ", SP1));
  }

  @Test
  void theHashAlgorithmMustBeSet() {
    final TestGenerator generator = generator(SP1);
    assertThatIllegalArgumentException().isThrownBy(() -> generator.setHashAlgorithm(" "));
  }

}
