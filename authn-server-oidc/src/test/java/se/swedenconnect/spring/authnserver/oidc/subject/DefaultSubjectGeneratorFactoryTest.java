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
package se.swedenconnect.spring.authnserver.oidc.subject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static se.swedenconnect.spring.authnserver.oidc.subject.SubjectTestSupport.IDENTITY_NUMBER;
import static se.swedenconnect.spring.authnserver.oidc.subject.SubjectTestSupport.ISSUER;
import static se.swedenconnect.spring.authnserver.oidc.subject.SubjectTestSupport.SECRET;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.openid.connect.sdk.SubjectType;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;

/**
 * Tests for {@link DefaultSubjectGeneratorFactory}.
 *
 * @author Martin Lindström
 */
class DefaultSubjectGeneratorFactoryTest {

  private static final AuthenticatedUser USER = SubjectTestSupport.user();

  private static final Requester CLIENT1 = SubjectTestSupport.client("client-1");

  private static final Requester CLIENT2 = SubjectTestSupport.client("client-2");

  private static final List<URI> REDIRECT_URIS = List.of(URI.create("https://client.example.com/cb"));

  private static final List<URI> OTHER_REDIRECT_URIS = List.of(URI.create("https://other.example.com/cb"));

  private static DefaultSubjectGeneratorFactory factory() {
    return new DefaultSubjectGeneratorFactory(ISSUER);
  }

  private static DefaultSubjectGeneratorFactory factoryWithSecret() {
    final DefaultSubjectGeneratorFactory factory = factory();
    factory.setSecret(SECRET);
    return factory;
  }

  private static String sub(final DefaultSubjectGeneratorFactory factory, final SubjectType subjectType,
      final URI sectorIdentifierUri, final List<URI> redirectUris, final Requester client) {
    return factory.getSubjectGenerator(subjectType, sectorIdentifierUri, redirectUris)
        .getSubjectIdentifier(USER, client);
  }

  // ---- The subject type ----

  @Test
  void bothTypesAreSupported() {
    assertThat(factory().getSupportedSubjectTypes())
        .containsExactly(SubjectType.PUBLIC, SubjectType.PAIRWISE);
  }

  @Test
  void theDefaultTypeIsPublic() {
    assertThat(factory().getSubjectGenerator(null, null, REDIRECT_URIS).getSubjectType())
        .isEqualTo(SubjectType.PUBLIC);
  }

  @Test
  void theRegisteredTypeIsUsed() {
    assertThat(factory().getSubjectGenerator(SubjectType.PUBLIC, null, REDIRECT_URIS))
        .isInstanceOf(PublicSubjectGenerator.class);
    assertThat(factory().getSubjectGenerator(SubjectType.PAIRWISE, null, REDIRECT_URIS))
        .isInstanceOf(PairwiseSubjectGenerator.class)
        .extracting(SubjectGenerator::getSubjectType).isEqualTo(SubjectType.PAIRWISE);
  }

  @Test
  void anUnsupportedTypeIsAConfigurationError() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> factory.getSubjectGenerator(SubjectType.EPHEMERAL, null, REDIRECT_URIS))
        .satisfies(e -> assertThat(e.getError())
            .isEqualTo(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION));
  }

  @Test
  void theIssuerIsRequired() {
    assertThatIllegalArgumentException().isThrownBy(() -> new DefaultSubjectGeneratorFactory(null));
    assertThatIllegalArgumentException().isThrownBy(() -> new DefaultSubjectGeneratorFactory(" "));
  }

  // ---- public ----

  @Test
  void aPublicSubIsTheSameForAllClients() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThat(sub(factory, SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1))
        .isEqualTo(sub(factory, SubjectType.PUBLIC, null, OTHER_REDIRECT_URIS, CLIENT2));
  }

  @Test
  void aPublicSubIsStableAndDoesNotRevealTheUserId() {
    final DefaultSubjectGeneratorFactory factory = factory();
    final String sub = sub(factory, SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1);
    assertThat(sub)
        .isNotEmpty()
        .doesNotContain(IDENTITY_NUMBER)
        .isEqualTo(factory.getSubjectGenerator(SubjectType.PUBLIC, null, REDIRECT_URIS)
            .getSubjectIdentifier(SubjectTestSupport.user(), CLIENT1));
  }

  @Test
  void aPublicSubDiffersBetweenUsers() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThat(sub(factory, SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(factory.getSubjectGenerator(SubjectType.PUBLIC, null, REDIRECT_URIS)
            .getSubjectIdentifier(SubjectTestSupport.user("198906121234"), CLIENT1));
  }

  // ---- pairwise ----

  @Test
  void aPairwiseSubDiffersBetweenSectorIdentifiers() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThat(sub(factory, SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(sub(factory, SubjectType.PAIRWISE, null, OTHER_REDIRECT_URIS, CLIENT2));
  }

  @Test
  void aPairwiseSubIsTheSameForClientsThatShareASectorIdentifier() {
    final DefaultSubjectGeneratorFactory factory = factory();
    final URI sectorIdentifierUri = URI.create("https://sector.example.com/uris.json");
    assertThat(sub(factory, SubjectType.PAIRWISE, sectorIdentifierUri, REDIRECT_URIS, CLIENT1))
        .isEqualTo(sub(factory, SubjectType.PAIRWISE, sectorIdentifierUri, OTHER_REDIRECT_URIS, CLIENT2));
  }

  @Test
  void aPairwiseSubIsStableAndDoesNotRevealTheUserId() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThat(sub(factory, SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isNotEmpty()
        .doesNotContain(IDENTITY_NUMBER)
        .isEqualTo(sub(factory, SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1));
  }

  @Test
  void aPairwiseSubDiffersFromThePublicOne() {
    final DefaultSubjectGeneratorFactory factory = factory();
    assertThat(sub(factory, SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(sub(factory, SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1));
  }

  @Test
  void anAmbiguousSectorIdentifierIsAConfigurationError() {
    final DefaultSubjectGeneratorFactory factory = factory();
    final List<URI> redirectUris = List.of(
        URI.create("https://client.example.com/cb"),
        URI.create("https://other.example.com/cb"));
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> factory.getSubjectGenerator(SubjectType.PAIRWISE, null, redirectUris))
        .satisfies(e -> {
          assertThat(e.getError()).isEqualTo(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION);
          assertThat(e.getMessage()).contains("sector_identifier_uri");
        });
  }

  @Test
  void anAmbiguousSectorIdentifierDoesNotStopThePublicType() {
    final List<URI> redirectUris = List.of(
        URI.create("https://client.example.com/cb"),
        URI.create("https://other.example.com/cb"));
    assertThat(sub(factory(), SubjectType.PUBLIC, null, redirectUris, CLIENT1)).isNotEmpty();
  }

  @Test
  void theSectorIdentifierIsAvailableFromTheGenerator() {
    final PairwiseSubjectGenerator generator = (PairwiseSubjectGenerator) factory()
        .getSubjectGenerator(SubjectType.PAIRWISE, null, REDIRECT_URIS);
    assertThat(generator.getSectorId().getValue()).isEqualTo("client.example.com");
  }

  // ---- The server secret ----

  @Test
  void theSecretChangesThePublicSub() {
    assertThat(sub(factoryWithSecret(), SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(sub(factory(), SubjectType.PUBLIC, null, REDIRECT_URIS, CLIENT1));
  }

  @Test
  void theSecretChangesThePairwiseSub() {
    assertThat(sub(factoryWithSecret(), SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(sub(factory(), SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1));
  }

  @Test
  void withASecretTheSubIsStableAndDiffersBetweenSecrets() {
    final DefaultSubjectGeneratorFactory other = factory();
    other.setSecret("another-secret".getBytes(StandardCharsets.UTF_8));
    assertThat(sub(factoryWithSecret(), SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isEqualTo(sub(factoryWithSecret(), SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1))
        .isNotEqualTo(sub(other, SubjectType.PAIRWISE, null, REDIRECT_URIS, CLIENT1));
  }

  // ---- The Subject and serialization ----

  @Test
  void theSubjectCarriesTheIdentifier() {
    final SubjectGenerator generator = factory().getSubjectGenerator(SubjectType.PAIRWISE, null, REDIRECT_URIS);
    assertThat(generator.getSubject(USER, CLIENT1).getValue())
        .isEqualTo(generator.getSubjectIdentifier(USER, CLIENT1));
  }

  @Test
  void theGeneratorsSurviveSerialization() throws Exception {
    final DefaultSubjectGeneratorFactory factory = factoryWithSecret();
    for (final SubjectType type : factory.getSupportedSubjectTypes()) {
      final SubjectGenerator generator = factory.getSubjectGenerator(type, null, REDIRECT_URIS);
      final String expected = generator.getSubjectIdentifier(USER, CLIENT1);
      final SubjectGenerator restored = SubjectTestSupport.roundTrip(generator);
      assertThat(restored.getSubjectType()).isEqualTo(type);
      assertThat(restored.getSubjectIdentifier(USER, CLIENT1)).isEqualTo(expected);
    }
  }

}
