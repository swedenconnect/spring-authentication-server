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
package se.swedenconnect.spring.authnserver.saml.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.nameid.DefaultNameIDGeneratorFactory;

/**
 * Tests for the subject identifier secret of {@link Saml2IdpConfigurer}.
 *
 * @author Martin Lindström
 */
class Saml2IdpSubjectIdentifierSecretTest extends OpenSamlTestBase {

  private static final String BASE_URL = "https://idp.example.com/auth";

  private static final byte[] SHARED = "shared".getBytes(StandardCharsets.UTF_8);

  private static final byte[] OWN = "saml".getBytes(StandardCharsets.UTF_8);

  @Test
  void withoutASecretStartupFails() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> init(new AuthnServerConfigurer(), saml()))
        .withMessageContaining("No subject identifier secret for SAML");
  }

  @Test
  void theSharedSecretOrTheSecretOfSamlIsUsed() {
    final Saml2IdpConfigurer shared = saml();
    init(new AuthnServerConfigurer().subjectIdentifierSecret(SHARED), shared);
    assertThat(shared.getSubjectIdentifierSecret()).isEqualTo(SHARED);
    assertThat(shared.getActiveNameIdGeneratorFactory()).isInstanceOf(DefaultNameIDGeneratorFactory.class);

    final Saml2IdpConfigurer own = saml().subjectIdentifierSecret(OWN);
    init(new AuthnServerConfigurer(), own);
    assertThat(own.getSubjectIdentifierSecret()).isEqualTo(OWN);
  }

  @Test
  void theSecretCanBeTurnedOffForSamlWithAWarning() {
    final Saml2IdpConfigurer saml = saml().subjectIdentifierSecret(OWN).subjectIdentifierSecretDisabled(true);
    assertThat(saml.isSubjectIdentifierSecretDisabled()).isTrue();

    final Logger logger = (Logger) LoggerFactory.getLogger(Saml2IdpConfigurer.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      init(new AuthnServerConfigurer().subjectIdentifierSecret(SHARED), saml);
    }
    finally {
      logger.detachAppender(appender);
    }

    // Neither the shared secret nor the secret of SAML is used
    assertThat(saml.getSubjectIdentifierSecret()).isNull();
    assertThat(appender.list)
        .filteredOn(e -> e.getLevel() == Level.WARN)
        .extracting(ILoggingEvent::getFormattedMessage)
        .singleElement()
        .satisfies(m -> assertThat(m).contains("turned off for SAML"));

    assertThat(saml().subjectIdentifierSecretDisabled(false).isSubjectIdentifierSecretDisabled()).isFalse();
  }

  @Test
  void anEmptySecretIsNotHowTheSecretIsTurnedOff() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> init(new AuthnServerConfigurer().subjectIdentifierSecret(SHARED),
            saml().subjectIdentifierSecret(new byte[0])))
        .withMessageContaining("subject identifier secret must not be empty");
  }

  @Test
  void aNameIdGeneratorFactoryOfTheApplicationNeedsNoSecret() {
    final DefaultNameIDGeneratorFactory factory = new DefaultNameIDGeneratorFactory("https://idp.example.com");
    final Saml2IdpConfigurer saml = saml().nameIdGeneratorFactory(factory);
    init(new AuthnServerConfigurer(), saml);
    assertThat(saml.getActiveNameIdGeneratorFactory()).isSameAs(factory);
  }

  private static Saml2IdpConfigurer saml() {
    return new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN);
  }

  private static void init(final AuthnServerConfigurer server, final Saml2IdpConfigurer saml) {
    server.baseUrl(BASE_URL).protocol(saml.metadataResolver(mock(MetadataResolver.class)))
        .init(mock(HttpSecurity.class));
  }

}
