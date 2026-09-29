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

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;

/**
 * Tests for {@link SectorIdentifiers}.
 *
 * @author Martin Lindström
 */
class SectorIdentifiersTest {

  private static void assertConfigurationError(final URI sectorIdentifierUri, final List<URI> redirectUris) {
    assertThatExceptionOfType(UnrecoverableErrorException.class)
        .isThrownBy(() -> SectorIdentifiers.resolve(sectorIdentifierUri, redirectUris))
        .satisfies(e -> assertThat(e.getError())
            .isEqualTo(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION));
  }

  @Test
  void theHostOfTheSectorIdentifierUriIsUsed() {
    assertThat(SectorIdentifiers.resolve(URI.create("https://sector.example.com/uris.json"),
        List.of(URI.create("https://client.example.com/cb"))).getValue())
            .isEqualTo("sector.example.com");
  }

  @Test
  void theHostOfTheRedirectUriIsUsed() {
    assertThat(SectorIdentifiers.resolve(null, List.of(URI.create("https://client.example.com/cb"))).getValue())
        .isEqualTo("client.example.com");
  }

  @Test
  void severalRedirectUrisWithTheSameHostAreFine() {
    assertThat(SectorIdentifiers.resolve(null, List.of(
        URI.create("https://client.example.com/cb"),
        URI.create("https://client.example.com/other-cb"),
        URI.create("https://client.example.com:8443/cb"))).getValue())
            .isEqualTo("client.example.com");
  }

  @Test
  void redirectUrisWithSeveralHostsIsAConfigurationError() {
    assertConfigurationError(null, List.of(
        URI.create("https://client.example.com/cb"),
        URI.create("https://other.example.com/cb")));
  }

  @Test
  void noRedirectUriIsAConfigurationError() {
    assertConfigurationError(null, List.of());
    assertConfigurationError(null, null);
  }

  @Test
  void aRedirectUriWithoutAHostIsAConfigurationError() {
    assertConfigurationError(null, List.of(URI.create("myapp:/cb")));
  }

  @Test
  void aSectorIdentifierUriWithoutAHostIsAConfigurationError() {
    assertConfigurationError(URI.create("/uris.json"), List.of(URI.create("https://client.example.com/cb")));
  }

}
