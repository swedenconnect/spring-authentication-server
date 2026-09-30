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
package se.swedenconnect.spring.authnserver.oidc.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.DefaultClientRegistry;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link ConfigurationClientBackend}, {@link RepositoryClientBackend} and
 * {@link InMemoryClientRepository}, including the order in which the backends are asked.
 *
 * @author Martin Lindström
 */
class OidcClientBackendsTest {

  private static final String CLIENT_ID = "https://client.example.com";

  private static final String MARK = "https://example.com/mark";

  private static final String ORGANIZATION_IDENTIFIER = "urn:glue:iso6523:0007:5566778899";

  @Test
  void aConfiguredClientIsFound() {
    final ConfigurationClientBackend backend = new ConfigurationClientBackend(
        List.of(new OidcClientRecord(CLIENT_ID, metadata("Configured"), Set.of(MARK))));

    assertThat(backend.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(backend.getName()).isEqualTo(ConfigurationClientBackend.DEFAULT_NAME);

    final RequesterRecord record = backend.lookup(CLIENT_ID);
    assertThat(record).isNotNull();
    assertThat(record.getDisplayName(null)).isEqualTo("Configured");
    assertThat(record.marks()).containsExactly(MARK);
    assertThat(backend.lookup("https://other.example.com")).isNull();
  }

  @Test
  void aClientOfTheRepositoryIsFound() {
    final InMemoryClientRepository repository = new InMemoryClientRepository(
        List.of(OidcClientRecord.of(CLIENT_ID, metadata("Stored"))));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);

    assertThat(backend.getProtocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(backend.getName()).isEqualTo(RepositoryClientBackend.DEFAULT_NAME);
    assertThat(backend.lookup(CLIENT_ID)).isNotNull();
    assertThat(repository.findAll()).hasSize(1);

    repository.remove(CLIENT_ID);
    assertThat(backend.lookup(CLIENT_ID)).isNull();
    assertThat(repository.findByClientId(CLIENT_ID)).isNull();

    repository.save(OidcClientRecord.of(CLIENT_ID, metadata("Saved again")));
    assertThat(backend.lookup(CLIENT_ID)).isNotNull();
  }

  @Test
  void aRepositoryThatFailsIsNotAnUnknownClient() {
    final ClientRepository repository = clientId -> {
      throw new ClientRegistryException("the database could not be reached");
    };

    assertThatThrownBy(() -> new RepositoryClientBackend(repository).lookup(CLIENT_ID))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void theBackendsAreAskedInOrderAndTheFirstMatchWins() {
    final ConfigurationClientBackend configuration = new ConfigurationClientBackend(
        List.of(OidcClientRecord.of(CLIENT_ID, metadata("From configuration"))));
    final RepositoryClientBackend repository = new RepositoryClientBackend(new InMemoryClientRepository(
        List.of(OidcClientRecord.of(CLIENT_ID, metadata("From repository")),
            OidcClientRecord.of("https://stored.example.com", metadata("Only in the repository")))));
    final ClientRegistryBackend federation = new StubBackend("federation",
        OidcClientRecord.of("https://federated.example.com", metadata("Only in the federation")));

    final DefaultClientRegistry registry =
        new DefaultClientRegistry(List.of(configuration, repository, federation));

    assertThat(registry.lookup(AuthenticationProtocol.OIDC, CLIENT_ID).getDisplayName(null))
        .isEqualTo("From configuration");
    assertThat(registry.lookup(AuthenticationProtocol.OIDC, "https://stored.example.com").getDisplayName(null))
        .isEqualTo("Only in the repository");
    assertThat(registry.lookup(AuthenticationProtocol.OIDC, "https://federated.example.com").getDisplayName(null))
        .isEqualTo("Only in the federation");
    assertThat(registry.lookup(AuthenticationProtocol.OIDC, "https://unknown.example.com")).isNull();
  }

  @Test
  void askingForAMarkGivesTheRecordUnchangedForABackendThatCannotObtainMarks() {
    final ConfigurationClientBackend backend = new ConfigurationClientBackend(
        List.of(OidcClientRecord.of(CLIENT_ID, metadata("Configured"))));

    final RequesterRecord record = backend.requestMark(CLIENT_ID, MARK);

    assertThat(record).isNotNull();
    assertThat(record.marks()).isEmpty();
    assertThat(backend.requestMark("https://other.example.com", MARK)).isNull();
  }

  @Test
  void theOrganisationIdentifierComesFromTheClientMetadata() {
    final OIDCClientMetadata withIdentifier = metadata("Configured");
    withIdentifier.setCustomField(OidcClientRecord.ORGANIZATION_IDENTIFIER, ORGANIZATION_IDENTIFIER);

    final ConfigurationClientBackend configuration = new ConfigurationClientBackend(List.of(
        OidcClientRecord.of(CLIENT_ID, withIdentifier),
        OidcClientRecord.of("https://other.example.com", metadata("Other"))));
    assertThat(configuration.lookup(CLIENT_ID).organizationNumber()).isEqualTo(ORGANIZATION_IDENTIFIER);
    assertThat(configuration.lookup("https://other.example.com").organizationNumber()).isNull();

    final RepositoryClientBackend repository = new RepositoryClientBackend(new InMemoryClientRepository(List.of(
        OidcClientRecord.of(CLIENT_ID, withIdentifier),
        OidcClientRecord.of("https://other.example.com", metadata("Other")))));
    assertThat(repository.lookup(CLIENT_ID).organizationNumber()).isEqualTo(ORGANIZATION_IDENTIFIER);
    assertThat(repository.lookup("https://other.example.com").organizationNumber()).isNull();
  }

  @Test
  void theOrganisationIdentifierIsReadFromParsedMetadataAndKeptAsGiven() throws Exception {
    final OIDCClientMetadata parsed = OIDCClientMetadata.parse(JSONObjectUtils.parse(
        "{\"client_name\":\"Client\",\"organization_identifier\":\"urn:glue:iso6523:0007:5566778899\"}"));
    assertThat(OidcClientRecord.of(CLIENT_ID, parsed).toRequesterRecord().organizationNumber())
        .isEqualTo("urn:glue:iso6523:0007:5566778899");
  }

  @Test
  void anEmptyOrNonStringOrganisationIdentifierGivesNone() {
    final OIDCClientMetadata blank = metadata("Client");
    blank.setCustomField(OidcClientRecord.ORGANIZATION_IDENTIFIER, " ");
    assertThat(OidcClientRecord.of(CLIENT_ID, blank).toRequesterRecord().organizationNumber()).isNull();

    final OIDCClientMetadata number = metadata("Client");
    number.setCustomField(OidcClientRecord.ORGANIZATION_IDENTIFIER, 5566778899L);
    assertThat(OidcClientRecord.of(CLIENT_ID, number).toRequesterRecord().organizationNumber()).isNull();
  }

  private static OIDCClientMetadata metadata(final String name) {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setName(name);
    return metadata;
  }

  /**
   * A backend that knows one client.
   */
  private record StubBackend(String name, OidcClientRecord client) implements ClientRegistryBackend {

    @Override
    public @Nonnull String getName() {
      return this.name;
    }

    @Override
    public @Nonnull AuthenticationProtocol getProtocol() {
      return AuthenticationProtocol.OIDC;
    }

    @Override
    public @Nullable RequesterRecord lookup(final @Nonnull String identifier) {
      return this.client.clientId().equals(identifier) ? this.client.toRequesterRecord() : null;
    }

  }

}
