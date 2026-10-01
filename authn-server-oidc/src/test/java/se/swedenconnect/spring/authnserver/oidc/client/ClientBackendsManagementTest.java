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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientStore;

/**
 * Tests for the management methods of {@link ConfigurationClientBackend} and {@link RepositoryClientBackend}.
 *
 * @author Martin Lindström
 */
class ClientBackendsManagementTest {

  private static final String ONE = "https://one.example.com";

  private static final String TWO = "https://two.example.com";

  private final List<ApplicationEvent> events = new ArrayList<>();

  @Test
  void theConfiguredClientsAreListedShownAndReported() {
    final ConfigurationClientBackend backend =
        new ConfigurationClientBackend(List.of(client(ONE), client(TWO)));

    assertThat(backend.getClients()).extracting(c -> c.requester().identifier()).containsExactlyInAnyOrder(ONE, TWO);
    assertThat(backend.getClient(ONE)).isNotNull()
        .satisfies(c -> assertThat(c.source()).isEqualTo(ConfigurationClientBackend.DEFAULT_NAME))
        .satisfies(c -> assertThat(c.marks()).containsExactly("https://example.com/mark"))
        .satisfies(c -> assertThat(c.expiresAt()).isNull());
    assertThat(backend.getClient("https://unknown.example.com")).isNull();
    assertThat(backend.getMetadata(ONE)).contains("\"client_name\":\"Client\"").doesNotContain("the-secret");
    assertThat(backend.getMetadata("https://unknown.example.com")).isNull();
    assertThat(backend.getSources()).singleElement()
        .satisfies(s -> assertThat(s.clients()).isEqualTo(2))
        .satisfies(s -> assertThat(s.protocol()).isEqualTo(AuthenticationProtocol.OIDC));
    assertThat(backend.update(ONE).outcome()).isEqualTo(ClientUpdateResult.Outcome.NOTHING_TO_UPDATE);
    assertThat(backend.update().outcome()).isEqualTo(ClientUpdateResult.Outcome.NOTHING_TO_UPDATE);

    final KnownClientStore store = new InMemoryKnownClientStore();
    backend.setClientChangeTracker(this.tracker(store));
    assertThat(this.added()).containsExactlyInAnyOrder(ONE, TWO);
    this.events.clear();

    new ConfigurationClientBackend(List.of(client(TWO))).setClientChangeTracker(this.tracker(store));
    assertThat(this.removed()).containsExactly(ONE);
    backend.setClientChangeTracker(null);
  }

  @Test
  void theClientsOfARepositoryAreListedWhenItCanListThem() {
    final InMemoryClientRepository repository = new InMemoryClientRepository(List.of(client(ONE)));
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);

    assertThat(backend.getClients()).singleElement()
        .satisfies(c -> assertThat(c.source()).isEqualTo(RepositoryClientBackend.DEFAULT_NAME));
    assertThat(backend.getClient(ONE)).isNotNull();
    assertThat(backend.getClient(TWO)).isNull();
    assertThat(backend.getMetadata(ONE)).doesNotContain("the-secret");
    assertThat(backend.getMetadata(TWO)).isNull();
    assertThat(backend.getSources()).singleElement().satisfies(s -> assertThat(s.clients()).isEqualTo(1));

    backend.setClientChangeTracker(this.tracker(new InMemoryKnownClientStore()));
    assertThat(this.added()).containsExactly(ONE);
    backend.setClientChangeTracker(null);
  }

  @Test
  void aRepositoryThatCannotListItsClientsReportsNothing() {
    final ClientRepository repository = new ClientRepository() {
      @Override
      public @Nullable OidcClientRecord findByClientId(final @NonNull String clientId) {
        return ONE.equals(clientId) ? client(ONE) : null;
      }
    };
    final RepositoryClientBackend backend = new RepositoryClientBackend(repository);

    assertThat(backend.getClients()).isEmpty();
    assertThat(backend.getClient(ONE)).isNotNull();
    assertThat(backend.getSources()).singleElement().satisfies(s -> assertThat(s.clients()).isNull());
    backend.setClientChangeTracker(this.tracker(new InMemoryKnownClientStore()));
    assertThat(this.events).isEmpty();
  }

  private ClientChangeTracker tracker(final KnownClientStore store) {
    final ClientChangeTracker tracker = new ClientChangeTracker(store);
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.start();
    return tracker;
  }

  private List<String> added() {
    return this.events.stream()
        .filter(ClientAddedEvent.class::isInstance)
        .map(e -> ((ClientAddedEvent) e).getClient().identifier())
        .toList();
  }

  private List<String> removed() {
    return this.events.stream()
        .filter(ClientRemovedEvent.class::isInstance)
        .map(e -> ((ClientRemovedEvent) e).getClient().identifier())
        .toList();
  }

  private static OidcClientRecord client(final String clientId) {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setName("Client");
    metadata.setRedirectionURI(URI.create(clientId + "/callback"));
    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "the-secret");
    return new OidcClientRecord(clientId, metadata, Set.of("https://example.com/mark"));
  }

}
