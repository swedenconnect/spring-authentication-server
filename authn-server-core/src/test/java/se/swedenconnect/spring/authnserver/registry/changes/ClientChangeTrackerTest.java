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
package se.swedenconnect.spring.authnserver.registry.changes;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Tests for {@link ClientChangeTracker} and {@link InMemoryKnownClientStore}.
 *
 * @author Martin Lindström
 */
class ClientChangeTrackerTest {

  private static final String SOURCE_A = "https://md.example.com/a.xml";

  private static final String SOURCE_B = "https://md.example.com/b.xml";

  private final List<ApplicationEvent> events = new ArrayList<>();

  @Test
  void withoutAPreviousRecordEveryClientIsAddedOnce() {
    final ClientChangeTracker tracker = this.tracker(new InMemoryKnownClientStore());
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A), sp("two", SOURCE_A)));
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A), sp("two", SOURCE_A)));

    assertThat(this.added()).containsExactlyInAnyOrder("one", "two");
    assertThat(this.removed()).isEmpty();
  }

  @Test
  void aRefreshedSourceWithOneAddedAndOneRemovedGivesOneEventOfEach() {
    final ClientChangeTracker tracker = this.tracker(new InMemoryKnownClientStore());
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A), sp("two", SOURCE_A)));
    this.events.clear();

    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("two", SOURCE_A), sp("three", SOURCE_A)));

    assertThat(this.added()).containsExactly("three");
    assertThat(this.removed()).containsExactly("one");
    final ClientRemovedEvent removed = (ClientRemovedEvent) this.events.stream()
        .filter(ClientRemovedEvent.class::isInstance)
        .findFirst()
        .orElseThrow();
    assertThat(removed.getReason()).contains(SOURCE_A);
    assertThat(removed.getClient().source()).isEqualTo(SOURCE_A);
  }

  @Test
  void aClientThatMovesToAnotherSourceIsNotRemoved() {
    final InMemoryKnownClientStore store = new InMemoryKnownClientStore();
    final ClientChangeTracker tracker = this.tracker(store);
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A)));
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_B, List.of(sp("one", SOURCE_B)));
    this.events.clear();

    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of());

    assertThat(this.events).isEmpty();
    assertThat(store.getAll()).singleElement().extracting(KnownClient::source).isEqualTo(SOURCE_B);

    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_B, List.of());
    assertThat(this.removed()).containsExactly("one");
  }

  @Test
  void sourcesOfAnotherProtocolAreNotAffected() {
    final ClientChangeTracker tracker = this.tracker(new InMemoryKnownClientStore());
    tracker.sourceLoaded(AuthenticationProtocol.SAML, "configuration", List.of(sp("one", "configuration")));
    tracker.sourceLoaded(AuthenticationProtocol.OIDC, "configuration", List.of());

    assertThat(this.removed()).isEmpty();
  }

  @Test
  void seenAndRemovedClients() {
    final ClientChangeTracker tracker = this.tracker(new InMemoryKnownClientStore());
    final KnownClient rp = new KnownClient(new Requester(AuthenticationProtocol.OIDC, "https://rp.example.com"),
        "urn:glue:iso6523:0007:5566778899", "federation");
    tracker.clientSeen(rp);
    tracker.clientSeen(rp);
    tracker.clientRemoved(new Requester(AuthenticationProtocol.OIDC, "https://unknown.example.com"), "not found");
    tracker.clientRemoved(rp.requester(), "not found");
    tracker.clientRemoved(rp.requester(), "not found");
    tracker.clientsSeen(List.of());

    assertThat(this.added()).containsExactly("https://rp.example.com");
    assertThat(this.removed()).containsExactly("https://rp.example.com");
    assertThat(((ClientAddedEvent) this.events.get(0)).getClient().organizationNumber())
        .isEqualTo("urn:glue:iso6523:0007:5566778899");
  }

  @Test
  void eventsAreHeldUntilTheTrackerIsStarted() {
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A)));
    assertThat(this.events).isEmpty();
    assertThat(tracker.isRunning()).isFalse();

    tracker.start();
    assertThat(tracker.isRunning()).isTrue();
    assertThat(this.added()).containsExactly("one");

    tracker.clientRemoved(new Requester(AuthenticationProtocol.SAML, "one"), "gone");
    assertThat(this.removed()).containsExactly("one");

    tracker.stop();
    assertThat(tracker.isRunning()).isFalse();
  }

  @Test
  void withoutAPublisherNothingIsPublished() {
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.start();
    tracker.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A)));
    assertThat(tracker.getStore().getAll()).hasSize(1);
  }

  @Test
  void theRecordInAFileSurvivesARestart(@TempDir final Path directory) {
    final Path file = directory.resolve("cache/known-clients.json");
    this.tracker(new InMemoryKnownClientStore(file))
        .sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A), sp("two", SOURCE_A)));
    assertThat(file).exists();
    this.events.clear();

    final ClientChangeTracker restarted = this.tracker(new InMemoryKnownClientStore(file));
    restarted.sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("two", SOURCE_A), sp("three", SOURCE_A)));

    assertThat(this.added()).containsExactly("three");
    assertThat(this.removed()).containsExactly("one");
  }

  @Test
  void anUnreadableFileGivesAFirstStart(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("known-clients.json");
    Files.writeString(file, "not json");
    final InMemoryKnownClientStore store = new InMemoryKnownClientStore(file);
    assertThat(store.getAll()).isEmpty();

    this.tracker(store).sourceLoaded(AuthenticationProtocol.SAML, SOURCE_A, List.of(sp("one", SOURCE_A)));
    assertThat(this.added()).containsExactly("one");
    assertThat(new InMemoryKnownClientStore(file).getAll()).hasSize(1);
  }

  @Test
  void aFileThatCannotBeWrittenKeepsTheRecordInMemory(@TempDir final Path directory) throws Exception {
    final Path blocker = directory.resolve("blocker");
    Files.writeString(blocker, "a file, not a directory");
    final InMemoryKnownClientStore store = new InMemoryKnownClientStore(blocker.resolve("known-clients.json"));
    assertThat(store.addAll(List.of(sp("one", SOURCE_A)))).hasSize(1);
    assertThat(store.getAll()).hasSize(1);
  }

  @Test
  void theJsonFormRoundTrips() {
    final KnownClient client = new KnownClient(new Requester(AuthenticationProtocol.OIDC, "https://rp.example.com"),
        null, "federation");
    assertThat(KnownClientJson.read(KnownClientJson.write(client))).isEqualTo(client);
    assertThat(KnownClientJson.readAll(KnownClientJson.writeAll(List.of(client)))).containsExactly(client);
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

  private static KnownClient sp(final String id, final String source) {
    return new KnownClient(new Requester(AuthenticationProtocol.SAML, id), "556677-8899", source);
  }

}
