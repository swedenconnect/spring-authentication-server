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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.SmartLifecycle;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Keeps track of the clients that appear in and disappear from the client registry, and publishes a
 * {@link ClientAddedEvent} or a {@link ClientRemovedEvent} for each.
 * <p>
 * The backends of the registry report to the tracker: the full set of clients of a source, when it has been loaded or
 * refreshed, a single client that has been seen, or a client that its source no longer knows. The tracker compares
 * with the record of known clients in its {@link KnownClientStore}, so that the first report after a restart is
 * compared with the clients known before the restart. Without a previous record every client is reported as added.
 * </p>
 * <p>
 * The store decides which node publishes an event, so with a store shared by the nodes of a deployment each change
 * gives one event for the whole deployment.
 * </p>
 * <p>
 * Events are held until the tracker is started, so that the clients loaded while the application starts are reported
 * to listeners that are set up later. As a Spring bean the tracker is started when the application context has been
 * refreshed; otherwise call {@link #start()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientChangeTracker implements SmartLifecycle, ApplicationEventPublisherAware {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientChangeTracker.class);

  /** The record of known clients. */
  private final KnownClientStore store;

  /** The latest full set of clients of each source, by protocol and source name. Guarded by {@code this}. */
  private final Map<String, Set<String>> snapshots = new HashMap<>();

  /** Events waiting for the tracker to be started. Guarded by itself. */
  private final List<ApplicationEvent> pending = new ArrayList<>();

  /** Whether the tracker has been started. Guarded by {@link #pending}. */
  private boolean running = false;

  /** Publishes the events, or {@code null} if nothing is published. */
  private ApplicationEventPublisher eventPublisher;

  /**
   * Constructor.
   *
   * @param store the record of known clients
   */
  public ClientChangeTracker(final @NonNull KnownClientStore store) {
    this.store = Objects.requireNonNull(store, "store must not be null");
  }

  /**
   * Reports the full set of clients of a source, after it has been loaded or refreshed. A client that is not in the
   * record gives a {@link ClientAddedEvent}, and a client recorded for the source that the source no longer holds gives
   * a {@link ClientRemovedEvent}, unless another source of the same protocol holds it.
   *
   * @param protocol the protocol of the clients
   * @param source the name of the source
   * @param clients every client that the source holds
   */
  public synchronized void sourceLoaded(final @NonNull AuthenticationProtocol protocol, final @NonNull String source,
      final @NonNull Collection<KnownClient> clients) {
    Objects.requireNonNull(protocol, "protocol must not be null");
    Objects.requireNonNull(source, "source must not be null");
    final Set<String> identifiers = Objects.requireNonNull(clients, "clients must not be null").stream()
        .map(KnownClient::identifier)
        .collect(Collectors.toSet());
    this.snapshots.put(key(protocol, source), identifiers);

    final List<KnownClient> added = this.store.addAll(clients);

    final List<Requester> gone = new ArrayList<>();
    for (final KnownClient known : this.store.getAll()) {
      if (known.protocol() != protocol || !known.source().equals(source)
          || identifiers.contains(known.identifier())) {
        continue;
      }
      final String other = this.otherSource(protocol, source, known.identifier());
      if (other != null) {
        log.debug("The client '{}' is no longer in the source '{}', but is held by '{}'", known.identifier(), source,
            other);
        this.store.update(known.withSource(other));
      }
      else {
        gone.add(known.requester());
      }
    }
    final List<KnownClient> removed = this.store.removeAll(gone);

    final String reason = "no longer held by the source '%s'".formatted(source);
    added.forEach(this::added);
    removed.forEach(c -> this.removed(c, reason));
    if (!added.isEmpty() || !removed.isEmpty()) {
      log.info("Client registry source '{}' ({}) holds {} clients: {} added and {} removed", source, protocol,
          identifiers.size(), added.size(), removed.size());
    }
  }

  /**
   * Reports clients that have been seen, for example an OpenID Federation client that has been resolved. A client that
   * is not in the record gives a {@link ClientAddedEvent}.
   *
   * @param clients the clients
   */
  public void clientsSeen(final @NonNull Collection<KnownClient> clients) {
    if (Objects.requireNonNull(clients, "clients must not be null").isEmpty()) {
      return;
    }
    this.store.addAll(clients).forEach(this::added);
  }

  /**
   * Reports a client that has been seen. A client that is not in the record gives a {@link ClientAddedEvent}.
   *
   * @param client the client
   */
  public void clientSeen(final @NonNull KnownClient client) {
    this.clientsSeen(List.of(Objects.requireNonNull(client, "client must not be null")));
  }

  /**
   * Reports a client that its source no longer knows. A client that is in the record gives a
   * {@link ClientRemovedEvent}.
   *
   * @param requester the client
   * @param reason why the client was removed
   */
  public void clientRemoved(final @NonNull Requester requester, final @NonNull String reason) {
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(reason, "reason must not be null");
    this.store.removeAll(List.of(requester)).forEach(c -> this.removed(c, reason));
  }

  /**
   * Gets the record of known clients.
   *
   * @return the store
   */
  public @NonNull KnownClientStore getStore() {
    return this.store;
  }

  /**
   * Assigns the publisher of the events. Without a publisher, nothing is published.
   *
   * @param eventPublisher the event publisher, or {@code null}
   */
  @Override
  public void setApplicationEventPublisher(final @Nullable ApplicationEventPublisher eventPublisher) {
    this.eventPublisher = eventPublisher;
  }

  /**
   * Starts the tracker, publishing the events that have been held, and every event after that at once.
   */
  @Override
  public void start() {
    final List<ApplicationEvent> events;
    synchronized (this.pending) {
      this.running = true;
      events = List.copyOf(this.pending);
      this.pending.clear();
    }
    events.forEach(this::doPublish);
  }

  /**
   * Stops the tracker. Events are held again until it is started.
   */
  @Override
  public void stop() {
    synchronized (this.pending) {
      this.running = false;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRunning() {
    synchronized (this.pending) {
      return this.running;
    }
  }

  /**
   * Publishes the event of a client that was added.
   *
   * @param client the client
   */
  private void added(final @NonNull KnownClient client) {
    log.debug("Client '{}' ({}) added from '{}'", client.identifier(), client.protocol(), client.source());
    this.publish(new ClientAddedEvent(client));
  }

  /**
   * Publishes the event of a client that was removed.
   *
   * @param client the client
   * @param reason why it was removed
   */
  private void removed(final @NonNull KnownClient client, final @NonNull String reason) {
    log.debug("Client '{}' ({}) removed from '{}': {}", client.identifier(), client.protocol(), client.source(),
        reason);
    this.publish(new ClientRemovedEvent(client, reason));
  }

  /**
   * Publishes an event, or holds it until the tracker is started.
   *
   * @param event the event
   */
  private void publish(final @NonNull ApplicationEvent event) {
    synchronized (this.pending) {
      if (!this.running) {
        this.pending.add(event);
        return;
      }
    }
    this.doPublish(event);
  }

  /**
   * Publishes an event, if there is a publisher.
   *
   * @param event the event
   */
  private void doPublish(final @NonNull ApplicationEvent event) {
    if (this.eventPublisher != null) {
      this.eventPublisher.publishEvent(event);
    }
  }

  /**
   * Finds another source of the same protocol whose latest set of clients holds a client.
   *
   * @param protocol the protocol
   * @param source the source to leave out
   * @param identifier the identity of the client
   * @return the name of the other source, or {@code null} if there is none
   */
  private @Nullable String otherSource(final @NonNull AuthenticationProtocol protocol, final @NonNull String source,
      final @NonNull String identifier) {
    final String prefix = protocol.name() + ":";
    final String own = key(protocol, source);
    return this.snapshots.entrySet().stream()
        .filter(e -> e.getKey().startsWith(prefix) && !e.getKey().equals(own) && e.getValue().contains(identifier))
        .map(e -> e.getKey().substring(prefix.length()))
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the key of a source in the map of the latest sets of clients.
   *
   * @param protocol the protocol
   * @param source the source
   * @return the key
   */
  private static @NonNull String key(final @NonNull AuthenticationProtocol protocol, final @NonNull String source) {
    return protocol.name() + ":" + source;
  }

}
