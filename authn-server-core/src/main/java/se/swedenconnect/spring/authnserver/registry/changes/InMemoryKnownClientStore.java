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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * A {@link KnownClientStore} that keeps the record in memory, and in a file when one is given, so that it survives a
 * restart.
 * <p>
 * The file is read when the store is created, and written after every change. A file that cannot be read is logged
 * and treated as missing, which makes the start behave as a first start.
 * </p>
 *
 * @author Martin Lindström
 */
public class InMemoryKnownClientStore implements KnownClientStore {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(InMemoryKnownClientStore.class);

  /** The record, keyed by requester. */
  private final Map<Requester, KnownClient> clients = new LinkedHashMap<>();

  /** The file where the record is kept, or {@code null}. */
  private final Path file;

  /**
   * Constructor for a store that is kept in memory only.
   */
  public InMemoryKnownClientStore() {
    this(null);
  }

  /**
   * Constructor.
   *
   * @param file the file where the record is kept, or {@code null} to keep it in memory only
   */
  public InMemoryKnownClientStore(final @Nullable Path file) {
    this.file = file;
    if (file != null && Files.isRegularFile(file)) {
      try {
        KnownClientJson.readAll(Files.readString(file, StandardCharsets.UTF_8))
            .forEach(c -> this.clients.put(c.requester(), c));
        log.debug("Read {} known clients from {}", this.clients.size(), file);
      }
      catch (final IOException | IllegalArgumentException e) {
        log.warn("The record of known clients in {} could not be read and is not used: {}", file, e.getMessage());
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized @NonNull List<KnownClient> addAll(final @NonNull Collection<KnownClient> clientsToAdd) {
    final List<KnownClient> added = new ArrayList<>();
    for (final KnownClient client : Objects.requireNonNull(clientsToAdd, "clientsToAdd must not be null")) {
      if (this.clients.putIfAbsent(client.requester(), client) == null) {
        added.add(client);
      }
    }
    if (!added.isEmpty()) {
      this.write();
    }
    return added;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized @NonNull List<KnownClient> removeAll(final @NonNull Collection<Requester> requesters) {
    final List<KnownClient> removed = new ArrayList<>();
    for (final Requester requester : Objects.requireNonNull(requesters, "requesters must not be null")) {
      final KnownClient client = this.clients.remove(requester);
      if (client != null) {
        removed.add(client);
      }
    }
    if (!removed.isEmpty()) {
      this.write();
    }
    return removed;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void update(final @NonNull KnownClient client) {
    Objects.requireNonNull(client, "client must not be null");
    if (!client.equals(this.clients.put(client.requester(), client))) {
      this.write();
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized @NonNull List<KnownClient> getAll() {
    return List.copyOf(this.clients.values());
  }

  /**
   * Writes the record to the file, if there is one. A failure is logged, and the record in memory is kept.
   */
  private void write() {
    if (this.file == null) {
      return;
    }
    try {
      final Path directory = this.file.toAbsolutePath().getParent();
      Files.createDirectories(directory);
      final Path temporary = Files.createTempFile(directory, "known-clients", ".tmp");
      Files.writeString(temporary, KnownClientJson.writeAll(this.clients.values()), StandardCharsets.UTF_8);
      Files.move(temporary, this.file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    catch (final IOException e) {
      log.warn("Failed to write the record of known clients to {}: {}", this.file, e.getMessage());
    }
  }

}
