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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A {@link FederationEntityStore} that keeps its entries in the memory of one node.
 *
 * @author Martin Lindström
 */
public class InMemoryFederationEntityStore implements FederationEntityStore {

  /** The entries, keyed by entity identifier. */
  private final Map<String, FederationEntityRecord> entries = new ConcurrentHashMap<>();

  /** The retained clients, keyed by {@code client_id}. */
  private final Map<String, RetainedClient> retained = new ConcurrentHashMap<>();

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /**
   * Default constructor using the system clock.
   */
  public InMemoryFederationEntityStore() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock to use
   */
  public InMemoryFederationEntityStore(final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable FederationEntityRecord get(final @NonNull String entityId) {
    Objects.requireNonNull(entityId, "entityId must not be null");
    final FederationEntityRecord record = this.entries.get(entityId);
    if (record == null) {
      return null;
    }
    if (record.isExpired(this.clock.instant())) {
      this.entries.remove(entityId, record);
      return null;
    }
    return record;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull FederationEntityRecord record) {
    Objects.requireNonNull(record, "record must not be null");
    this.entries.put(record.entityId(), record);
  }

  /** {@inheritDoc} */
  @Override
  public void purgeExpired() {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(r -> r.isExpired(now));
  }

  /**
   * Gets the number of entries that the store holds, expired entries that have not yet been dropped included.
   *
   * @return the number of entries
   */
  public int size() {
    return this.entries.size();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<RetainedClient> getRetainedClients() {
    return List.copyOf(this.retained.values());
  }

  /** {@inheritDoc} */
  @Override
  public void putRetainedClient(final @NonNull RetainedClient client) {
    Objects.requireNonNull(client, "client must not be null");
    this.retained.put(client.clientId(), client);
  }

  /** {@inheritDoc} */
  @Override
  public void removeRetainedClient(final @NonNull String clientId) {
    this.retained.remove(Objects.requireNonNull(clientId, "clientId must not be null"));
  }

}
