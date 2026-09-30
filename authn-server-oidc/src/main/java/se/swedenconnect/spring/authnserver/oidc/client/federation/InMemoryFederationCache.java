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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A {@link FederationCache} that keeps its entries in the memory of one node. It is the default, and it is what a
 * single node deployment needs.
 *
 * @author Martin Lindström
 */
public class InMemoryFederationCache implements FederationCache {

  /** The entries, keyed by {@code client_id}. */
  private final Map<String, CachedClientRecord> entries = new ConcurrentHashMap<>();

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /**
   * Default constructor using the system clock.
   */
  public InMemoryFederationCache() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock to use
   */
  public InMemoryFederationCache(final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable CachedClientRecord get(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final CachedClientRecord record = this.entries.get(clientId);
    if (record == null) {
      return null;
    }
    if (record.isExpired(this.clock.instant())) {
      this.entries.remove(clientId, record);
      return null;
    }
    return record;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull CachedClientRecord record) {
    Objects.requireNonNull(record, "record must not be null");
    this.entries.put(record.clientId(), record);
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final @NonNull String clientId) {
    this.entries.remove(Objects.requireNonNull(clientId, "clientId must not be null"));
  }

  /**
   * Removes every entry that has expired.
   */
  public void purgeExpired() {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(r -> r.isExpired(now));
  }

  /**
   * Gets the number of entries that the cache holds, expired entries that have not yet been dropped included.
   *
   * @return the number of entries
   */
  public int size() {
    return this.entries.size();
  }

}
