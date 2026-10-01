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

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * The record of the clients that the server knows, which the {@link ClientChangeTracker} compares new data with.
 * <p>
 * Adding and removing are the operations that decide whether an event is published, so they must be atomic: when the
 * nodes of a deployment share the store, exactly one node is told that a client was added or removed. The library
 * ships an {@link InMemoryKnownClientStore}, which may be kept in a file so that it survives a restart, and a
 * {@link se.swedenconnect.spring.authnserver.redis.RedisKnownClientStore}.
 * </p>
 *
 * @author Martin Lindström
 */
public interface KnownClientStore {

  /**
   * Adds the clients that are not already in the record.
   *
   * @param clients the clients
   * @return the clients that were added by this call
   */
  @NonNull List<KnownClient> addAll(final @NonNull Collection<KnownClient> clients);

  /**
   * Removes clients from the record.
   *
   * @param requesters the clients to remove
   * @return the entries that were removed by this call
   */
  @NonNull List<KnownClient> removeAll(final @NonNull Collection<Requester> requesters);

  /**
   * Replaces the entry of a client, without telling whether it was there before. Used when a client moves from one
   * source to another.
   *
   * @param client the client
   */
  void update(final @NonNull KnownClient client);

  /**
   * Gets every client in the record.
   *
   * @return the clients
   */
  @NonNull List<KnownClient> getAll();

}
