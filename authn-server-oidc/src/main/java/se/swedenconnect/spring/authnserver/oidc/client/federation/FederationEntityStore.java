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

import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Where the {@link FederationClientCollector} keeps what the resolver answered about each entity it visits, so that an
 * entity is not resolved again on every run, and the clients that are kept after the resolver stopped knowing them.
 * <p>
 * The store is separate from the {@link FederationCache}, which only holds clients. The library ships an
 * {@link InMemoryFederationEntityStore} and a {@link RedisFederationEntityStore}.
 * </p>
 *
 * @author Martin Lindström
 */
public interface FederationEntityStore {

  /**
   * Gets the entry for an entity.
   *
   * @param entityId the entity identifier
   * @return a {@link FederationEntityRecord}, or {@code null} if the store holds no valid entry for the entity
   */
  @Nullable FederationEntityRecord get(final @NonNull String entityId);

  /**
   * Puts an entry in the store, replacing any entry already held for the same entity.
   *
   * @param record the entry
   */
  void put(final @NonNull FederationEntityRecord record);

  /**
   * Removes the entries that have expired. The default does nothing, for a store that drops them by itself.
   */
  default void purgeExpired() {
  }

  /**
   * Gets the clients that are kept although the resolver no longer knows them.
   *
   * @return the retained clients
   */
  @NonNull Collection<RetainedClient> getRetainedClients();

  /**
   * Records a client that is kept although the resolver no longer knows it, replacing any record for the same client.
   *
   * @param client the retained client
   */
  void putRetainedClient(final @NonNull RetainedClient client);

  /**
   * Removes the record of a retained client.
   *
   * @param clientId the {@code client_id} of the client
   */
  void removeRetainedClient(final @NonNull String clientId);

}
