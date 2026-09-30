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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Where resolved clients are kept between requests.
 * <p>
 * The store is pluggable so that the nodes of a deployment can share it, for example through Redis. The library ships
 * an {@link InMemoryFederationCache}.
 * </p>
 * <p>
 * An entry that has expired is never handed out. An implementation may drop it when it is asked for, or leave that to
 * the store.
 * </p>
 *
 * @author Martin Lindström
 */
public interface FederationCache {

  /**
   * Gets the entry for a client.
   *
   * @param clientId the {@code client_id} of the client
   * @return a {@link CachedClientRecord}, or {@code null} if the cache holds no valid entry for the client
   */
  @Nullable CachedClientRecord get(final @NonNull String clientId);

  /**
   * Puts an entry in the cache, replacing any entry already held for the same client.
   *
   * @param record the entry
   */
  void put(final @NonNull CachedClientRecord record);

  /**
   * Removes the entry for a client.
   *
   * @param clientId the {@code client_id} of the client
   */
  void remove(final @NonNull String clientId);

}
