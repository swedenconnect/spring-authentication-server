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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A {@link ClientValidationStore} kept in the memory of one node.
 *
 * @author Martin Lindström
 */
public class InMemoryClientValidationStore implements ClientValidationStore {

  /** The outcomes, by source name and {@code client_id}. */
  private final Map<String, Map<String, ValidatedClient>> sources = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public @Nullable ValidatedClient get(final @NonNull String source, final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final Map<String, ValidatedClient> clients =
        this.sources.get(Objects.requireNonNull(source, "source must not be null"));
    return clients != null ? clients.get(clientId) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull String source, final @NonNull ValidatedClient client) {
    Objects.requireNonNull(client, "client must not be null");
    this.sources.computeIfAbsent(Objects.requireNonNull(source, "source must not be null"),
        s -> new ConcurrentHashMap<>()).put(client.clientId(), client);
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final @NonNull String source, final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final Map<String, ValidatedClient> clients =
        this.sources.get(Objects.requireNonNull(source, "source must not be null"));
    if (clients != null) {
      clients.remove(clientId);
    }
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<ValidatedClient> getAll(final @NonNull String source) {
    final Map<String, ValidatedClient> clients =
        this.sources.get(Objects.requireNonNull(source, "source must not be null"));
    return clients != null ? List.copyOf(clients.values()) : List.of();
  }

}
