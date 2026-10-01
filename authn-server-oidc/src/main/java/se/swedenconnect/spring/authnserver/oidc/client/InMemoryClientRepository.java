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
 * A {@link ClientRepository} that holds its clients in memory. Useful for tests and for deployments with a small and
 * fixed set of clients.
 *
 * @author Martin Lindström
 */
public class InMemoryClientRepository implements ClientRepository {

  /** The clients, keyed by {@code client_id}. */
  private final Map<String, OidcClientRecord> clients = new ConcurrentHashMap<>();

  /**
   * Default constructor creating an empty repository.
   */
  public InMemoryClientRepository() {
  }

  /**
   * Constructor creating a repository holding the supplied clients.
   *
   * @param clients the clients
   */
  public InMemoryClientRepository(final @NonNull Collection<OidcClientRecord> clients) {
    Objects.requireNonNull(clients, "clients must not be null").forEach(this::save);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable OidcClientRecord findByClientId(final @NonNull String clientId) {
    return this.clients.get(Objects.requireNonNull(clientId, "clientId must not be null"));
  }

  /**
   * Adds a client to the repository, replacing any client already registered with the same {@code client_id}.
   *
   * @param client the client
   */
  public void save(final @NonNull OidcClientRecord client) {
    Objects.requireNonNull(client, "client must not be null");
    this.clients.put(client.clientId(), client);
  }

  /**
   * Removes a client from the repository.
   *
   * @param clientId the {@code client_id} of the client
   */
  public void remove(final @NonNull String clientId) {
    this.clients.remove(Objects.requireNonNull(clientId, "clientId must not be null"));
  }

  /**
   * Gets all clients of the repository.
   *
   * @return the clients
   */
  @Override
  public @NonNull List<OidcClientRecord> findAll() {
    return List.copyOf(this.clients.values());
  }

}
