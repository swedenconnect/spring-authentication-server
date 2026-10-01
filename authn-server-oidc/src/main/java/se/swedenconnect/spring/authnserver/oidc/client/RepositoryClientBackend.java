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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves the OpenID Connect clients of a {@link ClientRepository}.
 *
 * @author Martin Lindström
 */
public class RepositoryClientBackend implements ClientRegistryBackend {

  /** The default backend name. */
  public static final String DEFAULT_NAME = "repository";

  /** Where the clients are held. */
  private final ClientRepository repository;

  /** The backend name. */
  private final String name;

  /**
   * Constructor.
   *
   * @param repository where the clients are held
   */
  public RepositoryClientBackend(final @NonNull ClientRepository repository) {
    this(repository, DEFAULT_NAME);
  }

  /**
   * Constructor.
   *
   * @param repository where the clients are held
   * @param name the backend name
   */
  public RepositoryClientBackend(final @NonNull ClientRepository repository, final @NonNull String name) {
    this.repository = Objects.requireNonNull(repository, "repository must not be null");
    this.name = Objects.requireNonNull(name, "name must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final OidcClientRecord client = this.repository.findByClientId(identifier);
    return client != null ? client.toRequesterRecord() : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    final List<OidcClientRecord> clients = this.repository.findAll();
    if (clients == null) {
      return List.of();
    }
    return clients.stream()
        .map(c -> RegisteredClient.of(c.toRequesterRecord(), this.name, null))
        .toList();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RegisteredClient getClient(final @NonNull String identifier) {
    final OidcClientRecord client =
        this.repository.findByClientId(Objects.requireNonNull(identifier, "identifier must not be null"));
    return client != null ? RegisteredClient.of(client.toRequesterRecord(), this.name, null) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable String getMetadata(final @NonNull String identifier) {
    final OidcClientRecord client =
        this.repository.findByClientId(Objects.requireNonNull(identifier, "identifier must not be null"));
    return client != null ? OidcClientRecord.toJson(client.metadata()) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<ClientSource> getSources() {
    final List<OidcClientRecord> clients = this.repository.findAll();
    return List.of(new ClientSource(AuthenticationProtocol.OIDC, this.name, clients != null ? clients.size() : null,
        null));
  }

  /**
   * Reports the clients of the repository to the tracker, if the repository can list them.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    if (tracker == null) {
      return;
    }
    final List<OidcClientRecord> clients = this.repository.findAll();
    if (clients != null) {
      tracker.sourceLoaded(AuthenticationProtocol.OIDC, this.name, clients.stream()
          .map(c -> KnownClient.of(c.toRequesterRecord(), this.name))
          .toList());
    }
  }

}
