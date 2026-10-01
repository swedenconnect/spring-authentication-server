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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves the OpenID Connect clients given in the configuration of the OpenID
 * Provider.
 *
 * @author Martin Lindström
 */
public class ConfigurationClientBackend implements ClientRegistryBackend {

  /** The default backend name. */
  public static final String DEFAULT_NAME = "configuration";

  /** The clients, keyed by {@code client_id}. */
  private final Map<String, OidcClientRecord> clients;

  /** The backend name. */
  private final String name;

  /**
   * Constructor.
   *
   * @param clients the configured clients
   */
  public ConfigurationClientBackend(final @NonNull Collection<OidcClientRecord> clients) {
    this(clients, DEFAULT_NAME);
  }

  /**
   * Constructor.
   *
   * @param clients the configured clients
   * @param name the backend name
   */
  public ConfigurationClientBackend(
      final @NonNull Collection<OidcClientRecord> clients, final @NonNull String name) {
    Objects.requireNonNull(clients, "clients must not be null");
    this.name = Objects.requireNonNull(name, "name must not be null");
    final Map<String, OidcClientRecord> map = new LinkedHashMap<>();
    clients.forEach(c -> map.put(c.clientId(), c));
    this.clients = Map.copyOf(map);
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
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final OidcClientRecord client = this.clients.get(identifier);
    return client != null ? client.toRequesterRecord() : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    return this.clients.values().stream()
        .map(c -> RegisteredClient.of(c.toRequesterRecord(), this.name, null))
        .toList();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable String getMetadata(final @NonNull String identifier) {
    final OidcClientRecord client = this.clients.get(Objects.requireNonNull(identifier, "identifier must not be null"));
    return client != null ? OidcClientRecord.toJson(client.metadata()) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<ClientSource> getSources() {
    return List.of(new ClientSource(AuthenticationProtocol.OIDC, this.name, this.clients.size(), null));
  }

  /**
   * Reports the configured clients to the tracker.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    if (tracker != null) {
      tracker.sourceLoaded(AuthenticationProtocol.OIDC, this.name, this.clients.values().stream()
          .map(c -> KnownClient.of(c.toRequesterRecord(), this.name))
          .toList());
    }
  }

}
