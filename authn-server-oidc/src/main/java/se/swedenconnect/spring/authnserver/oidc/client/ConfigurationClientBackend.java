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
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

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

}
