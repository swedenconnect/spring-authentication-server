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

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

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

}
