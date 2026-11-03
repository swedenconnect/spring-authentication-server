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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves the OpenID Connect clients of a {@link ClientRepository}.
 * <p>
 * The clients are validated by the {@link ClientValidation} that the OpenID Provider assigns: at startup if the
 * repository can list them, on the first lookup of a client, and when the metadata of a client differs from what was
 * validated. A lookup makes no network call unless the metadata has changed or a temporary mark has run out. A client
 * with a fault stays in the backend, marked as invalid, and is never authenticated. The author of a repository does
 * nothing for this.
 * </p>
 * <p>
 * A repository that cannot be read at startup does not stop the server. Its clients are then validated when they are
 * looked up.
 * </p>
 *
 * @author Martin Lindström
 */
public class RepositoryClientBackend implements ValidatingClientBackend {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RepositoryClientBackend.class);

  /** The default backend name. */
  public static final String DEFAULT_NAME = "repository";

  /** Where the clients are held. */
  private final ClientRepository repository;

  /** The backend name. */
  private final String name;

  /** Validates the clients, or {@code null} until the OpenID Provider has assigned it. */
  private volatile ClientValidation validation;

  /** Told when a client appears, disappears or is invalid, or {@code null}. */
  private volatile ClientChangeTracker tracker;

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

  /**
   * Assigns the validation and, if the repository can list its clients, forgets the outcomes of clients that it no
   * longer holds and validates every client. A repository that cannot be read is logged, and its clients are validated
   * when they are looked up.
   */
  @Override
  public void setClientValidation(final @NonNull ClientValidation validation) {
    Objects.requireNonNull(validation, "validation must not be null");
    validation.setClientChangeTracker(this.tracker);
    final List<OidcClientRecord> clients;
    try {
      clients = this.repository.findAll();
    }
    catch (final ClientRegistryException e) {
      this.validation = validation;
      log.error("The client repository of the source '{}' cannot be read - its clients are validated when they are "
          + "looked up: {}", this.name, e.getMessage(), e);
      return;
    }
    if (clients == null) {
      this.validation = validation;
      log.info("The client repository of the source '{}' cannot list its clients - they are validated when they are "
          + "looked up", this.name);
      return;
    }
    validation.retain(clients.stream().map(OidcClientRecord::clientId).toList());
    final long invalid = clients.stream()
        .map(validation::validate)
        .filter(v -> !v.isValid())
        .count();
    this.validation = validation;
    log.info("Validated the {} OpenID Connect client(s) of the source '{}' - {} invalid", clients.size(), this.name,
        invalid);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ClientValidation getClientValidation() {
    return this.validation;
  }

  /**
   * Keeps the validated clients up to date. When the repository can list its clients, every listed client is covered,
   * and the outcomes of clients that it no longer holds are forgotten. Otherwise, the clients that have been validated
   * are covered.
   */
  @Override
  public void refreshClients() {
    final ClientValidation current = this.validation;
    if (current == null) {
      return;
    }
    List<OidcClientRecord> clients;
    try {
      clients = this.repository.findAll();
    }
    catch (final ClientRegistryException e) {
      log.warn("The client repository of the source '{}' cannot be read - the clients that have been validated are "
          + "covered: {}", this.name, e.getMessage());
      clients = null;
    }
    if (clients != null) {
      current.retain(clients.stream().map(OidcClientRecord::clientId).toList());
      clients.forEach(current::refresh);
      return;
    }
    for (final String clientId : current.getValidatedClientIds()) {
      final OidcClientRecord client;
      try {
        client = this.repository.findByClientId(clientId);
      }
      catch (final ClientRegistryException e) {
        log.warn("The client '{}' cannot be read from the repository of the source '{}': {}", clientId, this.name,
            e.getMessage());
        continue;
      }
      if (client == null) {
        current.forget(clientId);
      }
      else {
        current.refresh(client);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final OidcClientRecord client = this.find(identifier);
    return client != null ? this.toRecord(client) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    final List<OidcClientRecord> clients = this.repository.findAll();
    if (clients == null) {
      return List.of();
    }
    return clients.stream()
        .map(c -> RegisteredClient.of(this.toRecord(c), this.name, null))
        .toList();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RegisteredClient getClient(final @NonNull String identifier) {
    final OidcClientRecord client = this.find(Objects.requireNonNull(identifier, "identifier must not be null"));
    return client != null ? RegisteredClient.of(this.toRecord(client), this.name, null) : null;
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
   * Gives the keys of a client of the repository: those of {@code jwks}, or else those held from its
   * {@code jwks_uri}, see {@link ClientValidation#resolveKeys(OidcClientRecord, JWKMatcher)}. A client that has been
   * validated is not read from the repository again, since the metadata is that of the record that was looked up. A
   * client of a backend without a validation holds no keys.
   */
  @Override
  public @Nullable List<JWK> resolveKeys(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    final ClientValidation current = this.validation;
    if (current != null && current.getStore().get(current.getSource(), clientId) != null) {
      return current.resolveKeys(OidcClientRecord.of(clientId, metadata), matcher);
    }
    final OidcClientRecord client = this.find(clientId);
    if (client == null) {
      return null;
    }
    return current != null ? current.resolveKeys(client, matcher) : List.of();
  }

  /**
   * Reports the clients of the repository to the tracker, if the repository can list them, and the clients found to
   * be invalid. A repository that cannot be read is logged.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    this.tracker = tracker;
    if (tracker != null) {
      try {
        final List<OidcClientRecord> clients = this.repository.findAll();
        if (clients != null) {
          tracker.sourceLoaded(AuthenticationProtocol.OIDC, this.name, clients.stream()
              .map(c -> KnownClient.of(c.toRequesterRecord(), this.name))
              .toList());
        }
      }
      catch (final ClientRegistryException e) {
        log.error("The client repository of the source '{}' cannot be read to report its clients: {}", this.name,
            e.getMessage(), e);
      }
    }
    final ClientValidation current = this.validation;
    if (current != null) {
      current.setClientChangeTracker(tracker);
    }
  }

  /**
   * Finds a client in the repository. The outcome of a client that the repository no longer holds is forgotten.
   *
   * @param clientId the {@code client_id} of the client
   * @return the client, or {@code null} if the repository does not hold it
   * @throws ClientRegistryException if the repository cannot be read
   */
  private @Nullable OidcClientRecord find(final @NonNull String clientId) throws ClientRegistryException {
    final OidcClientRecord client = this.repository.findByClientId(clientId);
    final ClientValidation current = this.validation;
    if (client == null && current != null && current.getStore().get(current.getSource(), clientId) != null) {
      current.forget(clientId);
    }
    return client;
  }

  /**
   * Creates the protocol-neutral record of a client, marked as invalid if the client is.
   *
   * @param client the client
   * @return a {@link RequesterRecord}
   */
  private @NonNull RequesterRecord toRecord(final @NonNull OidcClientRecord client) {
    final ClientValidation current = this.validation;
    return client.toRequesterRecord()
        .withInvalidReason(current != null ? current.get(client).invalidReason() : NOT_VALIDATED_REASON);
  }

}
