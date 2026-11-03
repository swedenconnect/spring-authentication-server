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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves the OpenID Connect clients given in the configuration of the OpenID
 * Provider.
 * <p>
 * The clients are validated when the OpenID Provider assigns the {@link ClientValidation}, which it does at startup. A
 * client with a fault stays in the backend, marked as invalid, and is never authenticated. A client whose keys could
 * not be read is validated again when its temporary mark has run out, at its next lookup or by the
 * {@link ClientKeysRefresher}.
 * </p>
 *
 * @author Martin Lindström
 */
public class ConfigurationClientBackend implements ValidatingClientBackend {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ConfigurationClientBackend.class);

  /** The default backend name. */
  public static final String DEFAULT_NAME = "configuration";

  /** The clients, keyed by {@code client_id}. */
  private final Map<String, OidcClientRecord> clients;

  /** The backend name. */
  private final String name;

  /** Validates the clients, or {@code null} until the OpenID Provider has assigned it. */
  private volatile ClientValidation validation;

  /** Told when a client appears, disappears or is invalid, or {@code null}. */
  private volatile ClientChangeTracker tracker;

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

  /**
   * Assigns the validation, forgets the outcomes of clients that are no longer configured, and validates every
   * configured client.
   */
  @Override
  public void setClientValidation(final @NonNull ClientValidation validation) {
    Objects.requireNonNull(validation, "validation must not be null");
    validation.setClientChangeTracker(this.tracker);
    validation.retain(this.clients.keySet());
    final long invalid = this.clients.values().stream()
        .map(validation::validate)
        .filter(v -> !v.isValid())
        .count();
    this.validation = validation;
    log.info("Validated the {} OpenID Connect client(s) of the source '{}' - {} invalid", this.clients.size(),
        this.name, invalid);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ClientValidation getClientValidation() {
    return this.validation;
  }

  /** {@inheritDoc} */
  @Override
  public void refreshClients() {
    final ClientValidation current = this.validation;
    if (current != null) {
      this.clients.values().forEach(current::refresh);
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final OidcClientRecord client = this.clients.get(identifier);
    return client != null ? this.toRecord(client) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    return this.clients.values().stream()
        .map(c -> RegisteredClient.of(this.toRecord(c), this.name, null))
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
   * Gives the keys of a configured client: those of {@code jwks}, or else those held from its {@code jwks_uri}, see
   * {@link ClientValidation#resolveKeys(OidcClientRecord, JWKMatcher)}. A client of a backend without a validation
   * holds no keys.
   */
  @Override
  public @Nullable List<JWK> resolveKeys(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher) {
    final OidcClientRecord client = this.clients.get(Objects.requireNonNull(clientId, "clientId must not be null"));
    if (client == null) {
      return null;
    }
    final ClientValidation current = this.validation;
    return current != null ? current.resolveKeys(client, matcher) : List.of();
  }

  /**
   * Reports the configured clients to the tracker, and the clients found to be invalid.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    this.tracker = tracker;
    if (tracker != null) {
      tracker.sourceLoaded(AuthenticationProtocol.OIDC, this.name, this.clients.values().stream()
          .map(c -> KnownClient.of(c.toRequesterRecord(), this.name))
          .toList());
    }
    final ClientValidation current = this.validation;
    if (current != null) {
      current.setClientChangeTracker(tracker);
    }
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
