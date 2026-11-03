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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * Validates the clients of one client source, the configuration or a {@link ClientRepository}, with the
 * {@link ClientMetadataValidator}, and holds the keys that their {@code jwks_uri} gives. It is assigned to the backend
 * of the source by the OpenID Provider, see {@link ValidatingClientBackend}.
 * <p>
 * The outcome of a validation is kept in a {@link ClientValidationStore}, together with a fingerprint of the metadata
 * that was validated, so that a client is validated again only when its metadata has changed or its temporary mark has
 * run out. A client whose keys cannot be read on the first check is marked as invalid for the given time.
 * </p>
 * <p>
 * Every client that is found to be invalid is reported to the {@link ClientChangeTracker}, which publishes a
 * {@code client_invalid} audit event. A client found to be invalid before the tracker is assigned is reported when it
 * is.
 * </p>
 * <p>
 * When a JWT names a key that the held keys do not hold, the {@code jwks_uri} is read again, at most once per
 * {@link #KEY_REFRESH_INTERVAL} for each client, as for federation clients.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientValidation {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientValidation.class);

  /**
   * How often the keys of a client are read again at the most, when a JWT names a key that the held keys do not hold.
   */
  public static final Duration KEY_REFRESH_INTERVAL = Duration.ofMinutes(1);

  /** The name of the client source. */
  private final String source;

  /** Checks the metadata of the clients. */
  private final ClientMetadataValidator validator;

  /** Where the outcomes are kept. */
  private final ClientValidationStore store;

  /** How long a client whose keys cannot be read is marked as invalid. */
  private final Duration temporaryMarkTimeToLive;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** When the keys of each client were last read again because a JWT named an unknown key, by {@code client_id}. */
  private final Map<String, Instant> keyRefreshes = new ConcurrentHashMap<>();

  /** The invalid clients to report when the tracker is assigned, by {@code client_id}. Guarded by {@code this}. */
  private final Map<String, Unreported> unreported = new LinkedHashMap<>();

  /** Told when a client is found to be invalid, or {@code null}. Guarded by {@code this}. */
  private ClientChangeTracker tracker;

  /**
   * Constructor.
   *
   * @param source the name of the client source
   * @param validator checks the metadata of the clients
   * @param store where the outcomes are kept
   * @param temporaryMarkTimeToLive how long a client whose keys cannot be read is marked as invalid
   * @param clock the clock to use
   */
  public ClientValidation(final @NonNull String source, final @NonNull ClientMetadataValidator validator,
      final @NonNull ClientValidationStore store, final @NonNull Duration temporaryMarkTimeToLive,
      final @NonNull Clock clock) {
    this.source = Objects.requireNonNull(source, "source must not be null");
    this.validator = Objects.requireNonNull(validator, "validator must not be null");
    this.store = Objects.requireNonNull(store, "store must not be null");
    this.temporaryMarkTimeToLive =
        Objects.requireNonNull(temporaryMarkTimeToLive, "temporaryMarkTimeToLive must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /**
   * Gets the name of the client source.
   *
   * @return the name
   */
  public @NonNull String getSource() {
    return this.source;
  }

  /**
   * Gets the validator.
   *
   * @return the validator
   */
  public @NonNull ClientMetadataValidator getValidator() {
    return this.validator;
  }

  /**
   * Gets the store of the outcomes.
   *
   * @return the store
   */
  public @NonNull ClientValidationStore getStore() {
    return this.store;
  }

  /**
   * Assigns the tracker that is told when a client is found to be invalid. Clients found to be invalid before are
   * reported to it at once.
   *
   * @param tracker the tracker, or {@code null}
   */
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    final List<Unreported> pending;
    synchronized (this) {
      this.tracker = tracker;
      if (tracker == null) {
        return;
      }
      pending = List.copyOf(this.unreported.values());
      this.unreported.clear();
    }
    pending.forEach(u -> this.report(tracker, u.client(), u.reason()));
  }

  /**
   * Gets the outcome for a client, validating the client if there is no outcome for its current metadata, or its
   * temporary mark has run out. Otherwise nothing is fetched.
   *
   * @param client the client
   * @return the outcome
   */
  public @NonNull ValidatedClient get(final @NonNull OidcClientRecord client) {
    Objects.requireNonNull(client, "client must not be null");
    final ValidatedClient stored = this.store.get(this.source, client.clientId());
    if (stored != null && stored.fingerprint().equals(ValidatedClient.fingerprint(client))
        && !stored.isMarkExpired(this.clock.instant())) {
      return stored;
    }
    return this.validate(client, stored);
  }

  /**
   * Validates a client, using the keys that it held before if its keys cannot be read.
   *
   * @param client the client
   * @return the outcome
   */
  public @NonNull ValidatedClient validate(final @NonNull OidcClientRecord client) {
    Objects.requireNonNull(client, "client must not be null");
    return this.validate(client, this.store.get(this.source, client.clientId()));
  }

  /**
   * Keeps the outcome of a client up to date, for the {@link ClientKeysRefresher}. A client whose metadata has
   * changed, or whose temporary mark has run out, is validated again. A valid client that holds keys has them read
   * again. If they cannot be read, or are not usable, the held keys are kept.
   *
   * @param client the client
   */
  public void refresh(final @NonNull OidcClientRecord client) {
    Objects.requireNonNull(client, "client must not be null");
    final ValidatedClient stored = this.store.get(this.source, client.clientId());
    if (stored == null || !stored.fingerprint().equals(ValidatedClient.fingerprint(client))
        || stored.isMarkExpired(this.clock.instant())) {
      this.validate(client, stored);
      return;
    }
    final HeldKeys held = stored.heldKeys();
    if (!stored.isValid() || held == null) {
      return;
    }
    final HeldKeys refreshed = this.validator.refreshKeys(client.clientId(), client.metadata(), held);
    if (refreshed != null) {
      this.store.put(this.source, stored.withHeldKeys(refreshed));
    }
  }

  /**
   * Forgets the outcome for a client that the source no longer holds.
   *
   * @param clientId the {@code client_id} of the client
   */
  public void forget(final @NonNull String clientId) {
    this.store.remove(this.source, Objects.requireNonNull(clientId, "clientId must not be null"));
    this.keyRefreshes.remove(clientId);
  }

  /**
   * Forgets the outcomes for every client that the source no longer holds.
   *
   * @param clientIds the {@code client_id} of every client that the source holds
   */
  public void retain(final @NonNull Collection<String> clientIds) {
    final Set<String> held = Set.copyOf(Objects.requireNonNull(clientIds, "clientIds must not be null"));
    this.store.getAll(this.source).stream()
        .map(ValidatedClient::clientId)
        .filter(id -> !held.contains(id))
        .forEach(this::forget);
  }

  /**
   * Gets the {@code client_id} of every client that has an outcome.
   *
   * @return the {@code client_id} values
   */
  public @NonNull List<String> getValidatedClientIds() {
    return this.store.getAll(this.source).stream().map(ValidatedClient::clientId).toList();
  }

  /**
   * Finds the keys of a client that match a matcher. The keys are those of {@code jwks}, or else those held from its
   * {@code jwks_uri}. A request never causes a fetch of a key that is held.
   * <p>
   * When the matcher names a key that the held keys do not hold, the keys are read again, so that a client can roll
   * over its keys. The new keys replace the held keys if they pass the checks of the {@link ClientMetadataValidator}.
   * This is done at most once per {@link #KEY_REFRESH_INTERVAL} for each client, and never for a client marked as
   * invalid.
   * </p>
   *
   * @param client the client
   * @param matcher the matcher
   * @return the matching keys, possibly empty
   */
  public @NonNull List<JWK> resolveKeys(final @NonNull OidcClientRecord client, final @NonNull JWKMatcher matcher) {
    final OIDCClientMetadata metadata = client.metadata();
    final JWKSelector selector = new JWKSelector(Objects.requireNonNull(matcher, "matcher must not be null"));
    if (metadata.getJWKSet() != null) {
      return selector.select(metadata.getJWKSet());
    }
    final ValidatedClient validated = this.get(client);
    final HeldKeys held = validated.heldKeys();
    if (held == null) {
      log.debug("The client '{}' of the source '{}' holds no keys", client.clientId(), this.source);
      return List.of();
    }
    final List<JWK> keys = selector.select(held.keys());
    if (!keys.isEmpty() || !validated.isValid() || matcher.getKeyIDs() == null || matcher.getKeyIDs().isEmpty()
        || held.keys().getKeys().stream().anyMatch(k -> matcher.getKeyIDs().contains(k.getKeyID()))) {
      return keys;
    }
    final Instant now = this.clock.instant();
    final Instant last = this.keyRefreshes.get(client.clientId());
    if (last != null && now.isBefore(last.plus(KEY_REFRESH_INTERVAL))) {
      log.debug("The keys of the client '{}' do not hold the key {} - they were read again at {}", client.clientId(),
          matcher.getKeyIDs(), last);
      return keys;
    }
    this.keyRefreshes.put(client.clientId(), now);
    log.debug("The keys of the client '{}' do not hold the key {} - they are read again from {}", client.clientId(),
        matcher.getKeyIDs(), held.uri());
    final HeldKeys refreshed = this.validator.refreshKeys(client.clientId(), metadata, held);
    if (refreshed == null) {
      return keys;
    }
    this.store.put(this.source, validated.withHeldKeys(refreshed));
    return selector.select(refreshed.keys());
  }

  /**
   * Validates a client and keeps the outcome.
   *
   * @param client the client
   * @param earlier the earlier outcome, whose held keys are used if the keys cannot be read, or {@code null}
   * @return the outcome
   */
  private @NonNull ValidatedClient validate(final @NonNull OidcClientRecord client,
      final @Nullable ValidatedClient earlier) {
    log.debug("Validating the client '{}' of the source '{}'", client.clientId(), this.source);
    final ClientMetadataValidator.Outcome outcome =
        this.validator.validate(client, earlier != null ? earlier.heldKeys() : null);
    final ValidatedClient validated = new ValidatedClient(client.clientId(), ValidatedClient.fingerprint(client),
        outcome.invalidReason(), outcome.temporary() ? this.clock.instant().plus(this.temporaryMarkTimeToLive) : null,
        outcome.heldKeys());
    this.store.put(this.source, validated);
    if (!validated.isValid()) {
      final String reason = Objects.requireNonNull(validated.invalidReason());
      final ClientChangeTracker current;
      synchronized (this) {
        current = this.tracker;
        if (current == null) {
          this.unreported.put(client.clientId(), new Unreported(client, reason));
        }
      }
      if (current != null) {
        this.report(current, client, reason);
      }
    }
    return validated;
  }

  /**
   * Reports an invalid client to the tracker. A failure to report is logged and does not affect the validation.
   *
   * @param tracker the tracker
   * @param client the client
   * @param reason why the client is invalid
   */
  private void report(final @NonNull ClientChangeTracker tracker, final @NonNull OidcClientRecord client,
      final @NonNull String reason) {
    try {
      tracker.clientInvalid(KnownClient.of(client.toRequesterRecord(), this.source), reason);
    }
    catch (final RuntimeException e) {
      log.error("Failed to record that the client '{}' is invalid: {}", client.clientId(), e.getMessage(), e);
    }
  }

  /**
   * An invalid client that has not been reported, since there was no tracker.
   *
   * @param client the client
   * @param reason why the client is invalid
   */
  private record Unreported(@NonNull OidcClientRecord client, @NonNull String reason) {
  }

}
