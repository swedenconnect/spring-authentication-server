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

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.oidc.client.ClientKeyHolder;
import se.swedenconnect.spring.authnserver.oidc.client.ClientMetadataValidator;
import se.swedenconnect.spring.authnserver.oidc.client.HeldKeys;
import se.swedenconnect.spring.authnserver.oidc.client.HeldKeysClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.client.HttpClientKeysFetcher;
import se.swedenconnect.spring.authnserver.oidc.client.HttpSectorIdentifierFetcher;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.client.PairwiseClientCheck;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves OpenID Connect clients resolved through OpenID Federation, where the
 * {@code client_id} of a client is its entity identifier.
 * <p>
 * Resolved clients are cached. A client that the resolver does not know is cached as such for a short time, so that
 * repeated requests for the same unknown {@code client_id} do not each reach the resolver. A resolver that fails is
 * never cached, and the failure is never reported as an unknown client.
 * </p>
 * <p>
 * A client that is resolved and was not known before is reported to the {@link ClientChangeTracker} as added, and a
 * client that the resolver reports as not found is reported as removed. A cache entry that expires and is resolved
 * again is neither.
 * </p>
 * <p>
 * A {@link FederationClientCollector} fills the cache with the clients of the federation, so that a client is
 * normally found in the cache. A client that is not is resolved at its request.
 * </p>
 * <p>
 * Each time a client is resolved, its metadata is checked by the {@link ClientMetadataValidator}. A client with a
 * registration error stays in the cache, marked as invalid, and is never authenticated. It is reported to the
 * {@link ClientChangeTracker} as invalid.
 * </p>
 * <p>
 * The keys at the {@code jwks_uri} or {@code signed_jwks_uri} of a client are fetched when it is resolved, and held in
 * its cache entry. The {@link HeldKeysClientKeyResolver} gives them out, see
 * {@link #resolveKeys(String, OIDCClientMetadata, JWKMatcher)}, so that a request does not cause a fetch.
 * </p>
 *
 * @author Martin Lindström
 */
public class FederationClientBackend implements ClientRegistryBackend, ClientKeyHolder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationClientBackend.class);

  /** The default backend name. */
  public static final String DEFAULT_NAME = "federation";

  /**
   * How often the keys of a client are fetched again at the most, when a JWT names a key that the held keys do not
   * hold.
   */
  public static final Duration KEY_REFRESH_INTERVAL = Duration.ofMinutes(1);

  /** The reason given when a client is removed because the resolver does not know it. */
  public static final String NOT_FOUND_REASON = "the resolver reports the client as not found";

  /** How clients are resolved. */
  private final FederationResolver resolver;

  /** How trust marks are asked for on demand. */
  private final TrustMarkRequester trustMarkRequester;

  /** Where resolved clients are kept. */
  private final FederationCache cache;

  /** The cache settings. */
  private final FederationCacheSettings settings;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The backend name. */
  private String name = DEFAULT_NAME;

  /** Told when a client appears or disappears, or {@code null}. */
  private volatile ClientChangeTracker tracker;

  /** When a client was last resolved by this node, or {@code null}. */
  private volatile Instant lastResolved;

  /** Checks the metadata of resolved clients. */
  private volatile ClientMetadataValidator validator = new ClientMetadataValidator(
      new PairwiseClientCheck(new HttpSectorIdentifierFetcher()), new HttpClientKeysFetcher());

  /** When the keys of each client were last fetched again because a JWT named an unknown key, by {@code client_id}. */
  private final Map<String, Instant> keyRefreshes = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param resolver how clients are resolved
   * @param trustMarkRequester how trust marks are asked for on demand
   * @param cache where resolved clients are kept
   * @param settings the cache settings
   */
  public FederationClientBackend(final @NonNull FederationResolver resolver,
      final @NonNull TrustMarkRequester trustMarkRequester, final @NonNull FederationCache cache,
      final @NonNull FederationCacheSettings settings) {
    this(resolver, trustMarkRequester, cache, settings, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param resolver how clients are resolved
   * @param trustMarkRequester how trust marks are asked for on demand
   * @param cache where resolved clients are kept
   * @param settings the cache settings
   * @param clock the clock to use
   */
  public FederationClientBackend(final @NonNull FederationResolver resolver,
      final @NonNull TrustMarkRequester trustMarkRequester, final @NonNull FederationCache cache,
      final @NonNull FederationCacheSettings settings, final @NonNull Clock clock) {
    this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
    this.trustMarkRequester = Objects.requireNonNull(trustMarkRequester, "trustMarkRequester must not be null");
    this.cache = Objects.requireNonNull(cache, "cache must not be null");
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getName() {
    return this.name;
  }

  /**
   * Assigns the backend name. It is used in logs.
   *
   * @param name the backend name
   */
  public void setName(final @NonNull String name) {
    this.name = Objects.requireNonNull(name, "name must not be null");
  }

  /**
   * Assigns the validator of resolved clients. The default checks the {@code sector_identifier_uri} with an
   * {@link HttpSectorIdentifierFetcher} and fetches keys with an {@link HttpClientKeysFetcher}.
   *
   * @param validator the validator
   */
  public void setValidator(final @NonNull ClientMetadataValidator validator) {
    this.validator = Objects.requireNonNull(validator, "validator must not be null");
  }

  /**
   * Gets the validator of resolved clients.
   *
   * @return the validator
   */
  public @NonNull ClientMetadataValidator getValidator() {
    return this.validator;
  }

  /**
   * Assigns the check of pairwise clients, which is part of the validator. The default checks the
   * {@code sector_identifier_uri} with an {@link HttpSectorIdentifierFetcher}.
   *
   * @param pairwiseClientCheck the check
   */
  public void setPairwiseClientCheck(final @NonNull PairwiseClientCheck pairwiseClientCheck) {
    this.validator.setPairwiseClientCheck(pairwiseClientCheck);
  }

  /**
   * Gets the check of pairwise clients.
   *
   * @return the check
   */
  public @NonNull PairwiseClientCheck getPairwiseClientCheck() {
    return this.validator.getPairwiseClientCheck();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException {
    final CachedClientRecord entry = this.entryFor(identifier);
    return entry.isFound() ? this.toRecord(entry) : null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord requestMark(final @NonNull String identifier, final @NonNull String mark)
      throws ClientRegistryException {

    Objects.requireNonNull(mark, "mark must not be null");
    CachedClientRecord entry = this.entryFor(identifier);
    if (!entry.isFound()) {
      return null;
    }
    if (entry.getMarks(this.clock.instant()).contains(mark)) {
      return this.toRecord(entry);
    }
    final TrustMarkRequester.TrustMark trustMark = this.trustMarkRequester.request(identifier, mark);
    if (trustMark == null) {
      return this.toRecord(entry);
    }
    entry = entry.withTrustMark(trustMark);
    this.cache.put(entry);
    return this.toRecord(entry);
  }

  /**
   * Gets the cache entry for a client, resolving the client if the cache holds no valid entry for it.
   *
   * @param identifier the {@code client_id} of the client
   * @return a {@link CachedClientRecord}, which may be one telling that the client is not known
   * @throws ClientRegistryException if the resolution fails
   */
  private @NonNull CachedClientRecord entryFor(final @NonNull String identifier) throws ClientRegistryException {
    Objects.requireNonNull(identifier, "identifier must not be null");

    final CachedClientRecord cached = this.cache.get(identifier);
    if (cached != null) {
      return cached;
    }
    final Instant now = this.clock.instant();
    final ResolvedClient resolved = this.resolver.resolve(identifier);
    final CachedClientRecord entry;
    if (resolved == null) {
      log.debug("The federation does not know the client '{}'", identifier);
      entry = CachedClientRecord.notFound(identifier, now, this.settings.notFoundTimeToLive());
    }
    else {
      entry = this.found(resolved, null, now);
    }
    this.cache.put(entry);
    this.reportResolved(entry);
    return entry;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    final Instant now = this.clock.instant();
    return this.cache.getEntries().stream()
        .filter(CachedClientRecord::isFound)
        .map(e -> this.toRegisteredClient(e, now))
        .toList();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RegisteredClient getClient(final @NonNull String identifier) {
    final CachedClientRecord entry = this.cache.get(Objects.requireNonNull(identifier, "identifier must not be null"));
    return entry != null && entry.isFound() ? this.toRegisteredClient(entry, this.clock.instant()) : null;
  }

  /**
   * Gets the metadata of a cached client. A client whose metadata cannot be parsed has none.
   */
  @Override
  public @Nullable String getMetadata(final @NonNull String identifier) {
    final CachedClientRecord entry = this.cache.get(Objects.requireNonNull(identifier, "identifier must not be null"));
    return entry != null && entry.metadata() != null && !entry.metadata().toJSONObject().isEmpty()
        ? OidcClientRecord.toJson(entry.metadata())
        : null;
  }

  /**
   * Finds the held keys of a federation client that match a matcher. The keys are those fetched from the client's
   * {@code jwks_uri} or {@code signed_jwks_uri} when it was resolved.
   * <p>
   * When the matcher names a key that the held keys do not hold, the keys are fetched again, so that a client can roll
   * over its keys. The new keys replace the held keys if they pass the checks of the {@link ClientMetadataValidator}.
   * This is done at most once per {@link #KEY_REFRESH_INTERVAL} for each client, and never for a client marked as
   * invalid.
   * </p>
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param matcher the matcher
   * @return the matching keys, possibly empty, or {@code null} if the client is not a cached federation client whose
   *     keys are fetched from the same URI as the metadata gives
   */
  @Override
  public @Nullable List<JWK> resolveKeys(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher) {
    final URI uri = ClientMetadataValidator.getKeysUri(metadata);
    if (uri == null) {
      return null;
    }
    final CachedClientRecord entry = this.cache.get(clientId);
    if (entry == null || entry.metadata() == null
        || !uri.equals(ClientMetadataValidator.getKeysUri(entry.metadata()))) {
      return null;
    }
    final HeldKeys held = entry.heldKeys();
    final boolean signed = metadata.getSignedJWKSetURI() != null;
    if (held == null || !held.isFrom(uri.toString(), signed)) {
      log.debug("The client '{}' holds no keys from {}", clientId, uri);
      return List.of();
    }
    final JWKSelector selector = new JWKSelector(matcher);
    final List<JWK> keys = selector.select(held.keys());
    if (!keys.isEmpty() || !entry.isValid() || matcher.getKeyIDs() == null || matcher.getKeyIDs().isEmpty()
        || held.keys().getKeys().stream().anyMatch(k -> matcher.getKeyIDs().contains(k.getKeyID()))) {
      return keys;
    }
    final Instant now = this.clock.instant();
    final Instant last = this.keyRefreshes.get(clientId);
    if (last != null && now.isBefore(last.plus(KEY_REFRESH_INTERVAL))) {
      log.debug("The keys of the client '{}' do not hold the key {} - they were fetched again at {}", clientId,
          matcher.getKeyIDs(), last);
      return keys;
    }
    this.keyRefreshes.put(clientId, now);
    log.debug("The keys of the client '{}' do not hold the key {} - they are fetched again from {}", clientId,
        matcher.getKeyIDs(), uri);
    final HeldKeys refreshed = this.validator.refreshKeys(clientId, entry.metadata(), held);
    if (refreshed == null) {
      return keys;
    }
    this.cache.put(entry.withHeldKeys(refreshed));
    return selector.select(refreshed.keys());
  }

  /**
   * Gets the backend as one source, with the number of resolved clients in the cache and when this node last resolved
   * a client.
   */
  @Override
  public @NonNull List<ClientSource> getSources() {
    final long clients = this.cache.getEntries().stream().filter(CachedClientRecord::isFound).count();
    return List.of(new ClientSource(AuthenticationProtocol.OIDC, this.name, (int) clients, this.lastResolved));
  }

  /**
   * Drops the client from the cache and resolves it again. If the resolution fails, the entry held before is put back.
   * A client that the resolver reports as not found is reported as removed.
   */
  @Override
  public @NonNull ClientUpdateResult update(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final CachedClientRecord current = this.cache.get(identifier);
    this.cache.remove(identifier);
    final Instant now = this.clock.instant();
    final ResolvedClient resolved;
    try {
      resolved = this.resolver.resolve(identifier);
    }
    catch (final ClientRegistryException e) {
      if (current != null) {
        this.cache.put(current);
      }
      log.info("Failed to resolve the client '{}' again on request: {}", identifier, e.getMessage());
      return ClientUpdateResult.failed(
          "Failed to resolve '%s' - the data held before is kept: %s".formatted(identifier, e.getMessage()));
    }
    final CachedClientRecord entry = resolved != null
        ? this.found(resolved, current != null && current.isFound() ? current : null, now)
        : CachedClientRecord.notFound(identifier, now, this.settings.notFoundTimeToLive());
    this.cache.put(entry);
    this.reportResolved(entry);
    if (resolved == null) {
      log.info("The client '{}' was resolved again on request and is no longer known by the resolver", identifier);
      return ClientUpdateResult.removed("The resolver reports '%s' as not found".formatted(identifier));
    }
    if (!entry.isValid()) {
      log.info("The client '{}' was resolved again on request and is marked as invalid until {}: {}", identifier,
          entry.expiresAt(), entry.invalidReason());
      return ClientUpdateResult.updated("Resolved '%s' again, but it is marked as invalid until %s: %s".formatted(
          identifier, entry.expiresAt(), entry.invalidReason()));
    }
    log.info("The client '{}' was resolved again on request, valid until {}", identifier, entry.expiresAt());
    return ClientUpdateResult.updated("Resolved '%s' again, valid until %s".formatted(identifier, entry.expiresAt()));
  }

  /**
   * Reports the resolved clients of the cache to the tracker, so that a client that was cached before a restart and
   * is not in the record of known clients is reported as added.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    this.tracker = tracker;
    if (tracker != null) {
      tracker.clientsSeen(this.cache.getEntries().stream()
          .filter(CachedClientRecord::isFound)
          .map(this::toKnownClient)
          .toList());
    }
  }

  /**
   * Creates the cache entry of a client that the resolver knows, with the outcome of the validation of the client.
   *
   * @param resolved what the resolver answered
   * @param earlier the earlier entry of the client, whose held keys and remembered check are used, or {@code null}
   * @param now the current time
   * @return a {@link CachedClientRecord}
   */
  @NonNull CachedClientRecord found(final @NonNull ResolvedClient resolved,
      final @Nullable CachedClientRecord earlier, final @NonNull Instant now) {
    final ClientMetadataValidator.Outcome outcome = this.validator.validate(resolved, earlier);
    return CachedClientRecord.found(resolved, now, this.settings.maximumAge())
        .withOutcome(outcome, now, this.settings.notFoundTimeToLive());
  }

  /**
   * Reports the outcome of a resolution to the tracker: a client that was found is seen, a client that was found and
   * marked as invalid is also reported as invalid, and a client that was not found is removed. A failure to report is
   * logged and does not affect the resolution.
   *
   * @param entry the cache entry created from the resolution
   */
  void reportResolved(final @NonNull CachedClientRecord entry) {
    this.lastResolved = this.clock.instant();
    final ClientChangeTracker current = this.tracker;
    if (current == null) {
      return;
    }
    try {
      if (entry.isFound()) {
        current.clientSeen(this.toKnownClient(entry));
        if (entry.invalidReason() != null) {
          current.clientInvalid(this.toKnownClient(entry), entry.invalidReason());
        }
      }
      else {
        current.clientRemoved(new Requester(AuthenticationProtocol.OIDC, entry.clientId()), NOT_FOUND_REASON);
      }
    }
    catch (final RuntimeException e) {
      log.error("Failed to record the change of the client '{}': {}", entry.clientId(), e.getMessage(), e);
    }
  }

  /**
   * Gets where resolved clients are kept.
   *
   * @return the cache
   */
  @NonNull FederationCache getCache() {
    return this.cache;
  }

  /**
   * Gets how clients are resolved.
   *
   * @return the resolver
   */
  @NonNull FederationResolver getResolver() {
    return this.resolver;
  }

  /**
   * Gets the cache settings.
   *
   * @return the settings
   */
  @NonNull FederationCacheSettings getSettings() {
    return this.settings;
  }

  /**
   * Gets the clock.
   *
   * @return the clock
   */
  @NonNull Clock getClock() {
    return this.clock;
  }

  /**
   * Creates the entry of a cached client for the list of clients.
   *
   * @param entry the cache entry, which must hold a client
   * @param now the current time
   * @return a {@link RegisteredClient}
   */
  private @NonNull RegisteredClient toRegisteredClient(final @NonNull CachedClientRecord entry,
      final @NonNull Instant now) {
    final RequesterRecord record = new OidcClientRecord(entry.clientId(), Objects.requireNonNull(entry.metadata()),
        entry.getMarks(now)).toRequesterRecord().withInvalidReason(entry.invalidReason());
    return RegisteredClient.of(record, this.name, entry.expiresAt());
  }

  /**
   * Creates the entry of a cached client for the record of known clients.
   *
   * @param entry the cache entry, which must hold a client
   * @return a {@link KnownClient}
   */
  private @NonNull KnownClient toKnownClient(final @NonNull CachedClientRecord entry) {
    return KnownClient.of(new OidcClientRecord(entry.clientId(), Objects.requireNonNull(entry.metadata()),
        entry.trustMarkTypes()).toRequesterRecord(), this.name);
  }

  /**
   * Creates the protocol-neutral record from a cache entry, marked as invalid if the entry is.
   *
   * @param entry the cache entry, which must hold a client
   * @return a {@link RequesterRecord}
   */
  private @NonNull RequesterRecord toRecord(final @NonNull CachedClientRecord entry) {
    return new OidcClientRecord(entry.clientId(), Objects.requireNonNull(entry.metadata()),
        entry.getMarks(this.clock.instant())).toRequesterRecord().withInvalidReason(entry.invalidReason());
  }

}
