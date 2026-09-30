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

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * The client registry backend that serves OpenID Connect clients resolved through OpenID Federation, where the
 * {@code client_id} of a client is its entity identifier.
 * <p>
 * Resolved clients are cached. A client that the resolver does not know is cached as such for a short time, so that
 * repeated requests for the same unknown {@code client_id} do not each reach the resolver. A resolver that fails is
 * never cached, and the failure is never reported as an unknown client.
 * </p>
 *
 * @author Martin Lindström
 */
public class FederationClientBackend implements ClientRegistryBackend {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationClientBackend.class);

  /** The default backend name. */
  public static final String DEFAULT_NAME = "federation";

  /** How clients are resolved. */
  private final FederationResolver resolver;

  /** How trust marks are asked for on demand. */
  private final TrustMarkRequester trustMarkRequester;

  /** Where resolved clients are kept. */
  private final FederationCache cache;

  /** The cache settings. */
  private final FederationCacheSettings settings;

  /** How often each client is looked up. */
  private final LookupTracker lookupTracker;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The backend name. */
  private String name = DEFAULT_NAME;

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
    this.lookupTracker = new LookupTracker(this.settings.refresh().maximumTrackedClients(),
        this.settings.refresh().lookupPeriod(), clock);
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

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /**
   * Gets the count of lookups per client, which is what the background refresh job works from.
   *
   * @return the {@link LookupTracker} of the backend
   */
  public @NonNull LookupTracker getLookupTracker() {
    return this.lookupTracker;
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
    entry = entry.withTrustMark(trustMark.type(), trustMark.expiresAt());
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
    this.lookupTracker.record(identifier);

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
      entry = CachedClientRecord.found(resolved, now, this.settings.maximumAge());
    }
    this.cache.put(entry);
    return entry;
  }

  /**
   * Creates the protocol-neutral record from a cache entry.
   *
   * @param entry the cache entry, which must hold a client
   * @return a {@link RequesterRecord}
   */
  private @NonNull RequesterRecord toRecord(final @NonNull CachedClientRecord entry) {
    return new OidcClientRecord(entry.clientId(), Objects.requireNonNull(entry.metadata()),
        entry.getMarks(this.clock.instant())).toRequesterRecord();
  }

}
