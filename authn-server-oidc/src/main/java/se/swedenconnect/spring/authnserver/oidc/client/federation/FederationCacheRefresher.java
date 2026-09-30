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
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * The background job that resolves a cached client again shortly before its entry expires, so that a request from a
 * frequently used client never waits for the resolver.
 * <p>
 * Only clients that qualify are refreshed: a client must have been looked up often enough, and one run never
 * refreshes more clients than the configured maximum. Clients that are used rarely are left alone and are resolved
 * again when they are next asked for. The job is off unless it has been turned on.
 * </p>
 *
 * @author Martin Lindström
 */
public class FederationCacheRefresher implements Runnable, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationCacheRefresher.class);

  /** Where resolved clients are kept. */
  private final FederationCache cache;

  /** How clients are resolved. */
  private final FederationResolver resolver;

  /** How often each client is looked up. */
  private final LookupTracker lookupTracker;

  /** The cache settings. */
  private final FederationCacheSettings settings;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** Where the job runs, or {@code null} until it has been started. */
  private ScheduledExecutorService executor;

  /**
   * Constructor.
   *
   * @param cache where resolved clients are kept
   * @param resolver how clients are resolved
   * @param lookupTracker how often each client is looked up
   * @param settings the cache settings
   */
  public FederationCacheRefresher(final @NonNull FederationCache cache, final @NonNull FederationResolver resolver,
      final @NonNull LookupTracker lookupTracker, final @NonNull FederationCacheSettings settings) {
    this(cache, resolver, lookupTracker, settings, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param cache where resolved clients are kept
   * @param resolver how clients are resolved
   * @param lookupTracker how often each client is looked up
   * @param settings the cache settings
   * @param clock the clock to use
   */
  public FederationCacheRefresher(final @NonNull FederationCache cache, final @NonNull FederationResolver resolver,
      final @NonNull LookupTracker lookupTracker, final @NonNull FederationCacheSettings settings,
      final @NonNull Clock clock) {
    this.cache = Objects.requireNonNull(cache, "cache must not be null");
    this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
    this.lookupTracker = Objects.requireNonNull(lookupTracker, "lookupTracker must not be null");
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /**
   * Starts the job, unless the settings say that it does not run.
   */
  public synchronized void start() {
    if (!this.settings.refresh().enabled()) {
      log.debug("The federation cache refresh job is turned off");
      return;
    }
    if (this.executor != null) {
      return;
    }
    final long interval = this.settings.refresh().interval().toMillis();
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread thread = new Thread(r, "federation-cache-refresher");
      thread.setDaemon(true);
      return thread;
    });
    this.executor.scheduleWithFixedDelay(this, interval, interval, TimeUnit.MILLISECONDS);
    log.info("The federation cache refresh job runs every {}", this.settings.refresh().interval());
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    try {
      this.refresh();
    }
    catch (final RuntimeException e) {
      log.error("The federation cache refresh job failed", e);
    }
  }

  /**
   * Makes one pass over the clients that qualify and refreshes the entries that are about to expire.
   *
   * @return the number of entries that were refreshed
   */
  public int refresh() {
    final FederationCacheSettings.RefreshSettings refresh = this.settings.refresh();
    final List<String> candidates =
        this.lookupTracker.getFrequentClients(refresh.minimumLookups(), refresh.maximumClients());
    if (candidates.isEmpty()) {
      return 0;
    }
    final Instant now = this.clock.instant();
    final Instant limit = now.plus(refresh.refreshAhead());
    int refreshed = 0;
    for (final String clientId : candidates) {
      final CachedClientRecord current = this.cache.get(clientId);
      if (current == null || !current.isFound() || current.expiresAt().isAfter(limit)) {
        continue;
      }
      if (this.refreshClient(clientId, current, now)) {
        refreshed++;
      }
    }
    if (refreshed > 0) {
      log.debug("Refreshed {} of the {} frequently used clients", refreshed, candidates.size());
    }
    return refreshed;
  }

  /**
   * Resolves one client again and replaces its cache entry.
   *
   * @param clientId the {@code client_id} of the client
   * @param current the entry that is about to expire
   * @param now the current time
   * @return {@code true} if the entry was refreshed and {@code false} otherwise
   */
  private boolean refreshClient(
      final @NonNull String clientId, final @NonNull CachedClientRecord current, final @NonNull Instant now) {
    try {
      final ResolvedClient resolved = this.resolver.resolve(clientId);
      if (resolved == null) {
        log.info("The client '{}' is no longer known by the resolver - its cache entry is dropped", clientId);
        this.cache.remove(clientId);
        return false;
      }
      this.cache.put(CachedClientRecord.found(resolved, now, this.settings.maximumAge())
          .carryOverTrustMarks(current, now));
      return true;
    }
    catch (final ClientRegistryException e) {
      log.warn("Failed to refresh the client '{}' - the cache entry is kept until it expires: {}",
          clientId, e.getMessage());
      return false;
    }
  }

  /**
   * Stops the job.
   */
  @Override
  public synchronized void close() {
    if (this.executor != null) {
      this.executor.shutdownNow();
      this.executor = null;
    }
  }

}
