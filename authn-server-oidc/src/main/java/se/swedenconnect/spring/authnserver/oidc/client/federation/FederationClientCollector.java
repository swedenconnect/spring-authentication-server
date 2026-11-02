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

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.SubordinateListingRequest;

/**
 * The background job that fills the cache of a {@link FederationClientBackend} with the clients of the federation, so
 * that an authorization request does not have to wait for the resolver.
 * <p>
 * A run walks the federation from the trust anchor, or from the configured intermediates. Each entity is resolved,
 * asking for both its relying party and its federation entity metadata, see
 * {@link FederationResolver#resolveEntity(String)}. An entity that publishes a {@code federation_list_endpoint} is
 * asked for its subordinates, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.2">OpenID Federation 1.0, Section 8.2</a>, and
 * each of them is resolved in the same way. An entity with relying party metadata is a client and is put in the cache.
 * Each entity is visited once per run. What the resolver answers about each entity is kept in a
 * {@link FederationEntityStore}, and reused until it expires.
 * </p>
 * <p>
 * Each client that is put in the cache is checked as when it is resolved at its request, see
 * {@link PairwiseClientCheck}.
 * </p>
 * <p>
 * A run then renews every cached client whose entry expires before the next run, keeping the trust marks that have
 * been asked for on demand. When every listing call and every resolution of the walk succeeded, a cached client that
 * the walk did not find is resolved again; one that still resolves stays. A client that the resolver no longer knows
 * is kept until its entry expires, or dropped at once, see {@link FederationCollectorSettings#keepUntilExpiry()}. A
 * failure never removes a client, and never stops the run.
 * </p>
 * <p>
 * When the cache is shared by several nodes, a run takes place on one node at a time, see
 * {@link FederationCache#getJobLock()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class FederationClientCollector implements Runnable, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationClientCollector.class);

  /** The name of the job, for the {@link se.swedenconnect.spring.authnserver.job.JobLock} of the cache. */
  public static final String JOB_NAME = "oidc-federation-client-collector";

  /** The time from start until the first run. */
  public static final Duration INITIAL_DELAY = Duration.ofSeconds(10);

  /** The backend whose cache is filled. */
  private final FederationClientBackend backend;

  /** Where the resolve results of the entities are kept. */
  private final FederationEntityStore entityStore;

  /** The client making the listing calls. */
  private final FederationClient federationClient;

  /** The settings of the federation, giving the trust anchor. */
  private final FederationSettings federationSettings;

  /** The settings of the job. */
  private final FederationCollectorSettings settings;

  /** Where the job runs, or {@code null} until it has been started. */
  private ScheduledExecutorService executor;

  /**
   * Constructor.
   *
   * @param backend the backend whose cache is filled
   * @param entityStore where the resolve results of the entities are kept
   * @param federationClient the client making the listing calls
   * @param federationSettings the settings of the federation
   * @param settings the settings of the job
   */
  public FederationClientCollector(final @NonNull FederationClientBackend backend,
      final @NonNull FederationEntityStore entityStore, final @NonNull FederationClient federationClient,
      final @NonNull FederationSettings federationSettings, final @NonNull FederationCollectorSettings settings) {
    this.backend = Objects.requireNonNull(backend, "backend must not be null");
    this.entityStore = Objects.requireNonNull(entityStore, "entityStore must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.federationSettings = Objects.requireNonNull(federationSettings, "federationSettings must not be null");
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
  }

  /**
   * Starts the job, unless the settings say that it does not run. The first run comes {@link #INITIAL_DELAY} after
   * the start.
   */
  public synchronized void start() {
    if (!this.settings.enabled()) {
      log.info("The federation client collector is turned off");
      return;
    }
    if (this.executor != null) {
      return;
    }
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread thread = new Thread(r, "federation-client-collector");
      thread.setDaemon(true);
      return thread;
    });
    this.executor.scheduleWithFixedDelay(this, INITIAL_DELAY.toMillis(), this.settings.interval().toMillis(),
        TimeUnit.MILLISECONDS);
    log.info("The federation client collector runs every {}, starting from {}", this.settings.interval(),
        this.startingPoints());
  }

  /**
   * Tells whether the job has been started.
   *
   * @return {@code true} if the job is started and {@code false} otherwise
   */
  public synchronized boolean isStarted() {
    return this.executor != null;
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    try {
      this.collect();
    }
    catch (final RuntimeException e) {
      log.error("The federation client collector failed", e);
    }
  }

  /**
   * Makes one run. Nothing is done when another node makes the run.
   *
   * @return what the run did, or {@code null} if it ran on another node
   */
  public @Nullable RunResult collect() {
    if (!this.backend.getCache().getJobLock().tryAcquire(JOB_NAME, this.settings.interval())) {
      log.debug("The federation client collector runs on another node this round");
      return null;
    }
    final Run run = new Run();
    run.walk();
    run.renew();
    if (run.complete) {
      run.checkUnlisted();
    }
    else {
      log.debug("Not every listing call or resolution succeeded - cached clients that were not found are kept");
    }
    run.checkRetained();
    this.entityStore.purgeExpired();
    final RunResult result = new RunResult(run.complete, run.visited.size(), run.clients, run.renewed, run.removed,
        run.retained);
    log.debug("The federation client collector visited {} entities and found {} clients: {}", result.entities(),
        result.clients(), result);
    return result;
  }

  /**
   * Gets where the walk starts: the configured intermediates, or else the trust anchor.
   *
   * @return the entity identifiers to start from
   */
  private @NonNull List<String> startingPoints() {
    return this.settings.intermediates().isEmpty()
        ? List.of(this.federationSettings.trustAnchor().entityId())
        : this.settings.intermediates();
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

  /**
   * What a run did.
   *
   * @param complete whether every listing call and every resolution of the walk succeeded
   * @param entities the number of entities that the walk visited
   * @param clients the number of clients that the walk found
   * @param renewed the number of cached clients that were resolved again and updated
   * @param removed the number of cached clients that were dropped since the resolver no longer knows them
   * @param retained the number of cached clients that the resolver no longer knows and that are kept until they
   *     expire
   */
  public record RunResult(boolean complete, int entities, int clients, int renewed, int removed, int retained) {
  }

  /**
   * The state of one run.
   */
  private final class Run {

    /** The time of the run. */
    private final Instant now;

    /** The time of the next run. */
    private final Instant nextRun;

    /** The entities that the walk visited. */
    private final Set<String> visited = new LinkedHashSet<>();

    /** The clients that have been resolved in this run, whatever the answer. */
    private final Set<String> resolved = new HashSet<>();

    /** The clients that have been put in the cache in this run. */
    private final Set<String> updated = new HashSet<>();

    /** The retained clients, keyed by {@code client_id}. */
    private final Map<String, RetainedClient> retainedClients = new HashMap<>();

    /** Whether every listing call and every resolution of the walk succeeded. */
    private boolean complete = true;

    /** The number of clients found by the walk. */
    private int clients;

    /** The number of cached clients that were resolved again and updated. */
    private int renewed;

    /** The number of cached clients that were dropped. */
    private int removed;

    /** The number of cached clients that are kept although the resolver no longer knows them. */
    private int retained;

    /**
     * Constructor.
     */
    Run() {
      this.now = FederationClientCollector.this.backend.getClock().instant();
      this.nextRun = this.now.plus(FederationClientCollector.this.settings.interval());
      FederationClientCollector.this.entityStore.getRetainedClients()
          .forEach(c -> this.retainedClients.put(c.clientId(), c));
    }

    /**
     * Walks the federation from the starting points.
     */
    void walk() {
      final Deque<String> queue = new ArrayDeque<>(FederationClientCollector.this.startingPoints());
      while (!queue.isEmpty()) {
        final String entityId = queue.poll();
        if (!this.visited.add(entityId)) {
          continue;
        }
        FederationEntityRecord record = FederationClientCollector.this.entityStore.get(entityId);
        final boolean fresh = record == null;
        if (record == null) {
          try {
            record = this.resolve(entityId);
          }
          catch (final RuntimeException e) {
            log.warn("Failed to resolve the federation entity '{}' - it is tried again at the next run: {}",
                entityId, e.getMessage());
            this.complete = false;
            continue;
          }
        }
        if (record.listEndpoint() != null) {
          this.list(entityId, record.listEndpoint(), queue);
        }
        final CachedClientRecord cached = FederationClientCollector.this.backend.getCache().get(entityId);
        final ResolvedClient client = record.toClient();
        if (client != null) {
          this.clients++;
          if (fresh || cached == null || !cached.isFound()) {
            this.put(client, cached);
          }
        }
        else if (fresh && cached != null && cached.isFound()) {
          this.notFound(entityId, cached);
        }
      }
    }

    /**
     * Asks an entity for its subordinates and adds them to the walk.
     *
     * @param entityId the entity identifier
     * @param listEndpoint the {@code federation_list_endpoint} of the entity
     * @param queue the entities that remain to be visited
     */
    private void list(final @NonNull String entityId, final @NonNull String listEndpoint,
        final @NonNull Deque<String> queue) {
      try {
        final List<String> subordinates = FederationClientCollector.this.federationClient.subordinateListing(
            new FederationRequest<>(SubordinateListingRequest.requestAll(),
                Map.of(HttpFederationClient.FEDERATION_LIST_ENDPOINT, listEndpoint,
                    HttpFederationClient.LISTING_ENTITY_ID, entityId)));
        log.trace("The federation entity '{}' lists {} subordinates", entityId, subordinates.size());
        queue.addAll(subordinates);
      }
      catch (final RuntimeException e) {
        log.warn("Failed to list the subordinates of the federation entity '{}' - it is tried again at the next "
            + "run: {}", entityId, e.getMessage());
        this.complete = false;
      }
    }

    /**
     * Resolves every cached client whose entry expires before the next run, unless it has been resolved in this run,
     * or put in the cache in this run and marked as invalid.
     */
    void renew() {
      for (final CachedClientRecord entry : FederationClientCollector.this.backend.getCache().getEntries()) {
        if (entry.isFound() && entry.expiresAt().isBefore(this.nextRun) && !this.resolved.contains(entry.clientId())
            && !(this.updated.contains(entry.clientId()) && !entry.isValid())) {
          this.resolveAgain(entry, "renew");
        }
      }
    }

    /**
     * Resolves every cached client that the walk did not find, unless it has been resolved in this run.
     */
    void checkUnlisted() {
      for (final CachedClientRecord entry : FederationClientCollector.this.backend.getCache().getEntries()) {
        if (entry.isFound() && !this.visited.contains(entry.clientId()) && !this.resolved.contains(entry.clientId())) {
          log.debug("The cached client '{}' was not found in the federation - it is resolved again", entry.clientId());
          this.resolveAgain(entry, "check");
        }
      }
    }

    /**
     * Goes through the retained clients whose cache entries have expired. A client that the resolver still does not
     * know is reported as removed, and one that it knows again is put back in the cache.
     */
    void checkRetained() {
      for (final RetainedClient client : List.copyOf(this.retainedClients.values())) {
        final CachedClientRecord cached = FederationClientCollector.this.backend.getCache().get(client.clientId());
        if (cached != null && cached.isFound()) {
          this.retained++;
          continue;
        }
        if (cached != null) {
          // A request has resolved the client since its entry expired, and reported it as removed
          this.retainedClients.remove(client.clientId());
          FederationClientCollector.this.entityStore.removeRetainedClient(client.clientId());
          continue;
        }
        try {
          final FederationEntityRecord stored = this.resolved.contains(client.clientId())
              ? FederationClientCollector.this.entityStore.get(client.clientId())
              : null;
          final ResolvedClient resolved =
              (stored != null ? stored : this.resolve(client.clientId())).toClient();
          if (resolved != null) {
            log.info("The client '{}' is known by the resolver again", client.clientId());
            this.put(resolved, null);
          }
          else {
            this.drop(client.clientId());
          }
        }
        catch (final RuntimeException e) {
          log.warn("Failed to resolve the retained client '{}' - it is tried again at the next run: {}",
              client.clientId(), e.getMessage());
        }
      }
    }

    /**
     * Resolves a cached client again and updates its entry. A failure leaves the entry in place.
     *
     * @param entry the cache entry
     * @param what what is done, for the log
     */
    private void resolveAgain(final @NonNull CachedClientRecord entry, final @NonNull String what) {
      try {
        final ResolvedClient client = this.resolve(entry.clientId()).toClient();
        if (client != null) {
          this.put(client, entry);
          this.renewed++;
        }
        else {
          this.notFound(entry.clientId(), entry);
        }
      }
      catch (final RuntimeException e) {
        log.warn("Failed to {} the client '{}' - its cache entry is kept: {}", what, entry.clientId(), e.getMessage());
      }
    }

    /**
     * Resolves an entity and keeps the answer in the entity store.
     *
     * @param entityId the entity identifier
     * @return the entity record
     * @throws RuntimeException if the resolution fails
     */
    private @NonNull FederationEntityRecord resolve(final @NonNull String entityId) {
      this.resolved.add(entityId);
      final FederationCacheSettings cacheSettings = FederationClientCollector.this.backend.getSettings();
      final ResolvedEntity entity = FederationClientCollector.this.backend.getResolver().resolveEntity(entityId);
      final FederationEntityRecord record = entity != null
          ? FederationEntityRecord.found(entity, this.now, cacheSettings.maximumAge())
          : FederationEntityRecord.notFound(entityId, this.now, cacheSettings.notFoundTimeToLive());
      FederationClientCollector.this.entityStore.put(record);
      return record;
    }

    /**
     * Puts a client in the cache, keeping the trust marks of the earlier entry that have been asked for on demand. A
     * pairwise client is checked, see {@link PairwiseClientCheck}.
     *
     * @param client the resolved client
     * @param earlier the earlier entry, or {@code null}
     */
    private void put(final @NonNull ResolvedClient client, final @Nullable CachedClientRecord earlier) {
      final FederationClientBackend backend = FederationClientCollector.this.backend;
      final CachedClientRecord found = earlier != null && earlier.isFound() ? earlier : null;
      final CachedClientRecord entry = backend.found(client, found, this.now).carryOverTrustMarks(found, this.now);
      backend.getCache().put(entry);
      backend.reportResolved(entry);
      this.updated.add(client.clientId());
      if (this.retainedClients.remove(client.clientId()) != null) {
        FederationClientCollector.this.entityStore.removeRetainedClient(client.clientId());
      }
    }

    /**
     * Handles a cached client that the resolver no longer knows: it is kept until its entry expires, or dropped at
     * once, depending on the settings.
     *
     * @param clientId the {@code client_id} of the client
     * @param cached the cache entry
     */
    private void notFound(final @NonNull String clientId, final @NonNull CachedClientRecord cached) {
      if (!FederationClientCollector.this.settings.keepUntilExpiry()) {
        this.drop(clientId);
        return;
      }
      if (this.retainedClients.containsKey(clientId)) {
        log.debug("The client '{}' is still not known by the resolver - it is kept until {}", clientId,
            cached.expiresAt());
        return;
      }
      log.warn("The client '{}' is no longer known by the resolver - it is kept until its cache entry expires at {}",
          clientId, cached.expiresAt());
      final RetainedClient retainedClient = new RetainedClient(clientId, this.now, cached.expiresAt());
      FederationClientCollector.this.entityStore.putRetainedClient(retainedClient);
      this.retainedClients.put(clientId, retainedClient);
    }

    /**
     * Drops a client that the resolver no longer knows from the cache, and reports it as removed.
     *
     * @param clientId the {@code client_id} of the client
     */
    private void drop(final @NonNull String clientId) {
      log.info("The client '{}' is no longer known by the resolver - it is dropped", clientId);
      final FederationClientBackend backend = FederationClientCollector.this.backend;
      final CachedClientRecord entry =
          CachedClientRecord.notFound(clientId, this.now, backend.getSettings().notFoundTimeToLive());
      backend.getCache().put(entry);
      backend.reportResolved(entry);
      if (this.retainedClients.remove(clientId) != null) {
        FederationClientCollector.this.entityStore.removeRetainedClient(clientId);
      }
      this.removed++;
    }

  }

}
