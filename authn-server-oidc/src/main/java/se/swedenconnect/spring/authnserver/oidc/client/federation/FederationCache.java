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
import java.time.Duration;
import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * Where resolved clients are kept between requests.
 * <p>
 * The store is pluggable so that the nodes of a deployment can share it. The library ships an
 * {@link InMemoryFederationCache} and a {@link RedisFederationCache}.
 * </p>
 * <p>
 * The cache is also where the shared state of the background jobs that work on it is kept: the lookup counts that the
 * {@link FederationCacheRefresher} works from, and the lock that makes the jobs run on one node at a time. A cache
 * kept in the memory of one node keeps them there too.
 * </p>
 * <p>
 * An entry that has expired is never handed out. An implementation may drop it when it is asked for, or leave that to
 * the store.
 * </p>
 *
 * @author Martin Lindström
 */
public interface FederationCache {

  /**
   * Gets the entry for a client.
   *
   * @param clientId the {@code client_id} of the client
   * @return a {@link CachedClientRecord}, or {@code null} if the cache holds no valid entry for the client
   */
  @Nullable CachedClientRecord get(final @NonNull String clientId);

  /**
   * Puts an entry in the cache, replacing any entry already held for the same client.
   *
   * @param record the entry
   */
  void put(final @NonNull CachedClientRecord record);

  /**
   * Gets the valid entries of the cache. It is used by the background jobs that go through the cached clients, such
   * as the {@link TrustMarkStatusChecker}.
   *
   * @return the valid entries
   */
  @NonNull Collection<CachedClientRecord> getEntries();

  /**
   * Removes the entry for a client.
   *
   * @param clientId the {@code client_id} of the client
   */
  void remove(final @NonNull String clientId);

  /**
   * Creates the object that counts how often each client is looked up. The default keeps the counts in memory, in an
   * {@link InMemoryLookupTracker}.
   *
   * @param maximumTrackedClients the largest number of clients that are counted
   * @param period the period that lookups are counted within
   * @param clock the clock to use
   * @return a {@link LookupTracker}
   */
  default @NonNull LookupTracker createLookupTracker(final int maximumTrackedClients, final @NonNull Duration period,
      final @NonNull Clock clock) {
    return new InMemoryLookupTracker(maximumTrackedClients, period, clock);
  }

  /**
   * Gets the lock that the background jobs working on the cache use, so that a round runs on one node at a time. The
   * default is {@link JobLock#LOCAL}, which is always granted.
   *
   * @return a {@link JobLock}
   */
  default @NonNull JobLock getJobLock() {
    return JobLock.LOCAL;
  }

}
