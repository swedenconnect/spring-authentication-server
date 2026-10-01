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

import java.util.List;

import org.jspecify.annotations.NonNull;

/**
 * Counts how often each client is looked up, so that the background refresh job knows which clients are used often
 * enough to be worth refreshing.
 * <p>
 * Counts are kept per period: a client that has not been looked up for a whole period starts over. The number of
 * clients that are counted is bounded, and the client that has not been asked for in the longest time is dropped
 * first.
 * </p>
 * <p>
 * The tracker is created by the {@link FederationCache}, see
 * {@link FederationCache#createLookupTracker(int, java.time.Duration, java.time.Clock)}, so that the counts are kept
 * where the cache is: in the memory of one node, or shared by all nodes.
 * </p>
 *
 * @author Martin Lindström
 */
public interface LookupTracker {

  /**
   * Records that a client was looked up.
   *
   * @param clientId the {@code client_id} of the client
   */
  void record(final @NonNull String clientId);

  /**
   * Gets the clients that have been looked up at least {@code minimumLookups} times within the current period, the
   * one that was looked up the most first, and at most {@code maximum} of them.
   *
   * @param minimumLookups the number of lookups that makes a client qualify
   * @param maximum the largest number of clients to return
   * @return the {@code client_id}s of the qualifying clients
   */
  @NonNull List<String> getFrequentClients(final int minimumLookups, final int maximum);

}
