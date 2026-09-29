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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Duration;
import java.util.Objects;

/**
 * How resolved clients are cached.
 *
 * @param maximumAge how long an entry may live at the most, regardless of what the resolve response says, or
 *          {@code null} for no limit. No limit is the default
 * @param notFoundTimeToLive how long the answer that the resolver does not know a client is kept, so that repeated
 *          requests for the same unknown {@code client_id} do not each reach the resolver. A resolver that fails is
 *          never cached
 * @param refresh how frequently used clients are kept fresh
 * @author Martin Lindström
 */
public record FederationCacheSettings(
    @Nullable Duration maximumAge,
    @Nonnull Duration notFoundTimeToLive,
    @Nonnull RefreshSettings refresh) {

  /** The default time that the answer that a client is unknown is kept: one minute. */
  public static final Duration DEFAULT_NOT_FOUND_TIME_TO_LIVE = Duration.ofMinutes(1);

  /**
   * Constructor.
   *
   * @param maximumAge how long an entry may live at the most, or {@code null}
   * @param notFoundTimeToLive how long the answer that the resolver does not know a client is kept
   * @param refresh how frequently used clients are kept fresh
   */
  public FederationCacheSettings {
    Objects.requireNonNull(notFoundTimeToLive, "notFoundTimeToLive must not be null");
    Objects.requireNonNull(refresh, "refresh must not be null");
    if (maximumAge != null && (maximumAge.isZero() || maximumAge.isNegative())) {
      throw new IllegalArgumentException("maximumAge must be a positive duration");
    }
    if (notFoundTimeToLive.isZero() || notFoundTimeToLive.isNegative()) {
      throw new IllegalArgumentException("notFoundTimeToLive must be a positive duration");
    }
  }

  /**
   * Creates the default settings: no maximum age and no background refresh.
   *
   * @return a {@link FederationCacheSettings}
   */
  public static @Nonnull FederationCacheSettings defaults() {
    return new FederationCacheSettings(null, DEFAULT_NOT_FOUND_TIME_TO_LIVE, RefreshSettings.disabled());
  }

  /**
   * How the background job that refreshes cache entries before they expire works.
   * <p>
   * The job is off by default. Only clients that are used often are refreshed, so that a request for such a client
   * never waits for the resolver. A client that is used rarely is not refreshed; it is resolved again the next time
   * it is asked for after its entry has expired.
   * </p>
   *
   * @param enabled whether the job runs
   * @param interval how often the job runs
   * @param refreshAhead how long before an entry expires that it is refreshed
   * @param minimumLookups how many times a client must have been looked up within {@code lookupPeriod} to qualify
   * @param lookupPeriod the period that lookups are counted within
   * @param maximumClients the largest number of clients that one run refreshes
   * @param maximumTrackedClients the largest number of clients that lookups are counted for. The count of the client
   *          that has not been asked for in the longest time is dropped when the limit is reached, which is what
   *          keeps the counting from growing without limit
   */
  public record RefreshSettings(
      boolean enabled,
      @Nonnull Duration interval,
      @Nonnull Duration refreshAhead,
      int minimumLookups,
      @Nonnull Duration lookupPeriod,
      int maximumClients,
      int maximumTrackedClients) {

    /** The default interval between two runs of the job: one minute. */
    public static final Duration DEFAULT_INTERVAL = Duration.ofMinutes(1);

    /** The default time before an entry expires that it is refreshed: five minutes. */
    public static final Duration DEFAULT_REFRESH_AHEAD = Duration.ofMinutes(5);

    /** The default number of lookups that makes a client qualify: ten. */
    public static final int DEFAULT_MINIMUM_LOOKUPS = 10;

    /** The default period that lookups are counted within: ten minutes. */
    public static final Duration DEFAULT_LOOKUP_PERIOD = Duration.ofMinutes(10);

    /** The default largest number of clients that one run refreshes: one hundred. */
    public static final int DEFAULT_MAXIMUM_CLIENTS = 100;

    /** The default largest number of clients that lookups are counted for: one thousand. */
    public static final int DEFAULT_MAXIMUM_TRACKED_CLIENTS = 1000;

    /**
     * Constructor.
     *
     * @param enabled whether the job runs
     * @param interval how often the job runs
     * @param refreshAhead how long before an entry expires that it is refreshed
     * @param minimumLookups how many times a client must have been looked up to qualify
     * @param lookupPeriod the period that lookups are counted within
     * @param maximumClients the largest number of clients that one run refreshes
     * @param maximumTrackedClients the largest number of clients that lookups are counted for
     */
    public RefreshSettings {
      Objects.requireNonNull(interval, "interval must not be null");
      Objects.requireNonNull(refreshAhead, "refreshAhead must not be null");
      Objects.requireNonNull(lookupPeriod, "lookupPeriod must not be null");
      if (interval.isZero() || interval.isNegative()) {
        throw new IllegalArgumentException("interval must be a positive duration");
      }
      if (refreshAhead.isNegative()) {
        throw new IllegalArgumentException("refreshAhead must not be negative");
      }
      if (lookupPeriod.isZero() || lookupPeriod.isNegative()) {
        throw new IllegalArgumentException("lookupPeriod must be a positive duration");
      }
      if (minimumLookups < 1) {
        throw new IllegalArgumentException("minimumLookups must be a positive number");
      }
      if (maximumClients < 1) {
        throw new IllegalArgumentException("maximumClients must be a positive number");
      }
      if (maximumTrackedClients < 1) {
        throw new IllegalArgumentException("maximumTrackedClients must be a positive number");
      }
    }

    /**
     * Creates settings where the job does not run, which is the default.
     *
     * @return a {@link RefreshSettings}
     */
    public static @Nonnull RefreshSettings disabled() {
      return enabled(false);
    }

    /**
     * Creates settings with the default values.
     *
     * @param enabled whether the job runs
     * @return a {@link RefreshSettings}
     */
    public static @Nonnull RefreshSettings enabled(final boolean enabled) {
      return new RefreshSettings(enabled, DEFAULT_INTERVAL, DEFAULT_REFRESH_AHEAD, DEFAULT_MINIMUM_LOOKUPS,
          DEFAULT_LOOKUP_PERIOD, DEFAULT_MAXIMUM_CLIENTS, DEFAULT_MAXIMUM_TRACKED_CLIENTS);
    }

  }

}
