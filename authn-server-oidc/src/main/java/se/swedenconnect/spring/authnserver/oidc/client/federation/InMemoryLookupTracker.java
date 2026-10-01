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

import java.io.Serial;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A {@link LookupTracker} that keeps the counts in the memory of one node.
 * <p>
 * Counting is bounded: at most a configured number of clients are counted, and the count of the client that has not
 * been asked for in the longest time is dropped when a new client arrives. Counts are kept per period; a client that
 * goes quiet for a whole period starts over.
 * </p>
 *
 * @author Martin Lindström
 */
public class InMemoryLookupTracker implements LookupTracker {

  /** The period that lookups are counted within. */
  private final Duration period;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The counts, keyed by {@code client_id}, in the order the clients were last asked for. */
  private final Map<String, Count> counts;

  /**
   * Constructor.
   *
   * @param maximumTrackedClients the largest number of clients that are counted
   * @param period the period that lookups are counted within
   */
  public InMemoryLookupTracker(final int maximumTrackedClients, final @NonNull Duration period) {
    this(maximumTrackedClients, period, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param maximumTrackedClients the largest number of clients that are counted
   * @param period the period that lookups are counted within
   * @param clock the clock to use
   */
  public InMemoryLookupTracker(final int maximumTrackedClients, final @NonNull Duration period,
      final @NonNull Clock clock) {
    if (maximumTrackedClients < 1) {
      throw new IllegalArgumentException("maximumTrackedClients must be a positive number");
    }
    this.period = Objects.requireNonNull(period, "period must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.counts = new BoundedCounts(maximumTrackedClients);
  }

  /** {@inheritDoc} */
  @Override
  public void record(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final Instant now = this.clock.instant();
    synchronized (this.counts) {
      final Count count = this.counts.get(clientId);
      if (count == null || !now.isBefore(count.periodStart.plus(this.period))) {
        this.counts.put(clientId, new Count(now));
      }
      else {
        count.lookups++;
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getFrequentClients(final int minimumLookups, final int maximum) {
    final Instant now = this.clock.instant();
    final List<Map.Entry<String, Count>> qualifying = new ArrayList<>();
    synchronized (this.counts) {
      for (final Map.Entry<String, Count> entry : this.counts.entrySet()) {
        final Count count = entry.getValue();
        if (count.lookups >= minimumLookups && now.isBefore(count.periodStart.plus(this.period))) {
          qualifying.add(Map.entry(entry.getKey(), new Count(count)));
        }
      }
    }
    return qualifying.stream()
        .sorted(Comparator.comparingInt((final Map.Entry<String, Count> e) -> e.getValue().lookups).reversed())
        .limit(maximum)
        .map(Map.Entry::getKey)
        .toList();
  }

  /**
   * Gets the number of clients that lookups are currently counted for.
   *
   * @return the number of clients
   */
  public int size() {
    synchronized (this.counts) {
      return this.counts.size();
    }
  }

  /**
   * The counts, holding at most a set number of clients. The count of the client that has not been asked for in the
   * longest time is dropped when a new client arrives.
   */
  private static final class BoundedCounts extends LinkedHashMap<String, Count> {

    @Serial
    private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

    /** The largest number of clients that are counted. */
    private final int maximum;

    /**
     * Constructor.
     *
     * @param maximum the largest number of clients that are counted
     */
    private BoundedCounts(final int maximum) {
      super(16, 0.75f, true);
      this.maximum = maximum;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean removeEldestEntry(final Map.Entry<String, Count> eldest) {
      return this.size() > this.maximum;
    }

  }

  /**
   * The lookups of one client within one period.
   */
  private static final class Count {

    /** When the period started. */
    private final Instant periodStart;

    /** The number of lookups within the period. */
    private int lookups;

    /**
     * Constructor recording the first lookup of a period.
     *
     * @param periodStart when the period started
     */
    private Count(final Instant periodStart) {
      this.periodStart = periodStart;
      this.lookups = 1;
    }

    /**
     * Copy constructor.
     *
     * @param other the count to copy
     */
    private Count(final Count other) {
      this.periodStart = other.periodStart;
      this.lookups = other.lookups;
    }

  }

}
