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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link LookupTracker} that keeps the counts in Redis, so that the counts of all nodes add up.
 * <p>
 * The count of a client is the key {@code <prefix>:oidc:federation-lookups:<client_id>}. It is counted up on the Redis
 * server and expires when its period has passed, so a client that is looked up after that starts over. The key
 * {@code <prefix>:oidc:federation-lookups} lists the clients that are counted, ordered by when they were last asked
 * for, and holds at most the configured number of clients.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisLookupTracker implements LookupTracker {

  /** Counts a lookup, and starts the period at the first one. */
  private static final RedisScript<Long> INCREMENT = new DefaultRedisScript<>("""
      local count = redis.call('INCR', KEYS[1])
      if count == 1 then
        redis.call('PEXPIRE', KEYS[1], ARGV[1])
      end
      return count
      """, Long.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The largest number of clients that are counted. */
  private final int maximumTrackedClients;

  /** The period that lookups are counted within. */
  private final Duration period;

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   * @param maximumTrackedClients the largest number of clients that are counted
   * @param period the period that lookups are counted within
   * @param clock the clock to use
   */
  public RedisLookupTracker(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix,
      final int maximumTrackedClients, final @NonNull Duration period, final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    if (maximumTrackedClients < 1) {
      throw new IllegalArgumentException("maximumTrackedClients must be a positive number");
    }
    this.maximumTrackedClients = maximumTrackedClients;
    this.period = Objects.requireNonNull(period, "period must not be null");
    if (period.toMillis() < 1) {
      throw new IllegalArgumentException("period must be a positive duration");
    }
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void record(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    this.redisTemplate.execute(INCREMENT, List.of(this.countKey(clientId)), String.valueOf(this.period.toMillis()));

    final String indexKey = this.indexKey();
    this.redisTemplate.opsForZSet().add(indexKey, clientId, this.clock.instant().toEpochMilli());
    this.redisTemplate.opsForZSet().removeRange(indexKey, 0, -(this.maximumTrackedClients + 1L));
    this.redisTemplate.expire(indexKey, this.period);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getFrequentClients(final int minimumLookups, final int maximum) {
    final String indexKey = this.indexKey();
    final Instant periodStart = this.clock.instant().minus(this.period);
    this.redisTemplate.opsForZSet().removeRangeByScore(indexKey, Double.NEGATIVE_INFINITY, periodStart.toEpochMilli());
    final Set<String> clientIds = this.redisTemplate.opsForZSet().range(indexKey, 0, -1);
    if (clientIds == null || clientIds.isEmpty()) {
      return List.of();
    }
    final List<String> ids = new ArrayList<>(clientIds);
    final List<String> counts = this.redisTemplate.opsForValue().multiGet(ids.stream().map(this::countKey).toList());
    if (counts == null) {
      return List.of();
    }
    final List<Map.Entry<String, Long>> qualifying = new ArrayList<>();
    for (int i = 0; i < ids.size() && i < counts.size(); i++) {
      final String count = counts.get(i);
      if (count != null && Long.parseLong(count) >= minimumLookups) {
        qualifying.add(Map.entry(ids.get(i), Long.parseLong(count)));
      }
    }
    return qualifying.stream()
        .sorted(Comparator.comparingLong((final Map.Entry<String, Long> e) -> e.getValue()).reversed())
        .limit(maximum)
        .map(Map.Entry::getKey)
        .toList();
  }

  /**
   * Gets the key of the count of a client.
   *
   * @param clientId the {@code client_id}
   * @return the key
   */
  private @NonNull String countKey(final @NonNull String clientId) {
    return this.keyPrefix + ":oidc:federation-lookups:" + clientId;
  }

  /**
   * Gets the key of the list of the clients that are counted.
   *
   * @return the key
   */
  private @NonNull String indexKey() {
    return this.keyPrefix + ":oidc:federation-lookups";
  }

}
