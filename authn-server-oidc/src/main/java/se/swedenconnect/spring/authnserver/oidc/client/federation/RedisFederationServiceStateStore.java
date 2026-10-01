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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link FederationServiceStateStore} that keeps the state in Redis, so that every node of a deployment reports the
 * same.
 * <p>
 * The state of a service is the hash {@code <prefix>:oidc:federation-service:<type>|<id>}, and the set
 * {@code <prefix>:oidc:federation-services} lists them. A call is recorded by one script on the Redis server, so that
 * calls made at the same time by several nodes are all counted. The state expires {@value #RETENTION_DAYS} days after
 * the latest call.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisFederationServiceStateStore implements FederationServiceStateStore {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisFederationServiceStateStore.class);

  /** The number of days that the state of a service is kept after the latest call. */
  public static final int RETENTION_DAYS = 7;

  /** Records a call. */
  private static final RedisScript<Long> RECORD = new DefaultRedisScript<>("""
      local latest = tonumber(redis.call('HGET', KEYS[1], 'latest-call') or '0')
      if tonumber(ARGV[4]) >= latest then
        redis.call('HSET', KEYS[1], 'type', ARGV[1], 'id', ARGV[2], 'latest-outcome', ARGV[3], 'latest-call', ARGV[4])
      end
      if ARGV[5] == '1' then
        local failure = tonumber(redis.call('HGET', KEYS[1], 'last-failure') or '0')
        if tonumber(ARGV[4]) >= failure then
          redis.call('HSET', KEYS[1], 'last-failure', ARGV[4], 'last-failure-outcome', ARGV[3],
            'last-failure-error', ARGV[6])
        end
        redis.call('HINCRBY', KEYS[1], 'failures', 1)
      else
        redis.call('HSET', KEYS[1], 'failures', 0)
      end
      redis.call('PEXPIRE', KEYS[1], ARGV[7])
      redis.call('SADD', KEYS[2], KEYS[1])
      redis.call('PEXPIRE', KEYS[2], ARGV[7])
      return 1
      """, Long.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisFederationServiceStateStore(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
  }

  /** {@inheritDoc} */
  @Override
  public void record(final @NonNull FederationCallEvent event) {
    Objects.requireNonNull(event, "event must not be null");
    final String key = this.keyPrefix + ":oidc:federation-service:" + event.getServiceType() + "|"
        + event.getServiceId();
    this.redisTemplate.execute(RECORD, List.of(key, this.indexKey()),
        event.getServiceType().name(), event.getServiceId(), event.getOutcome().name(),
        String.valueOf(event.getTime().toEpochMilli()),
        event.getOutcome() == FederationCallEvent.Outcome.SUCCESS ? "0" : "1",
        Objects.requireNonNullElse(event.getError(), ""),
        String.valueOf(Duration.ofDays(RETENTION_DAYS).toMillis()));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<FederationServiceState> getStates() {
    final Set<String> keys = this.redisTemplate.opsForSet().members(this.indexKey());
    if (keys == null) {
      return List.of();
    }
    final List<FederationServiceState> states = new ArrayList<>();
    for (final String key : keys) {
      final Map<Object, Object> hash = this.redisTemplate.opsForHash().entries(key);
      if (hash.isEmpty()) {
        this.redisTemplate.opsForSet().remove(this.indexKey(), key);
        continue;
      }
      final FederationServiceState state = toState(key, hash);
      if (state != null) {
        states.add(state);
      }
    }
    states.sort(Comparator.comparing(FederationServiceState::type).thenComparing(FederationServiceState::id));
    return states;
  }

  /**
   * Creates the state of a service from its hash.
   *
   * @param key the key of the hash, for the log
   * @param hash the hash
   * @return the state, or {@code null} if the hash cannot be read
   */
  private static @Nullable FederationServiceState toState(final @NonNull String key,
      final @NonNull Map<Object, Object> hash) {
    try {
      final String error = (String) hash.get("last-failure-error");
      return new FederationServiceState(
          FederationCallEvent.ServiceType.valueOf((String) hash.get("type")),
          (String) Objects.requireNonNull(hash.get("id")),
          FederationCallEvent.Outcome.valueOf((String) hash.get("latest-outcome")),
          instant(hash.get("latest-call")),
          hash.get("last-failure") != null ? instant(hash.get("last-failure")) : null,
          hash.get("last-failure-outcome") != null
              ? FederationCallEvent.Outcome.valueOf((String) hash.get("last-failure-outcome"))
              : null,
          error != null && !error.isEmpty() ? error : null,
          Integer.parseInt((String) hash.getOrDefault("failures", "0")));
    }
    catch (final RuntimeException e) {
      log.warn("The Redis entry '{}' does not hold a valid federation service state and is ignored: {}", key,
          e.getMessage());
      return null;
    }
  }

  /**
   * Reads a time written as milliseconds since the epoch.
   *
   * @param value the value
   * @return the time
   */
  private static @NonNull Instant instant(final @Nullable Object value) {
    return Instant.ofEpochMilli(Long.parseLong((String) Objects.requireNonNull(value)));
  }

  /**
   * Gets the key of the set that lists the services.
   *
   * @return the key
   */
  private @NonNull String indexKey() {
    return this.keyPrefix + ":oidc:federation-services";
  }

}
