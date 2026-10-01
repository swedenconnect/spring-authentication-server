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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link ClientAssertionReplayCache} that keeps the values in Redis, so that all nodes of a deployment share them.
 * <p>
 * A value is the key {@code <prefix>:oidc:client-assertion:<client_id> <jti>}, which expires with the assertion.
 * Registering a value is one operation on the Redis server (SET NX), so when two nodes register the same value at the
 * same time, only one of them is told that it is new.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisClientAssertionReplayCache implements ClientAssertionReplayCache {

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor using the default key prefix, {@value RedisKeys#DEFAULT_PREFIX}.
   *
   * @param redisTemplate the Redis template
   */
  public RedisClientAssertionReplayCache(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisClientAssertionReplayCache(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix) {
    this(redisTemplate, keyPrefix, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   * @param clock the clock
   */
  public RedisClientAssertionReplayCache(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix, final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public boolean register(final @NonNull String clientId, final @NonNull String jti,
      final @NonNull Instant expiresAt) {
    return Boolean.TRUE.equals(this.redisTemplate.opsForValue().setIfAbsent(
        "%s:oidc:client-assertion:%s %s".formatted(this.keyPrefix, clientId, jti), "",
        RedisKeys.timeToLive(expiresAt, this.clock.instant())));
  }

}
