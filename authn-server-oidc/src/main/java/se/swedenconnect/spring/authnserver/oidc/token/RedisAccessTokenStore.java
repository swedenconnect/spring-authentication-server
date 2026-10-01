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
import org.jspecify.annotations.Nullable;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * An {@link AccessTokenStore} that keeps the tokens in Redis, so that all nodes of a deployment share them.
 * <p>
 * A token is the key {@code <prefix>:oidc:access-token:<value>}, holding the token as JSON. That a single use token has
 * been used is the key {@code <prefix>:oidc:access-token-use:<value>}. Both expire with the token. Marking a token as
 * used is one operation on the Redis server (SET NX), so when two nodes use the same single use token at the same
 * time, only one of them succeeds.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisAccessTokenStore implements AccessTokenStore {

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
  public RedisAccessTokenStore(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisAccessTokenStore(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix) {
    this(redisTemplate, keyPrefix, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   * @param clock the clock
   */
  public RedisAccessTokenStore(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix,
      final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void save(final @NonNull AccessTokenData token) {
    this.redisTemplate.opsForValue().set(this.tokenKey(token.value()), RedisJson.write(token),
        RedisKeys.timeToLive(token.expiresAt(), this.clock.instant()));
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable AccessTokenData get(final @NonNull String value) {
    final AccessTokenData token = this.read(value);
    if (token == null || token.isExpired(this.clock.instant())) {
      return null;
    }
    if (token.singleUse() && Boolean.TRUE.equals(this.redisTemplate.hasKey(this.useKey(value)))) {
      return null;
    }
    return token;
  }

  /** {@inheritDoc} */
  @Override
  public boolean markUsed(final @NonNull String value) {
    final AccessTokenData token = this.read(value);
    final Instant now = this.clock.instant();
    if (token == null || token.isExpired(now)) {
      return false;
    }
    if (!token.singleUse()) {
      return true;
    }
    return Boolean.TRUE.equals(this.redisTemplate.opsForValue().setIfAbsent(this.useKey(value), "",
        RedisKeys.timeToLive(token.expiresAt(), now)));
  }

  /** {@inheritDoc} */
  @Override
  public void revoke(final @NonNull String value) {
    this.redisTemplate.delete(this.tokenKey(value));
    this.redisTemplate.delete(this.useKey(value));
  }

  /**
   * Reads a token.
   *
   * @param value the token value
   * @return the token, or {@code null} if it is not known
   */
  private @Nullable AccessTokenData read(final @NonNull String value) {
    final String key = this.tokenKey(value);
    return RedisJson.read(key, this.redisTemplate.opsForValue().get(key), AccessTokenData.class);
  }

  /**
   * Gets the key of a token.
   *
   * @param value the token value
   * @return the key
   */
  private @NonNull String tokenKey(final @NonNull String value) {
    return this.keyPrefix + ":oidc:access-token:" + value;
  }

  /**
   * Gets the key that tells that a single use token has been used.
   *
   * @param value the token value
   * @return the key
   */
  private @NonNull String useKey(final @NonNull String value) {
    return this.keyPrefix + ":oidc:access-token-use:" + value;
  }

}
