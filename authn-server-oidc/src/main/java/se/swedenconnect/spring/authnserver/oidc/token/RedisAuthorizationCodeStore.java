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

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.redis.connection.RedisStringCommands;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.types.Expiration;

import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * An {@link AuthorizationCodeStore} that keeps the codes in Redis, so that all nodes of a deployment share them.
 * <p>
 * A code is the key {@code <prefix>:oidc:code:<code>}, holding the code as JSON. That it has been used is the key
 * {@code <prefix>:oidc:code-use:<code>}, holding the access token issued for it once there is one. Both expire when the
 * code is no longer retained. Marking a code as used is one operation on the Redis server (SET NX), so when two nodes
 * redeem the same code at the same time, only one of them gets it.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisAuthorizationCodeStore implements AuthorizationCodeStore {

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
  public RedisAuthorizationCodeStore(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisAuthorizationCodeStore(final @NonNull StringRedisTemplate redisTemplate,
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
  public RedisAuthorizationCodeStore(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix, final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void save(final @NonNull AuthorizationCodeData code) {
    this.redisTemplate.opsForValue().set(this.codeKey(code.code()), RedisJson.write(code),
        RedisKeys.timeToLive(code.retainUntil(), this.clock.instant()));
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Redemption redeem(final @NonNull String code) {
    final String codeKey = this.codeKey(code);
    final AuthorizationCodeData data =
        RedisJson.read(codeKey, this.redisTemplate.opsForValue().get(codeKey), AuthorizationCodeData.class);
    final Instant now = this.clock.instant();
    if (data == null || !now.isBefore(data.retainUntil())) {
      return null;
    }
    final String useKey = this.useKey(code);
    final String used = this.redisTemplate.opsForValue().get(useKey);
    if (used != null) {
      return replay(data, used);
    }
    if (data.isExpired(now)) {
      return null;
    }
    final Boolean first = this.redisTemplate.opsForValue().setIfAbsent(useKey, "",
        RedisKeys.timeToLive(data.retainUntil(), now));
    if (Boolean.TRUE.equals(first)) {
      return new Redemption(data, false, null);
    }
    return replay(data, Objects.requireNonNullElse(this.redisTemplate.opsForValue().get(useKey), ""));
  }

  /** {@inheritDoc} */
  @Override
  public void registerAccessToken(final @NonNull String code, final @NonNull String accessToken) {
    final byte[] key = this.useKey(code).getBytes(StandardCharsets.UTF_8);
    final byte[] value = accessToken.getBytes(StandardCharsets.UTF_8);
    this.redisTemplate.execute((RedisCallback<Boolean>) connection -> connection.stringCommands()
        .set(key, value, Expiration.keepTtl(), RedisStringCommands.SetOption.ifPresent()));
  }

  /**
   * Creates the redemption of a code that has been used before.
   *
   * @param data the code
   * @param accessToken the access token issued for the code, or an empty string if none has been issued
   * @return a {@link Redemption}
   */
  private static @NonNull Redemption replay(final @NonNull AuthorizationCodeData data,
      final @NonNull String accessToken) {
    return new Redemption(data, true, accessToken.isEmpty() ? null : accessToken);
  }

  /**
   * Gets the key of a code.
   *
   * @param code the code value
   * @return the key
   */
  private @NonNull String codeKey(final @NonNull String code) {
    return this.keyPrefix + ":oidc:code:" + code;
  }

  /**
   * Gets the key that tells that a code has been used.
   *
   * @param code the code value
   * @return the key
   */
  private @NonNull String useKey(final @NonNull String code) {
    return this.keyPrefix + ":oidc:code-use:" + code;
  }

}
