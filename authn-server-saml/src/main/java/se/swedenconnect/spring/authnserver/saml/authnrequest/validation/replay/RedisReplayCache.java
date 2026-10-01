/*
 * Copyright 2023-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay;

import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link ReplayCache} that keeps the seen message IDs in Redis, so that all nodes of a deployment share it.
 * <p>
 * Each message ID is the key {@code <prefix>:saml:replay:<context>:<id>}, which expires when the ID no longer needs to
 * be remembered.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisReplayCache implements ReplayCache {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisReplayCache.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /**
   * Constructor using the default key prefix, {@value RedisKeys#DEFAULT_PREFIX}.
   *
   * @param redisTemplate the Redis template
   */
  public RedisReplayCache(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisReplayCache(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
  }

  /**
   * Checks the key and adds it if it is not present.
   */
  @Override
  public boolean check(final @NonNull String context, final @NonNull String key, final @NonNull Instant expires) {

    // Adding the key if it is not present is one operation on the Redis server (SET NX), meaning that only one of any
    // number of concurrent calls for the same key, from any node, gets true.
    //
    final Boolean added = this.redisTemplate.opsForValue().setIfAbsent(
        "%s:saml:replay:%s:%s".formatted(this.keyPrefix, context, key), "",
        RedisKeys.timeToLive(expires, Instant.now()));
    if (added == null) {
      log.warn("Redis did not report whether key '{}' was added to the replay cache ({}), returning false",
          key, context);
      return false;
    }
    if (added) {
      log.trace("Key '{}' was not present in Redis replay cache ({}), adding it", key, context);
      return true;
    }
    log.debug("Key '{}' was present in Redis replay cache ({})", key, context);
    return false;
  }

}
