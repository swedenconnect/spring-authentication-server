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
package se.swedenconnect.spring.authnserver.autoconfigure.storage;

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * What the Redis stores of the server are created from: the Redis template and the key prefix.
 *
 * @author Martin Lindström
 */
public class RedisStorage {

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /**
   * Constructor.
   *
   * @param connectionFactory the Redis connection factory
   * @param keyPrefix the key prefix
   */
  public RedisStorage(final @NonNull RedisConnectionFactory connectionFactory, final @NonNull String keyPrefix) {
    this.redisTemplate = new StringRedisTemplate(
        Objects.requireNonNull(connectionFactory, "connectionFactory must not be null"));
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
  }

  /**
   * Gets the Redis template.
   *
   * @return the Redis template
   */
  public @NonNull StringRedisTemplate getRedisTemplate() {
    return this.redisTemplate;
  }

  /**
   * Gets the key prefix.
   *
   * @return the key prefix
   */
  public @NonNull String getKeyPrefix() {
    return this.keyPrefix;
  }

}
