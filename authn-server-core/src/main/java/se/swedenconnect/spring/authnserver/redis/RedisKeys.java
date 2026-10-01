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
package se.swedenconnect.spring.authnserver.redis;

import java.time.Duration;
import java.time.Instant;

import org.jspecify.annotations.NonNull;
import org.springframework.util.StringUtils;

/**
 * Key names and expiry for the entries that the server keeps in Redis.
 * <p>
 * Every key starts with a configurable prefix, {@value #DEFAULT_PREFIX} by default, so that two deployments that share
 * one Redis are kept apart.
 * </p>
 *
 * @author Martin Lindström
 */
public final class RedisKeys {

  /** The default key prefix. */
  public static final String DEFAULT_PREFIX = "authn-server";

  /**
   * Checks a key prefix.
   *
   * @param prefix the prefix
   * @return the prefix
   * @throws IllegalArgumentException if the prefix is {@code null} or empty
   */
  public static @NonNull String checkPrefix(final String prefix) {
    if (!StringUtils.hasText(prefix)) {
      throw new IllegalArgumentException("The Redis key prefix must be set and not empty");
    }
    return prefix;
  }

  /**
   * Gets the time to live of an entry that expires at a given time. An entry that has already expired gets one
   * millisecond, since Redis does not accept a time to live that is not positive.
   *
   * @param expiresAt when the entry expires
   * @param now the current time
   * @return the time to live
   */
  public static @NonNull Duration timeToLive(final @NonNull Instant expiresAt, final @NonNull Instant now) {
    final Duration ttl = Duration.between(now, expiresAt);
    return ttl.compareTo(Duration.ofMillis(1)) < 0 ? Duration.ofMillis(1) : ttl;
  }

  // Hidden constructor
  private RedisKeys() {
  }

}
