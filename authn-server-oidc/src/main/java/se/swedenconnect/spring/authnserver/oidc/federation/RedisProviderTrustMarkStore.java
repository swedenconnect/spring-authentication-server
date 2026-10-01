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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.job.JobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link ProviderTrustMarkStore} that keeps the state in Redis, so that all nodes of a deployment publish the same
 * trust marks and report the same failures, while one node at a time fetches them, see {@link #getJobLock()}.
 * <p>
 * The state of a trust mark type is the key {@code <prefix>:oidc:provider-trust-mark:<type>}, holding the state as
 * JSON. It expires {@value #RETENTION_DAYS} day after the trust mark expires, or after the latest attempt when there is
 * no valid trust mark, so that the failure state outlives the trust mark. A trust mark without {@code exp} is kept
 * until it is replaced.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisProviderTrustMarkStore implements ProviderTrustMarkStore {

  /** The number of days that the state is kept after the trust mark has expired. */
  public static final int RETENTION_DAYS = 1;

  /** How long the state is kept after the trust mark has expired. */
  private static final Duration RETENTION = Duration.ofDays(RETENTION_DAYS);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The clock. */
  private final Clock clock;

  /** The lock that decides which node fetches the trust marks. */
  private final JobLock jobLock;

  /**
   * Constructor using the default key prefix, {@value RedisKeys#DEFAULT_PREFIX}.
   *
   * @param redisTemplate the Redis template
   */
  public RedisProviderTrustMarkStore(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisProviderTrustMarkStore(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix) {
    this(redisTemplate, keyPrefix, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   * @param clock the clock to use
   */
  public RedisProviderTrustMarkStore(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix, final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.jobLock = new RedisJobLock(redisTemplate, keyPrefix);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Entry get(final @NonNull String trustMarkType) {
    final String key = this.key(trustMarkType);
    return RedisJson.read(key, this.redisTemplate.opsForValue().get(key), Entry.class);
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull String trustMarkType, final @NonNull Entry entry) {
    Objects.requireNonNull(entry, "entry must not be null");
    final String key = this.key(trustMarkType);
    final Instant now = this.clock.instant();
    if (entry.trustMark() != null && entry.expiresAt() == null) {
      this.redisTemplate.opsForValue().set(key, RedisJson.write(entry));
      return;
    }
    final Instant base = entry.isValid(now) ? Objects.requireNonNull(entry.expiresAt()) : now;
    this.redisTemplate.opsForValue().set(key, RedisJson.write(entry), RedisKeys.timeToLive(base.plus(RETENTION), now));
  }

  /**
   * Gets a {@link RedisJobLock}, so that one node at a time fetches the trust marks.
   */
  @Override
  public @NonNull JobLock getJobLock() {
    return this.jobLock;
  }

  /**
   * Gets the key of a trust mark type.
   *
   * @param trustMarkType the trust mark type
   * @return the key
   */
  private @NonNull String key(final @NonNull String trustMarkType) {
    return this.keyPrefix + ":oidc:provider-trust-mark:"
        + Objects.requireNonNull(trustMarkType, "trustMarkType must not be null");
  }

}
