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
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * A {@link JobLock} kept in Redis, so that a job runs on one node of a deployment at a time.
 * <p>
 * The lock of a job is the key {@code <prefix>:lock:<job>}, holding the identity of the node that holds it, and it
 * expires when the lease has passed. Getting the lock, or renewing it for the node that holds it, is one script on the
 * Redis server, so two nodes that ask at the same time cannot both get it.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisJobLock implements JobLock {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisJobLock.class);

  /** Sets the lock if it is free, or renews it if this node holds it. */
  private static final RedisScript<Long> ACQUIRE = new DefaultRedisScript<>("""
      if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then
        return 1
      end
      if redis.call('GET', KEYS[1]) == ARGV[1] then
        redis.call('PEXPIRE', KEYS[1], ARGV[2])
        return 1
      end
      return 0
      """, Long.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The identity of this node. */
  private final String nodeId = UUID.randomUUID().toString();

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisJobLock(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
  }

  /** {@inheritDoc} */
  @Override
  public boolean tryAcquire(final @NonNull String job, final @NonNull Duration lease) {
    Objects.requireNonNull(job, "job must not be null");
    if (Objects.requireNonNull(lease, "lease must not be null").toMillis() < 1) {
      throw new IllegalArgumentException("lease must be at least one millisecond");
    }
    final Long result = this.redisTemplate.execute(ACQUIRE, List.of(this.keyPrefix + ":lock:" + job),
        this.nodeId, String.valueOf(lease.toMillis()));
    final boolean acquired = result != null && result == 1L;
    log.trace("Lock for job '{}' {} by node {}", job, acquired ? "held" : "not granted", this.nodeId);
    return acquired;
  }

}
