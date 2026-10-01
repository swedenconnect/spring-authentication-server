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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.job.JobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link FederationCache} that keeps its entries in Redis, so that all nodes of a deployment share them.
 * <p>
 * An entry is the key {@code <prefix>:oidc:federation-cache:<client_id>}, holding the entry as JSON, and it expires
 * with the entry. The key {@code <prefix>:oidc:federation-cache-index} lists the entries, so that the background jobs
 * can go through them, and it expires with the last of them.
 * </p>
 * <p>
 * The lookup counts are kept in Redis too, by a {@link RedisLookupTracker}, so that the threshold of the refresh job
 * applies to the traffic of all nodes, and the background jobs use a {@link RedisJobLock}, so that a round runs on one
 * node at a time.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisFederationCache implements FederationCache {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisFederationCache.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The clock. */
  private final Clock clock;

  /** The lock of the background jobs. */
  private final JobLock jobLock;

  /**
   * Constructor using the default key prefix, {@value RedisKeys#DEFAULT_PREFIX}.
   *
   * @param redisTemplate the Redis template
   */
  public RedisFederationCache(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisFederationCache(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix) {
    this(redisTemplate, keyPrefix, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   * @param clock the clock to use
   */
  public RedisFederationCache(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix,
      final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.jobLock = new RedisJobLock(redisTemplate, keyPrefix);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable CachedClientRecord get(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final String key = this.entryKey(clientId);
    final CachedClientRecord record = this.toRecord(key, this.redisTemplate.opsForValue().get(key));
    return record == null || record.isExpired(this.clock.instant()) ? null : record;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull CachedClientRecord record) {
    Objects.requireNonNull(record, "record must not be null");
    final Instant now = this.clock.instant();
    this.redisTemplate.opsForValue().set(this.entryKey(record.clientId()), RedisJson.write(Entry.of(record)),
        RedisKeys.timeToLive(record.expiresAt(), now));

    final String indexKey = this.indexKey();
    final ZSetOperations<String, String> index = this.redisTemplate.opsForZSet();
    index.add(indexKey, record.clientId(), record.expiresAt().toEpochMilli());
    index.removeRangeByScore(indexKey, Double.NEGATIVE_INFINITY, now.toEpochMilli());
    final Set<ZSetOperations.TypedTuple<String>> last = index.reverseRangeWithScores(indexKey, 0, 0);
    if (last != null && !last.isEmpty()) {
      final Double score = last.iterator().next().getScore();
      if (score != null) {
        this.redisTemplate.expireAt(indexKey, Instant.ofEpochMilli(score.longValue()));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<CachedClientRecord> getEntries() {
    final Instant now = this.clock.instant();
    final Set<String> clientIds =
        this.redisTemplate.opsForZSet().rangeByScore(this.indexKey(), now.toEpochMilli() + 1, Double.POSITIVE_INFINITY);
    if (clientIds == null || clientIds.isEmpty()) {
      return List.of();
    }
    final List<String> keys = clientIds.stream().map(this::entryKey).toList();
    final List<String> values = this.redisTemplate.opsForValue().multiGet(keys);
    if (values == null) {
      return List.of();
    }
    final List<CachedClientRecord> records = new ArrayList<>();
    for (int i = 0; i < keys.size() && i < values.size(); i++) {
      final CachedClientRecord record = this.toRecord(keys.get(i), values.get(i));
      if (record != null && !record.isExpired(now)) {
        records.add(record);
      }
    }
    return records;
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    this.redisTemplate.delete(this.entryKey(clientId));
    this.redisTemplate.opsForZSet().remove(this.indexKey(), clientId);
  }

  /**
   * Creates a {@link RedisLookupTracker}, so that the lookup counts are shared by all nodes.
   */
  @Override
  public @NonNull LookupTracker createLookupTracker(final int maximumTrackedClients, final @NonNull Duration period,
      final @NonNull Clock clock) {
    return new RedisLookupTracker(this.redisTemplate, this.keyPrefix, maximumTrackedClients, period, clock);
  }

  /**
   * Gets a {@link RedisJobLock}, so that a round of a background job runs on one node at a time.
   */
  @Override
  public @NonNull JobLock getJobLock() {
    return this.jobLock;
  }

  /**
   * Reads an entry.
   *
   * @param key the key of the entry
   * @param json the JSON of the entry, or {@code null}
   * @return the entry, or {@code null} if there is none or it cannot be read
   */
  private @Nullable CachedClientRecord toRecord(final @NonNull String key, final @Nullable String json) {
    final Entry entry = RedisJson.read(key, json, Entry.class);
    if (entry == null) {
      return null;
    }
    try {
      return entry.toRecord();
    }
    catch (final ParseException | RuntimeException e) {
      log.warn("The Redis entry '{}' does not hold a valid cache entry and is ignored: {}", key, e.getMessage());
      return null;
    }
  }

  /**
   * Gets the key of the entry of a client.
   *
   * @param clientId the {@code client_id}
   * @return the key
   */
  private @NonNull String entryKey(final @NonNull String clientId) {
    return this.keyPrefix + ":oidc:federation-cache:" + clientId;
  }

  /**
   * Gets the key of the index of the entries.
   *
   * @return the key
   */
  private @NonNull String indexKey() {
    return this.keyPrefix + ":oidc:federation-cache-index";
  }

  /**
   * A cache entry as it is written to Redis. The client metadata is kept as the JSON that the metadata gives.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata as a JSON object, or {@code null}
   * @param trustMarkTypes the trust mark types of the resolve response
   * @param onDemandTrustMarks the trust marks that have been asked for on demand
   * @param expiresAt when the entry is no longer valid
   */
  record Entry(@NonNull String clientId, @Nullable String metadata, @Nullable Set<String> trustMarkTypes,
      @Nullable List<OnDemandTrustMark> onDemandTrustMarks, @NonNull Instant expiresAt) {

    /**
     * Creates the entry of a cache record.
     *
     * @param record the record
     * @return an {@link Entry}
     */
    static @NonNull Entry of(final @NonNull CachedClientRecord record) {
      return new Entry(record.clientId(),
          record.metadata() != null ? record.metadata().toJSONObject().toJSONString() : null,
          record.trustMarkTypes(), List.copyOf(record.onDemandTrustMarks().values()), record.expiresAt());
    }

    /**
     * Creates the cache record of the entry.
     *
     * @return a {@link CachedClientRecord}
     * @throws ParseException if the client metadata cannot be parsed
     */
    @NonNull CachedClientRecord toRecord() throws ParseException {
      final Map<String, OnDemandTrustMark> marks = this.onDemandTrustMarks == null
          ? Map.of()
          : this.onDemandTrustMarks.stream().collect(Collectors.toMap(OnDemandTrustMark::type, Function.identity()));
      return new CachedClientRecord(this.clientId,
          this.metadata != null ? OIDCClientMetadata.parse(JSONObjectUtils.parse(this.metadata)) : null,
          this.trustMarkTypes != null ? this.trustMarkTypes : Set.of(), marks, this.expiresAt);
    }

  }

}
