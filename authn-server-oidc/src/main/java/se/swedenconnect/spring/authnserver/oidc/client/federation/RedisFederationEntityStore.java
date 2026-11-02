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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.nimbusds.oauth2.sdk.ParseException;

import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link FederationEntityStore} that keeps its entries in Redis, so that all nodes of a deployment share them.
 * <p>
 * An entry is the key {@code <prefix>:oidc:federation-entity:<entity identifier>}, holding the entry as JSON, and it
 * expires with the entry. The retained clients are the fields of the hash {@code <prefix>:oidc:federation-retained},
 * which is kept for {@value #RETENTION_DAYS} days after the latest of them expires.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisFederationEntityStore implements FederationEntityStore {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisFederationEntityStore.class);

  /** The number of days that the retained clients are kept after the latest of them expires. */
  public static final int RETENTION_DAYS = 7;

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisFederationEntityStore(final @NonNull StringRedisTemplate redisTemplate,
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
  public RedisFederationEntityStore(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix,
      final @NonNull Clock clock) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable FederationEntityRecord get(final @NonNull String entityId) {
    Objects.requireNonNull(entityId, "entityId must not be null");
    final String key = this.entryKey(entityId);
    final StoredEntityRecord stored =
        RedisJson.read(key, this.redisTemplate.opsForValue().get(key), StoredEntityRecord.class);
    if (stored == null) {
      return null;
    }
    try {
      final FederationEntityRecord record = stored.toRecord();
      return record.isExpired(this.clock.instant()) ? null : record;
    }
    catch (final ParseException | RuntimeException e) {
      log.warn("The Redis entry '{}' does not hold a valid federation entity and is ignored: {}", key,
          e.getMessage());
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull FederationEntityRecord record) {
    Objects.requireNonNull(record, "record must not be null");
    this.redisTemplate.opsForValue().set(this.entryKey(record.entityId()),
        RedisJson.write(StoredEntityRecord.of(record)), RedisKeys.timeToLive(record.expiresAt(), this.clock.instant()));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<RetainedClient> getRetainedClients() {
    final String key = this.retainedKey();
    final Map<Object, Object> hash = this.redisTemplate.opsForHash().entries(key);
    final List<RetainedClient> clients = new ArrayList<>();
    for (final Object value : hash.values()) {
      final RetainedClient client = RedisJson.read(key, (String) value, RetainedClient.class);
      if (client != null) {
        clients.add(client);
      }
    }
    return clients;
  }

  /** {@inheritDoc} */
  @Override
  public void putRetainedClient(final @NonNull RetainedClient client) {
    Objects.requireNonNull(client, "client must not be null");
    final String key = this.retainedKey();
    this.redisTemplate.opsForHash().put(key, client.clientId(), RedisJson.write(client));
    final Instant keepUntil = this.getRetainedClients().stream()
        .map(RetainedClient::expiresAt)
        .max(Instant::compareTo)
        .orElse(client.expiresAt())
        .plus(Duration.ofDays(RETENTION_DAYS));
    this.redisTemplate.expireAt(key, keepUntil);
  }

  /** {@inheritDoc} */
  @Override
  public void removeRetainedClient(final @NonNull String clientId) {
    this.redisTemplate.opsForHash().delete(this.retainedKey(),
        Objects.requireNonNull(clientId, "clientId must not be null"));
  }

  /**
   * Gets the key of the entry of an entity.
   *
   * @param entityId the entity identifier
   * @return the key
   */
  private @NonNull String entryKey(final @NonNull String entityId) {
    return this.keyPrefix + ":oidc:federation-entity:" + entityId;
  }

  /**
   * Gets the key of the hash of the retained clients.
   *
   * @return the key
   */
  private @NonNull String retainedKey() {
    return this.keyPrefix + ":oidc:federation-retained";
  }

}
