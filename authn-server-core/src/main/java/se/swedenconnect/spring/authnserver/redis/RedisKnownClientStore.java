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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientJson;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientStore;

/**
 * A {@link KnownClientStore} that keeps the record in Redis, so that the nodes of a deployment share it and each
 * change is reported by one node.
 * <p>
 * The record is the hash {@code <prefix>:known-clients}, where the field of a client is {@code <protocol>|<identity>}
 * and the value is the entry as JSON. A client is added with {@code HSETNX} and removed with {@code HDEL}, so that
 * exactly one node is told that it added or removed a client.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisKnownClientStore implements KnownClientStore {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisKnownClientStore.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key of the hash. */
  private final String key;

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisKnownClientStore(final @NonNull StringRedisTemplate redisTemplate, final @NonNull String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.key = RedisKeys.checkPrefix(keyPrefix) + ":known-clients";
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<KnownClient> addAll(final @NonNull Collection<KnownClient> clients) {
    final List<KnownClient> list = List.copyOf(Objects.requireNonNull(clients, "clients must not be null"));
    if (list.isEmpty()) {
      return List.of();
    }
    final byte[] hashKey = bytes(this.key);
    final List<Object> results = this.redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
      for (final KnownClient client : list) {
        connection.hashCommands().hSetNX(hashKey, bytes(field(client.requester())),
            bytes(KnownClientJson.write(client)));
      }
      return null;
    });
    final List<KnownClient> added = new ArrayList<>();
    for (int i = 0; i < list.size() && i < results.size(); i++) {
      if (Boolean.TRUE.equals(results.get(i))) {
        added.add(list.get(i));
      }
    }
    return added;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<KnownClient> removeAll(final @NonNull Collection<Requester> requesters) {
    final List<String> fields = Objects.requireNonNull(requesters, "requesters must not be null").stream()
        .map(RedisKnownClientStore::field)
        .toList();
    if (fields.isEmpty()) {
      return List.of();
    }
    final List<Object> values = this.redisTemplate.opsForHash().multiGet(this.key, List.copyOf(fields));
    final byte[] hashKey = bytes(this.key);
    final List<Object> results = this.redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
      for (final String field : fields) {
        connection.hashCommands().hDel(hashKey, bytes(field));
      }
      return null;
    });
    final List<KnownClient> removed = new ArrayList<>();
    for (int i = 0; i < fields.size() && i < results.size(); i++) {
      if (results.get(i) instanceof final Long count && count > 0) {
        final KnownClient client = read(fields.get(i), i < values.size() ? values.get(i) : null);
        if (client != null) {
          removed.add(client);
        }
      }
    }
    return removed;
  }

  /** {@inheritDoc} */
  @Override
  public void update(final @NonNull KnownClient client) {
    Objects.requireNonNull(client, "client must not be null");
    this.redisTemplate.opsForHash().put(this.key, field(client.requester()), KnownClientJson.write(client));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<KnownClient> getAll() {
    final Map<Object, Object> entries = this.redisTemplate.opsForHash().entries(this.key);
    final List<KnownClient> clients = new ArrayList<>();
    entries.forEach((field, value) -> {
      final KnownClient client = read(String.valueOf(field), value);
      if (client != null) {
        clients.add(client);
      }
    });
    return clients;
  }

  /**
   * Reads an entry. An entry that cannot be read is logged and ignored.
   *
   * @param field the field of the entry
   * @param value the value, or {@code null}
   * @return the client, or {@code null}
   */
  private @Nullable KnownClient read(final @NonNull String field, final @Nullable Object value) {
    if (value == null) {
      return null;
    }
    try {
      return KnownClientJson.read(value.toString());
    }
    catch (final IllegalArgumentException e) {
      log.warn("The known client entry '{}' in '{}' could not be read and is ignored: {}", field, this.key,
          e.getMessage());
      return null;
    }
  }

  /**
   * Gets the hash field of a client.
   *
   * @param requester the client
   * @return the field
   */
  private static @NonNull String field(final @NonNull Requester requester) {
    return requester.protocol().name() + "|" + requester.identifier();
  }

  /**
   * Gets the UTF-8 bytes of a string.
   *
   * @param value the string
   * @return the bytes
   */
  private static byte @NonNull [] bytes(final @NonNull String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

}
