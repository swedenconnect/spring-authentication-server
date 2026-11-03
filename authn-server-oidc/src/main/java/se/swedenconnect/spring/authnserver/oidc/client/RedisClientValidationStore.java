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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.text.ParseException;
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
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.nimbusds.jose.jwk.JWKSet;

import se.swedenconnect.spring.authnserver.job.JobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJobLock;
import se.swedenconnect.spring.authnserver.redis.RedisJson;
import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * A {@link ClientValidationStore} that keeps the outcomes in Redis, so that all nodes of a deployment share them and
 * the keys that the clients hold.
 * <p>
 * The outcomes of a client source are the hash {@code <prefix>:oidc:client-validation:<source>}, with one field per
 * {@code client_id} holding the outcome as JSON. The outcomes do not expire. An outcome for a client that its source
 * no longer holds is removed by the {@link ClientValidation}.
 * </p>
 * <p>
 * The {@link ClientKeysRefresher} uses a {@link RedisJobLock}, so that a round runs on one node at a time.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisClientValidationStore implements ClientValidationStore {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisClientValidationStore.class);

  /** The Redis template. */
  private final StringRedisTemplate redisTemplate;

  /** The key prefix. */
  private final String keyPrefix;

  /** The lock of the background job. */
  private final JobLock jobLock;

  /**
   * Constructor using the default key prefix, {@value RedisKeys#DEFAULT_PREFIX}.
   *
   * @param redisTemplate the Redis template
   */
  public RedisClientValidationStore(final @NonNull StringRedisTemplate redisTemplate) {
    this(redisTemplate, RedisKeys.DEFAULT_PREFIX);
  }

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   * @param keyPrefix the key prefix
   */
  public RedisClientValidationStore(final @NonNull StringRedisTemplate redisTemplate,
      final @NonNull String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.keyPrefix = RedisKeys.checkPrefix(keyPrefix);
    this.jobLock = new RedisJobLock(redisTemplate, keyPrefix);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ValidatedClient get(final @NonNull String source, final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final String key = this.key(source);
    return this.toClient(key, this.hash().get(key, clientId));
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull String source, final @NonNull ValidatedClient client) {
    Objects.requireNonNull(client, "client must not be null");
    this.hash().put(this.key(source), client.clientId(), RedisJson.write(StoredValidatedClient.of(client)));
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final @NonNull String source, final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    this.hash().delete(this.key(source), clientId);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<ValidatedClient> getAll(final @NonNull String source) {
    final String key = this.key(source);
    final Map<String, String> entries = this.hash().entries(key);
    final List<ValidatedClient> clients = new ArrayList<>();
    entries.values().forEach(json -> {
      final ValidatedClient client = this.toClient(key, json);
      if (client != null) {
        clients.add(client);
      }
    });
    return clients;
  }

  /**
   * Gets a {@link RedisJobLock}, so that a round of the {@link ClientKeysRefresher} runs on one node at a time.
   */
  @Override
  public @NonNull JobLock getJobLock() {
    return this.jobLock;
  }

  /**
   * Reads an outcome.
   *
   * @param key the key of the hash, for the log
   * @param json the JSON of the outcome, or {@code null}
   * @return the outcome, or {@code null} if there is none or it cannot be read
   */
  private @Nullable ValidatedClient toClient(final @NonNull String key, final @Nullable String json) {
    final StoredValidatedClient stored = RedisJson.read(key, json, StoredValidatedClient.class);
    if (stored == null) {
      return null;
    }
    try {
      return stored.toClient();
    }
    catch (final ParseException | RuntimeException e) {
      log.warn("The Redis entry '{}' holds an outcome that cannot be read and is ignored: {}", key, e.getMessage());
      return null;
    }
  }

  /**
   * Gets the hash operations.
   *
   * @return the operations
   */
  private @NonNull HashOperations<String, String, String> hash() {
    return this.redisTemplate.opsForHash();
  }

  /**
   * Gets the key of the hash of a source.
   *
   * @param source the name of the source
   * @return the key
   */
  private @NonNull String key(final @NonNull String source) {
    return this.keyPrefix + ":oidc:client-validation:" + Objects.requireNonNull(source, "source must not be null");
  }

  /**
   * The stored form of a {@link ValidatedClient}.
   *
   * @param clientId the {@code client_id}
   * @param fingerprint the fingerprint of the validated metadata
   * @param invalidReason why the client is invalid, or {@code null}
   * @param invalidUntil when a temporary mark runs out, or {@code null}
   * @param keysUri the URI that the held keys were read from, or {@code null}
   * @param keys the held keys as a JWK Set, or {@code null}
   */
  record StoredValidatedClient(@NonNull String clientId, @NonNull String fingerprint, @Nullable String invalidReason,
      @Nullable Instant invalidUntil, @Nullable String keysUri, @Nullable String keys) {

    /**
     * Creates the stored form of an outcome.
     *
     * @param client the outcome
     * @return the stored form
     */
    static @NonNull StoredValidatedClient of(final @NonNull ValidatedClient client) {
      final HeldKeys held = client.heldKeys();
      return new StoredValidatedClient(client.clientId(), client.fingerprint(), client.invalidReason(),
          client.invalidUntil(), held != null ? held.uri() : null, held != null ? held.keys().toString() : null);
    }

    /**
     * Creates the outcome of the stored form.
     *
     * @return the outcome
     * @throws ParseException if the keys cannot be read
     */
    @NonNull ValidatedClient toClient() throws ParseException {
      final HeldKeys held = this.keysUri != null && this.keys != null
          ? new HeldKeys(this.keysUri, false, JWKSet.parse(this.keys), null)
          : null;
      return new ValidatedClient(this.clientId, this.fingerprint, this.invalidReason, this.invalidUntil, held);
    }
  }

}
