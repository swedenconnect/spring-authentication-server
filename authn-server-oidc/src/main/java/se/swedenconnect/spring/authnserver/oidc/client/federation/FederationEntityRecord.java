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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * An entry of the {@link FederationEntityStore}: what the resolver answered about an entity of the federation, or that
 * it does not know the entity, and for how long the answer is kept.
 *
 * @param entityId the entity identifier
 * @param entity what the resolver answered, or {@code null} if the resolver does not know the entity
 * @param expiresAt when the entry is no longer valid
 * @author Martin Lindström
 */
public record FederationEntityRecord(
    @NonNull String entityId,
    @Nullable ResolvedEntity entity,
    @NonNull Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param entityId the entity identifier
   * @param entity what the resolver answered, or {@code null}
   * @param expiresAt when the entry is no longer valid
   */
  public FederationEntityRecord {
    Objects.requireNonNull(entityId, "entityId must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
  }

  /**
   * Creates an entry for an entity that the resolver knows. The entry lives until the resolve response expires, or
   * until the maximum age has passed if that comes first.
   *
   * @param entity what the resolver answered
   * @param now the current time
   * @param maximumAge how long an entry may live at the most, or {@code null} for no limit
   * @return a {@link FederationEntityRecord}
   */
  public static @NonNull FederationEntityRecord found(final @NonNull ResolvedEntity entity,
      final @NonNull Instant now, final @Nullable Duration maximumAge) {
    Objects.requireNonNull(entity, "entity must not be null");
    Instant expiresAt = entity.expiresAt();
    if (maximumAge != null && now.plus(maximumAge).isBefore(expiresAt)) {
      expiresAt = now.plus(maximumAge);
    }
    return new FederationEntityRecord(entity.entityId(), entity, expiresAt);
  }

  /**
   * Creates an entry telling that the resolver does not know the entity, or that it is of none of the entity types
   * that were asked for.
   *
   * @param entityId the entity identifier
   * @param now the current time
   * @param timeToLive how long the entry is kept
   * @return a {@link FederationEntityRecord}
   */
  public static @NonNull FederationEntityRecord notFound(
      final @NonNull String entityId, final @NonNull Instant now, final @NonNull Duration timeToLive) {
    return new FederationEntityRecord(entityId, null, now.plus(timeToLive));
  }

  /**
   * Tells whether the resolver knows the entity.
   *
   * @return {@code true} if the entry holds a resolved entity and {@code false} otherwise
   */
  public boolean isFound() {
    return this.entity != null;
  }

  /**
   * Gets the entity as a resolved client, valid until the entry expires.
   *
   * @return a {@link ResolvedClient}, or {@code null} if the entity is not known or is not an OpenID Connect client
   */
  public @Nullable ResolvedClient toClient() {
    if (this.entity == null || this.entity.clientMetadata() == null) {
      return null;
    }
    return new ResolvedClient(this.entityId, this.entity.clientMetadata(), this.entity.trustMarkTypes(),
        this.expiresAt, this.entity.clientMetadataError(), this.entity.entityKeys());
  }

  /**
   * Gets the {@code federation_list_endpoint} of the entity.
   *
   * @return the endpoint, or {@code null} if the entity is not known or lists no subordinates
   */
  public @Nullable String listEndpoint() {
    return this.entity != null ? this.entity.listEndpoint() : null;
  }

  /**
   * Tells whether the entry is no longer valid.
   *
   * @param now the current time
   * @return {@code true} if the entry has expired and {@code false} otherwise
   */
  public boolean isExpired(final @NonNull Instant now) {
    return !now.isBefore(this.expiresAt);
  }

}
