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

import java.time.Instant;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * A {@link FederationEntityRecord} as it is written outside the memory of the server. The client metadata is kept as
 * the JSON that the metadata gives.
 *
 * @param entityId the entity identifier
 * @param found whether the resolver knows the entity
 * @param clientMetadata the client metadata as a JSON object, or {@code null}
 * @param listEndpoint the {@code federation_list_endpoint}, or {@code null}
 * @param trustMarkTypes the trust mark types of the resolve response
 * @param entityExpiresAt when the resolved data is no longer valid, or {@code null} if the entity is not found
 * @param expiresAt when the entry is no longer valid
 * @param clientMetadataError why the relying party metadata cannot be parsed, or {@code null}
 * @param entityKeys the entity's Federation Entity Keys as a JWK Set, or {@code null}
 * @author Martin Lindström
 */
record StoredEntityRecord(@NonNull String entityId, boolean found, @Nullable String clientMetadata,
    @Nullable String listEndpoint, @Nullable Set<String> trustMarkTypes, @Nullable Instant entityExpiresAt,
    @NonNull Instant expiresAt, @Nullable String clientMetadataError, @Nullable String entityKeys) {

  /**
   * Creates the stored form of an entity record.
   *
   * @param record the record
   * @return a {@link StoredEntityRecord}
   */
  static @NonNull StoredEntityRecord of(final @NonNull FederationEntityRecord record) {
    final ResolvedEntity entity = record.entity();
    if (entity == null) {
      return new StoredEntityRecord(record.entityId(), false, null, null, null, null, record.expiresAt(), null, null);
    }
    return new StoredEntityRecord(record.entityId(), true,
        entity.clientMetadata() != null ? entity.clientMetadata().toJSONObject().toJSONString() : null,
        entity.listEndpoint(), entity.trustMarkTypes(), entity.expiresAt(), record.expiresAt(),
        entity.clientMetadataError(), StoredClientRecord.write(entity.entityKeys()));
  }

  /**
   * Creates the entity record of the stored form.
   *
   * @return a {@link FederationEntityRecord}
   * @throws ParseException if the client metadata cannot be parsed
   * @throws IllegalArgumentException if the Federation Entity Keys cannot be parsed
   */
  @NonNull FederationEntityRecord toRecord() throws ParseException {
    if (!this.found) {
      return new FederationEntityRecord(this.entityId, null, this.expiresAt);
    }
    return new FederationEntityRecord(this.entityId, new ResolvedEntity(this.entityId,
        this.clientMetadata != null ? OIDCClientMetadata.parse(JSONObjectUtils.parse(this.clientMetadata)) : null,
        this.listEndpoint, this.trustMarkTypes != null ? this.trustMarkTypes : Set.of(),
        this.entityExpiresAt != null ? this.entityExpiresAt : this.expiresAt, this.clientMetadataError,
        StoredClientRecord.readKeys(this.entityKeys)), this.expiresAt);
  }

}
