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
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * What a resolve response tells about an entity of the federation, as the {@link FederationClientCollector} needs it:
 * whether it is an OpenID Connect client, and whether it lists subordinates.
 *
 * @param entityId the entity identifier
 * @param clientMetadata the relying party metadata, after the metadata policies of the trust chain have been applied,
 *     or {@code null} if the entity is not an OpenID Connect client
 * @param listEndpoint the {@code federation_list_endpoint} of the entity, or {@code null} if it lists no subordinates
 * @param trustMarkTypes the types of the trust marks that the response holds. The resolver has checked them
 * @param expiresAt when the resolved data is no longer valid
 * @author Martin Lindström
 */
public record ResolvedEntity(
    @NonNull String entityId,
    @Nullable OIDCClientMetadata clientMetadata,
    @Nullable String listEndpoint,
    @NonNull Set<String> trustMarkTypes,
    @NonNull Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param entityId the entity identifier
   * @param clientMetadata the relying party metadata, or {@code null}
   * @param listEndpoint the {@code federation_list_endpoint} of the entity, or {@code null}
   * @param trustMarkTypes the types of the trust marks that the response holds
   * @param expiresAt when the resolved data is no longer valid
   */
  public ResolvedEntity {
    Objects.requireNonNull(entityId, "entityId must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
  }

  /**
   * Creates the resolved entity of a resolved client, which lists no subordinates.
   *
   * @param client the resolved client
   * @return a {@link ResolvedEntity}
   */
  public static @NonNull ResolvedEntity of(final @NonNull ResolvedClient client) {
    Objects.requireNonNull(client, "client must not be null");
    return new ResolvedEntity(client.clientId(), client.metadata(), null, client.trustMarkTypes(),
        client.expiresAt());
  }

  /**
   * Gets the entity as a resolved client.
   *
   * @return a {@link ResolvedClient}, or {@code null} if the entity is not an OpenID Connect client
   */
  public @Nullable ResolvedClient toClient() {
    return this.clientMetadata != null
        ? new ResolvedClient(this.entityId, this.clientMetadata, this.trustMarkTypes, this.expiresAt)
        : null;
  }

}
