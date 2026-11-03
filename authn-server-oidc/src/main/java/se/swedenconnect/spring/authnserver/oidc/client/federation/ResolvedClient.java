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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * What a resolve response tells about an OpenID Connect client.
 * <p>
 * Relying party metadata that cannot be parsed does not make the resolution fail. The client is then given empty
 * metadata and the reason, and the {@link se.swedenconnect.spring.authnserver.oidc.client.ClientMetadataValidator ClientMetadataValidator} marks it as invalid.
 * </p>
 *
 * @param clientId the {@code client_id} of the client, which is its entity identifier
 * @param metadata the client metadata, after the metadata policies of the trust chain have been applied. Empty when
 *     the metadata cannot be parsed
 * @param trustMarkTypes the types of the trust marks that the response holds. The resolver has checked them
 * @param expiresAt when the resolved data is no longer valid
 * @param metadataError why the relying party metadata cannot be parsed, or {@code null} if it can
 * @param entityKeys the client's Federation Entity Keys, from the entity configuration that comes first in the
 *     {@code trust_chain} of the resolve response, or {@code null} if the response has no usable {@code trust_chain}.
 *     They verify a signed JWK Set at the {@code signed_jwks_uri}
 * @author Martin Lindström
 */
public record ResolvedClient(
    @NonNull String clientId,
    @NonNull OIDCClientMetadata metadata,
    @NonNull Set<String> trustMarkTypes,
    @NonNull Instant expiresAt,
    @Nullable String metadataError,
    @Nullable JWKSet entityKeys) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param trustMarkTypes the types of the trust marks that the response holds
   * @param expiresAt when the resolved data is no longer valid
   * @param metadataError why the relying party metadata cannot be parsed, or {@code null}
   * @param entityKeys the client's Federation Entity Keys, or {@code null}
   */
  public ResolvedClient {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
  }

  /**
   * Constructor for a client whose metadata could be parsed, and whose Federation Entity Keys are not known.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param trustMarkTypes the types of the trust marks that the response holds
   * @param expiresAt when the resolved data is no longer valid
   */
  public ResolvedClient(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull Set<String> trustMarkTypes, final @NonNull Instant expiresAt) {
    this(clientId, metadata, trustMarkTypes, expiresAt, null, null);
  }

}
