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

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * What a resolve response tells about an OpenID Connect client.
 *
 * @param clientId the {@code client_id} of the client, which is its entity identifier
 * @param metadata the client metadata, after the metadata policies of the trust chain have been applied
 * @param trustMarkTypes the types of the trust marks that the response holds. The resolver has checked them
 * @param expiresAt when the resolved data is no longer valid
 * @author Martin Lindström
 */
public record ResolvedClient(
    @NonNull String clientId,
    @NonNull OIDCClientMetadata metadata,
    @NonNull Set<String> trustMarkTypes,
    @NonNull Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param trustMarkTypes the types of the trust marks that the response holds
   * @param expiresAt when the resolved data is no longer valid
   */
  public ResolvedClient {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
  }

}
