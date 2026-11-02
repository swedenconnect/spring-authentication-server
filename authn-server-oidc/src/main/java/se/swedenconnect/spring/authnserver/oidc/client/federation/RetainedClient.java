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

import org.jspecify.annotations.NonNull;

/**
 * A cached client that the resolver no longer knows, and that is kept until its cache entry expires, see
 * {@link FederationCollectorSettings#keepUntilExpiry()}.
 *
 * @param clientId the {@code client_id} of the client
 * @param since when the resolver first answered that it does not know the client
 * @param expiresAt when the cache entry of the client expires
 * @author Martin Lindström
 */
public record RetainedClient(@NonNull String clientId, @NonNull Instant since, @NonNull Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param since when the resolver first answered that it does not know the client
   * @param expiresAt when the cache entry of the client expires
   */
  public RetainedClient {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(since, "since must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
  }

}
