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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Where OpenID Connect clients that have been registered with the OpenID Provider are held.
 * <p>
 * The library ships an {@link InMemoryClientRepository}. Implementations backed by a database are added later.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ClientRepository {

  /**
   * Finds a client.
   *
   * @param clientId the {@code client_id} of the client
   * @return an {@link OidcClientRecord}, or {@code null} if the repository does not hold the client
   * @throws ClientRegistryException if the repository cannot be read
   */
  @Nullable OidcClientRecord findByClientId(final @Nonnull String clientId) throws ClientRegistryException;

}
