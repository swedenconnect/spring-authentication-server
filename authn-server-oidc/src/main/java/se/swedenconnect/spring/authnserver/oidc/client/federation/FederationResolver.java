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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Resolves an OpenID Connect client through OpenID Federation.
 * <p>
 * The library resolves through an external resolver service, see {@link HttpFederationResolver}. Resolving inside
 * the OpenID Provider itself is another implementation of this interface, and nothing else changes when it is used.
 * </p>
 *
 * @author Martin Lindström
 */
public interface FederationResolver {

  /**
   * Resolves a client.
   *
   * @param clientId the {@code client_id} of the client, which is its entity identifier
   * @return a {@link ResolvedClient}, or {@code null} if the federation does not know the client
   * @throws ClientRegistryException if the resolution fails
   */
  @Nullable ResolvedClient resolve(final @NonNull String clientId) throws ClientRegistryException;

}
