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
package se.swedenconnect.spring.authnserver.registry;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;

/**
 * One source of requesters behind a {@link ClientRegistry}: SAML metadata, a list of configured OpenID Connect
 * clients, a client repository or an OpenID Federation resolver.
 * <p>
 * A backend answers for one protocol only. Several backends may serve the same protocol, in which case the registry
 * asks them in the order they were given and the first one that knows the requester wins.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ClientRegistryBackend {

  /**
   * Gets the name of the backend. It is used in logs.
   *
   * @return the backend name
   */
  @NonNull String getName();

  /**
   * Gets the protocol that the backend answers for.
   *
   * @return the protocol
   */
  @NonNull AuthenticationProtocol getProtocol();

  /**
   * Looks up a requester.
   *
   * @param identifier the identity of the requester, a SAML SP entityID or an OpenID Connect {@code client_id}
   * @return a {@link RequesterRecord}, or {@code null} if the backend does not know the requester
   * @throws ClientRegistryException if the backend fails
   */
  @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException;

  /**
   * Asks for a mark that the requester does not already hold, see
   * {@link ClientRegistry#requestMark(se.swedenconnect.spring.authnserver.authentication.Requester, String)}.
   * <p>
   * The default implementation is a plain lookup, which is what a backend that cannot obtain marks of its own should
   * do.
   * </p>
   *
   * @param identifier the identity of the requester
   * @param mark the identifier of the mark to ask for
   * @return the requester's record, holding the mark if one could be obtained, or {@code null} if the backend does
   *           not know the requester
   * @throws ClientRegistryException if the backend fails
   */
  default @Nullable RequesterRecord requestMark(final @NonNull String identifier, final @NonNull String mark)
      throws ClientRegistryException {
    return this.lookup(identifier);
  }

}
