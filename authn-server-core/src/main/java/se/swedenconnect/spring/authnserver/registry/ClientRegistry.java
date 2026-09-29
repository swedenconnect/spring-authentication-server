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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Where the server finds out about a requester: a SAML Service Provider known by its entityID or an OpenID Connect
 * client known by its {@code client_id}.
 * <p>
 * A requester that the registry does not know is a normal outcome and is told by a {@code null} record. A backend
 * that fails, for example a metadata source that cannot be read or a resolver service that cannot be reached, throws
 * a {@link ClientRegistryException}. The two are never confused.
 * </p>
 * <p>
 * <b>Marks</b> are one set of identifiers for both protocols. For SAML they are the entity category URIs that the
 * Service Provider declares in its metadata, and for OpenID Connect they are trust mark types. A mark in the record
 * means that the requester holds it: a trust mark has been checked before its type was put in the set.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ClientRegistry {

  /**
   * Looks up a requester.
   *
   * @param requester the requester to look up
   * @return a {@link RequesterRecord}, or {@code null} if the requester is not known
   * @throws ClientRegistryException if a backend fails
   */
  @Nullable RequesterRecord lookup(final @Nonnull Requester requester) throws ClientRegistryException;

  /**
   * Looks up a requester.
   *
   * @param protocol the protocol that the requester speaks
   * @param identifier the identity of the requester
   * @return a {@link RequesterRecord}, or {@code null} if the requester is not known
   * @throws ClientRegistryException if a backend fails
   */
  default @Nullable RequesterRecord lookup(
      final @Nonnull AuthenticationProtocol protocol, final @Nonnull String identifier)
      throws ClientRegistryException {
    return this.lookup(new Requester(protocol, identifier));
  }

  /**
   * Asks for a mark that the requester does not already hold.
   * <p>
   * This is how an OpenID Connect trust mark is fetched from its issuer when the resolved client metadata does not
   * carry it. A mark that is obtained is checked, added to the requester's record and kept, so that a later request
   * from the same requester needs no call to the issuer. For SAML nothing is ever obtained this way.
   * </p>
   *
   * @param requester the requester
   * @param mark the identifier of the mark to ask for
   * @return the requester's record, holding the mark if one could be obtained, or {@code null} if the requester is
   *           not known
   * @throws ClientRegistryException if a backend fails
   */
  @Nullable RequesterRecord requestMark(final @Nonnull Requester requester, final @Nonnull String mark)
      throws ClientRegistryException;

}
