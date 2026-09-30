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
package se.swedenconnect.spring.authnserver.registry.acceptance;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * One condition that a requester must meet to be accepted by a {@link ConfigurableRequesterAcceptance}. A predicate
 * belongs to one protocol, and it is only evaluated for requesters of that protocol.
 * <p>
 * A predicate may read the protocol-neutral part of the record, or the protocol metadata through
 * {@link RequesterRecord#getProtocolMetadata(Class)}. Predicates that read protocol metadata are written in the
 * protocol module, since the core does not know the protocol types.
 * </p>
 *
 * @author Martin Lindström
 */
public interface RequesterPredicate {

  /**
   * Gets the protocol that the predicate applies to.
   *
   * @return the protocol
   */
  @NonNull AuthenticationProtocol getProtocol();

  /**
   * Tests whether the requester meets the condition.
   *
   * @param record the requester's record
   * @param registry the client registry, for asking for marks that the record does not hold
   * @return {@code true} if the requester meets the condition and {@code false} otherwise
   * @throws ClientRegistryException if the registry fails when asked for a mark
   */
  boolean test(final @NonNull RequesterRecord record, final @NonNull ClientRegistry registry)
      throws ClientRegistryException;

}
