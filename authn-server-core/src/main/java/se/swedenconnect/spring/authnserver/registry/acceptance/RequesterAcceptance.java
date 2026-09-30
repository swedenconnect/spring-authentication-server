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

import jakarta.annotation.Nonnull;

import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Decides whether a requester may use the server. The check runs for every request, once the requester is known and
 * the request has been verified. A requester that is not accepted gets the error
 * {@link se.swedenconnect.spring.authnserver.error.AuthenticationError#NOT_AUTHORIZED NOT_AUTHORIZED}, answered to the
 * requester as an error response.
 * <p>
 * Two implementations are supplied: {@link #acceptAll()}, which is used when nothing is configured, and
 * {@link ConfigurableRequesterAcceptance}, which holds a set of {@link RequesterPredicate}s.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface RequesterAcceptance {

  /**
   * Tells whether the requester may use the server.
   *
   * @param record the requester's record from the client registry
   * @param registry the client registry, for asking for marks that the record does not hold
   * @return {@code true} if the requester is accepted and {@code false} otherwise
   * @throws ClientRegistryException if the registry fails when asked for a mark
   */
  boolean isAccepted(final @Nonnull RequesterRecord record, final @Nonnull ClientRegistry registry)
      throws ClientRegistryException;

  /**
   * Gets an acceptance check that accepts every requester.
   *
   * @return a {@link RequesterAcceptance}
   */
  static @Nonnull RequesterAcceptance acceptAll() {
    return AcceptAllRequesterAcceptance.INSTANCE;
  }

}
