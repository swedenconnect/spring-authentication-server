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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;

/**
 * One source of requesters behind a {@link ClientRegistry}: SAML metadata, a list of configured OpenID Connect
 * clients, a client repository or an OpenID Federation resolver.
 * <p>
 * A backend answers for one protocol only. Several backends may serve the same protocol, in which case the registry
 * asks them in the order they were given and the first one that knows the requester wins.
 * </p>
 * <p>
 * The methods that show what a backend holds, and that update it, are there for management, such as the Actuator
 * support. They never call anything outside the server, except the update methods. Their default implementations tell
 * that the backend holds nothing that can be shown and nothing that can be updated.
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

  /**
   * Gets the clients that the backend holds now. A backend that reads its clients on demand, such as an MDQ source,
   * gives the ones it has read.
   *
   * @return the clients
   */
  default @NonNull List<RegisteredClient> getClients() {
    return List.of();
  }

  /**
   * Gets one client that the backend holds now, without asking anything outside the server.
   *
   * @param identifier the identity of the client
   * @return a {@link RegisteredClient}, or {@code null} if the backend does not hold the client
   */
  default @Nullable RegisteredClient getClient(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    return this.getClients().stream()
        .filter(c -> identifier.equals(c.requester().identifier()))
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the metadata of a client exactly as the backend holds it: the {@code EntityDescriptor} as XML for SAML, and
   * the client metadata as JSON for OpenID Connect. A client secret is left out.
   *
   * @param identifier the identity of the client
   * @return the metadata, or {@code null} if the backend does not hold the client
   */
  default @Nullable String getMetadata(final @NonNull String identifier) {
    return null;
  }

  /**
   * Gets the names of the sources of the backend, the names that {@link #getSources()} gives them. The names tell the
   * sources apart in management and audit, so they must be unique among the sources of a protocol. Unlike
   * {@link #getSources()}, this method never reads the clients. The default is the backend name.
   *
   * @return the source names
   */
  default @NonNull List<String> getSourceNames() {
    return List.of(this.getName());
  }

  /**
   * Gets the sources of the backend, with the number of clients of each and when it was last updated.
   *
   * @return the sources
   */
  default @NonNull List<ClientSource> getSources() {
    return List.of();
  }

  /**
   * Updates every source of the backend that can be updated, for example by downloading SAML metadata again.
   *
   * @return the result
   */
  default @NonNull ClientUpdateResult update() {
    return ClientUpdateResult.nothingToUpdate("The '%s' backend has nothing to update".formatted(this.getName()));
  }

  /**
   * Fetches the data of one client again, for example by resolving an OpenID Federation client again.
   *
   * @param identifier the identity of the client
   * @return the result
   */
  default @NonNull ClientUpdateResult update(final @NonNull String identifier) {
    return ClientUpdateResult.nothingToUpdate(
        "The client '%s' comes from the '%s' backend, which has nothing to update".formatted(identifier,
            this.getName()));
  }

  /**
   * Assigns the object that is told when a client appears or disappears. The registry assigns it when it is set up.
   * A backend reports the clients it holds when the tracker is assigned, and every change after that. The default
   * does nothing.
   *
   * @param tracker the tracker, or {@code null} for none
   */
  default void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
  }

}
