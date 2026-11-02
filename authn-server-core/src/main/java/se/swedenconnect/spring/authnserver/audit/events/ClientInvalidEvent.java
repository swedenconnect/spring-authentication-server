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
package se.swedenconnect.spring.authnserver.audit.events;

import java.io.Serial;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * Published when a client in the client registry is marked as invalid, for example an OpenID Federation client with
 * {@code subject_type} set to {@code pairwise} whose {@code sector_identifier_uri} does not list its redirect URIs. The
 * client stays in the registry, but is never authenticated.
 *
 * @author Martin Lindström
 */
public class ClientInvalidEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Why the client is invalid. */
  private final String reason;

  /**
   * Constructor.
   *
   * @param client the client
   * @param reason why the client is invalid
   */
  public ClientInvalidEvent(final @NonNull KnownClient client, final @NonNull String reason) {
    super(Objects.requireNonNull(client, "client must not be null"));
    this.reason = Objects.requireNonNull(reason, "reason must not be null");
  }

  /**
   * Gets the client.
   *
   * @return the client
   */
  public @NonNull KnownClient getClient() {
    return (KnownClient) this.getSource();
  }

  /**
   * Gets why the client is invalid.
   *
   * @return the reason
   */
  public @NonNull String getReason() {
    return this.reason;
  }

}
