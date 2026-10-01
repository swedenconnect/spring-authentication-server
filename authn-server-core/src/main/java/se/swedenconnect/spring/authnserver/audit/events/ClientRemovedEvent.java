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
 * Published when a client disappears from the client registry: a Service Provider that a refreshed SAML metadata
 * source no longer holds, an OpenID Federation client that the resolver reports as not found, or a client that was
 * known before a restart and that the server no longer loads.
 *
 * @author Martin Lindström
 */
public class ClientRemovedEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Why the client was removed. */
  private final String reason;

  /**
   * Constructor.
   *
   * @param client the client, as it was known
   * @param reason why the client was removed
   */
  public ClientRemovedEvent(final @NonNull KnownClient client, final @NonNull String reason) {
    super(Objects.requireNonNull(client, "client must not be null"));
    this.reason = Objects.requireNonNull(reason, "reason must not be null");
  }

  /**
   * Gets the client, as it was known.
   *
   * @return the client
   */
  public @NonNull KnownClient getClient() {
    return (KnownClient) this.getSource();
  }

  /**
   * Gets why the client was removed.
   *
   * @return the reason
   */
  public @NonNull String getReason() {
    return this.reason;
  }

}
