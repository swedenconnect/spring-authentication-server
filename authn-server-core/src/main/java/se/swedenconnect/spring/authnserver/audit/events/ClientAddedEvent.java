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
 * Published when a client appears in the client registry: a Service Provider that a refreshed SAML metadata source
 * now holds, an OpenID Federation client that is resolved for the first time, or a client that the server loads at
 * startup and that was not known before the restart.
 *
 * @author Martin Lindström
 */
public class ClientAddedEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param client the client
   */
  public ClientAddedEvent(final @NonNull KnownClient client) {
    super(Objects.requireNonNull(client, "client must not be null"));
  }

  /**
   * Gets the client.
   *
   * @return the client
   */
  public @NonNull KnownClient getClient() {
    return (KnownClient) this.getSource();
  }

}
