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

import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;

/**
 * One source of clients behind a {@link ClientRegistryBackend}, as it is shown to an operator: a SAML metadata source,
 * or an OpenID Connect backend.
 *
 * @param protocol the protocol of the clients
 * @param name the name of the source
 * @param clients the number of clients the source holds now, or {@code null} if it cannot tell
 * @param lastUpdate when the source was last updated, or {@code null} if it never is or it is not known
 * @author Martin Lindström
 */
public record ClientSource(
    @NonNull AuthenticationProtocol protocol,
    @NonNull String name,
    @Nullable Integer clients,
    @Nullable Instant lastUpdate) {

  /**
   * Constructor.
   *
   * @param protocol the protocol of the clients
   * @param name the name of the source
   * @param clients the number of clients, or {@code null}
   * @param lastUpdate when the source was last updated, or {@code null}
   */
  public ClientSource {
    Objects.requireNonNull(protocol, "protocol must not be null");
    Objects.requireNonNull(name, "name must not be null");
  }

}
