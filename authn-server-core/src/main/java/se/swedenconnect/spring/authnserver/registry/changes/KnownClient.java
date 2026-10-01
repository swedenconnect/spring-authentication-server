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
package se.swedenconnect.spring.authnserver.registry.changes;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * A client in the record of known clients, see {@link KnownClientStore}.
 *
 * @param requester the requester
 * @param organizationNumber the organisation number, as held in the registry, or {@code null}
 * @param source where the client came from: a SAML metadata source or the name of an OpenID Connect backend
 * @author Martin Lindström
 */
public record KnownClient(@NonNull Requester requester, @Nullable String organizationNumber, @NonNull String source)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param organizationNumber the organisation number, or {@code null}
   * @param source where the client came from
   */
  public KnownClient {
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(source, "source must not be null");
  }

  /**
   * Creates the entry of a client from its record.
   *
   * @param record the record of the client
   * @param source where the client came from
   * @return a {@link KnownClient}
   */
  public static @NonNull KnownClient of(final @NonNull RequesterRecord record, final @NonNull String source) {
    return new KnownClient(record.requester(), record.organizationNumber(), source);
  }

  /**
   * Gets the protocol of the client.
   *
   * @return the protocol
   */
  public @NonNull AuthenticationProtocol protocol() {
    return this.requester.protocol();
  }

  /**
   * Gets the identity of the client.
   *
   * @return the identity
   */
  public @NonNull String identifier() {
    return this.requester.identifier();
  }

  /**
   * Creates a copy with another source.
   *
   * @param newSource the source
   * @return a {@link KnownClient}
   */
  public @NonNull KnownClient withSource(final @NonNull String newSource) {
    return new KnownClient(this.requester, this.organizationNumber, newSource);
  }

}
