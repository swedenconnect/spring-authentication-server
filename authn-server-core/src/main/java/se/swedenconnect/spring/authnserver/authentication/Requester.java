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
package se.swedenconnect.spring.authnserver.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Who asked for an authentication: the protocol it used and its identity within that protocol.
 * <p>
 * Two requesters are the same only when both the protocol and the identity are the same. The same organisation
 * registered both as a SAML Service Provider and as an OpenID Connect client is therefore two requesters.
 * </p>
 *
 * @param protocol the protocol that the requester used
 * @param identifier the identity of the requester, a SAML SP entityID or an OpenID Connect {@code client_id}
 * @author Martin Lindström
 */
public record Requester(@NonNull AuthenticationProtocol protocol, @NonNull String identifier)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param protocol the protocol that the requester used
   * @param identifier the identity of the requester
   */
  public Requester {
    Objects.requireNonNull(protocol, "protocol must not be null");
    Objects.requireNonNull(identifier, "identifier must not be null");
    if (!StringUtils.hasText(identifier)) {
      throw new IllegalArgumentException("identifier must not be empty");
    }
  }

  /**
   * Predicate telling whether the supplied usage record was made for this requester.
   *
   * @param use the usage record
   * @return {@code true} if the record was made for this requester and {@code false} otherwise
   */
  public boolean matches(final @NonNull AuthenticationUse use) {
    return use.protocol() == this.protocol && this.identifier.equals(use.requester());
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "%s:%s".formatted(this.protocol, this.identifier);
  }

}
