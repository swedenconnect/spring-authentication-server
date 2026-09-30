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
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A record of one use of an authentication result. The first record of an {@link AuthenticationUsageTrack} is the
 * original authentication, and every record after that is a use where single sign-on was applied.
 *
 * @param protocol the protocol that the requester used
 * @param requester the requester, a SAML SP entityID or an OpenID Connect {@code client_id}
 * @param requestId the identifier of the request, the ID of the SAML {@code AuthnRequest}. OpenID Connect has no such
 *          identifier, so the value is {@code null} for that protocol
 * @param instant the instant of the use. For the original authentication this is the authentication instant
 * @param requestedAttributes the identifiers of the generic attributes that the requester asked for
 * @author Martin Lindström
 */
public record AuthenticationUse(@NonNull AuthenticationProtocol protocol, @NonNull String requester,
    @Nullable String requestId, @NonNull Instant instant, @NonNull List<String> requestedAttributes)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param protocol the protocol that the requester used
   * @param requester the requester, a SAML SP entityID or an OpenID Connect {@code client_id}
   * @param requestId the identifier of the request, may be {@code null}
   * @param instant the instant of the use
   * @param requestedAttributes the identifiers of the generic attributes that the requester asked for, empty when the
   *          requester asked for none
   */
  public AuthenticationUse {
    Objects.requireNonNull(protocol, "protocol must not be null");
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(instant, "instant must not be null");
    Objects.requireNonNull(requestedAttributes, "requestedAttributes must not be null");
    requestedAttributes = List.copyOf(requestedAttributes);
  }

}
