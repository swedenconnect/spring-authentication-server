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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;

/**
 * Published when an authorization response holding the authorization code is sent to an OpenID Connect client.
 *
 * @author Martin Lindström
 */
public class AuthnAuthorizationResponseEvent extends AbstractAuthnEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param response the protocol-specific data about the response, or {@code null}
   */
  public AuthnAuthorizationResponseEvent(final @NonNull AuditRequester requester,
      final @Nullable ProtocolAuditData response) {
    super(requester, response);
  }

}
