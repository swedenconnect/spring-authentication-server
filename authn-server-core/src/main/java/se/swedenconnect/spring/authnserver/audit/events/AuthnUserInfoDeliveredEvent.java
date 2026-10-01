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
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;

/**
 * Published when a UserInfo response is sent to an OpenID Connect client.
 *
 * @author Martin Lindström
 */
public class AuthnUserInfoDeliveredEvent extends AbstractAuthnEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The released claims. */
  private final List<AuditAttribute> releasedAttributes;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param response the protocol-specific data about the response, or {@code null}
   * @param releasedAttributes the released claims
   */
  public AuthnUserInfoDeliveredEvent(final @NonNull AuditRequester requester,
      final @Nullable ProtocolAuditData response, final @NonNull List<AuditAttribute> releasedAttributes) {
    super(requester, response);
    this.releasedAttributes =
        List.copyOf(Objects.requireNonNull(releasedAttributes, "releasedAttributes must not be null"));
  }

  /**
   * Gets the released claims.
   *
   * @return the released claims
   */
  public @NonNull List<AuditAttribute> getReleasedAttributes() {
    return this.releasedAttributes;
  }

}
