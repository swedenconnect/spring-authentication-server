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
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Published when the user has been authenticated, or an earlier authentication was reused for single sign-on.
 *
 * @author Martin Lindström
 */
public class AuthnUserAuthenticatedEvent extends AbstractAuthnEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The authentication. */
  private final UserAuthentication authentication;

  /** Whether single sign-on was used. */
  private final boolean sso;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param authnRequest the protocol-specific data about the request, or {@code null}
   * @param authentication the authentication
   * @param sso whether an earlier authentication was reused for single sign-on
   */
  public AuthnUserAuthenticatedEvent(final @NonNull AuditRequester requester,
      final @Nullable ProtocolAuditData authnRequest, final @NonNull UserAuthentication authentication,
      final boolean sso) {
    super(requester, authnRequest);
    this.authentication = Objects.requireNonNull(authentication, "authentication must not be null");
    this.sso = sso;
  }

  /**
   * Gets the authentication.
   *
   * @return the authentication
   */
  public @NonNull UserAuthentication getAuthentication() {
    return this.authentication;
  }

  /**
   * Tells whether an earlier authentication was reused for single sign-on.
   *
   * @return {@code true} if single sign-on was used and {@code false} otherwise
   */
  public boolean isSso() {
    return this.sso;
  }

}
