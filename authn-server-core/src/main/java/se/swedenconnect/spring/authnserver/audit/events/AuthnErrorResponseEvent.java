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
import se.swedenconnect.spring.authnserver.audit.AuditStage;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;

/**
 * Published when an error is sent to a requester: a SAML error response, an OpenID Connect authorization error, a
 * token endpoint error or a UserInfo error.
 *
 * @author Martin Lindström
 */
public class AuthnErrorResponseEvent extends AbstractAuthnEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The stage that the error came from. */
  private final AuditStage stage;

  /** The error code of the protocol. */
  private final String errorCode;

  /** The error description. */
  private final String errorDescription;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param response the protocol-specific data about the response, or {@code null}
   * @param stage the stage that the error came from, or {@code null} if it is not known
   * @param errorCode the error code of the protocol
   * @param errorDescription the error description, or {@code null}
   */
  public AuthnErrorResponseEvent(final @NonNull AuditRequester requester, final @Nullable ProtocolAuditData response,
      final @Nullable AuditStage stage, final @NonNull String errorCode, final @Nullable String errorDescription) {
    super(requester, response);
    this.stage = stage;
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode must not be null");
    this.errorDescription = errorDescription;
  }

  /**
   * Gets the stage that the error came from.
   *
   * @return the stage, or {@code null} if it is not known
   */
  public @Nullable AuditStage getStage() {
    return this.stage;
  }

  /**
   * Gets the error code of the protocol.
   *
   * @return the error code
   */
  public @NonNull String getErrorCode() {
    return this.errorCode;
  }

  /**
   * Gets the error description.
   *
   * @return the description, or {@code null}
   */
  public @Nullable String getErrorDescription() {
    return this.errorDescription;
  }

}
