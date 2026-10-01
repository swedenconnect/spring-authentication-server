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
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Published when an error is shown to the user because no response can be sent to the requester.
 *
 * @author Martin Lindström
 */
public class AuthnUnrecoverableErrorEvent extends AbstractAuthnEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The stage that the error came from. */
  private final AuditStage stage;

  /** The error. */
  private final UnrecoverableErrorException error;

  /**
   * Constructor.
   *
   * @param requester the requester, as far as it is known
   * @param stage the stage that the error came from, or {@code null} if it is not known
   * @param error the error
   */
  public AuthnUnrecoverableErrorEvent(final @NonNull AuditRequester requester, final @Nullable AuditStage stage,
      final @NonNull UnrecoverableErrorException error) {
    super(requester, null);
    this.stage = stage;
    this.error = Objects.requireNonNull(error, "error must not be null");
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
   * Gets the error.
   *
   * @return the error
   */
  public @NonNull UnrecoverableErrorException getError() {
    return this.error;
  }

}
