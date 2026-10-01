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
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;

/**
 * Base class for the events of an authentication flow. Every event carries the requester, and most carry a
 * protocol-specific part supplied by the protocol module.
 *
 * @author Martin Lindström
 */
public abstract class AbstractAuthnEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The protocol-specific part of the event. */
  private final ProtocolAuditData protocolData;

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param protocolData the protocol-specific part of the event, or {@code null}
   */
  protected AbstractAuthnEvent(final @NonNull AuditRequester requester,
      final @Nullable ProtocolAuditData protocolData) {
    super(Objects.requireNonNull(requester, "requester must not be null"));
    this.protocolData = protocolData;
  }

  /**
   * Gets the requester.
   *
   * @return the requester
   */
  public @NonNull AuditRequester getRequester() {
    return (AuditRequester) this.getSource();
  }

  /**
   * Gets the protocol-specific part of the event.
   *
   * @return the protocol-specific data, or {@code null}
   */
  public @Nullable ProtocolAuditData getProtocolData() {
    return this.protocolData;
  }

}
