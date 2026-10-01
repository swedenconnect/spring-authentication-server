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
package se.swedenconnect.spring.authnserver.audit;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * What the audit needs to know about an accepted request for the rest of its flow. It is kept with the request, and
 * thereby with the authentication in progress in the session, so that every request of the flow is audited under the
 * same correlation ID and with the same requester, whichever server instance handles it.
 *
 * @param correlationId the correlation ID of the flow
 * @param requester the requester
 * @param authnRequest the protocol-specific data about the request, or {@code null}
 * @author Martin Lindström
 */
public record AuditFlowData(@NonNull String correlationId, @NonNull AuditRequester requester,
    @Nullable ProtocolAuditData authnRequest) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param correlationId the correlation ID of the flow
   * @param requester the requester
   * @param authnRequest the protocol-specific data about the request, or {@code null}
   */
  public AuditFlowData {
    Objects.requireNonNull(correlationId, "correlationId must not be null");
    Objects.requireNonNull(requester, "requester must not be null");
  }

  /**
   * Creates the flow data for a request that has been accepted, under the correlation ID of the current request. A
   * correlation ID is generated if the current request has none.
   *
   * @param requester the requester
   * @param authnRequest the protocol-specific data about the request, or {@code null}
   * @return an {@link AuditFlowData}
   */
  public static @NonNull AuditFlowData of(final @NonNull AuditRequester requester,
      final @Nullable ProtocolAuditData authnRequest) {
    return new AuditFlowData(FlowCorrelation.ensure(), requester, authnRequest);
  }

}
