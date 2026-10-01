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
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * The requester as an audit event records it. This is the common data of every authentication event, and it gives the
 * principal of the event.
 * <p>
 * A requester is verified once the server has established who sent the request: the requester is known in the client
 * registry and the request passed the checks that tie it to the requester. Until then the identifier is only what the
 * request claims, and may be missing.
 * </p>
 *
 * @param protocol the protocol, or {@code null} if it is not known
 * @param identifier the identifier of the requester, a SAML entityID or an OpenID Connect {@code client_id}, or
 *     {@code null} if the request names no requester
 * @param organizationNumber the organisation number of the requester exactly as the client registry holds it, or
 *     {@code null}
 * @param verified whether the requester has been verified
 * @author Martin Lindström
 */
public record AuditRequester(@Nullable AuthenticationProtocol protocol, @Nullable String identifier,
    @Nullable String organizationNumber, boolean verified) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The principal of an event whose requester is not known. */
  public static final String UNKNOWN_PRINCIPAL = "unknown";

  /**
   * Constructor.
   *
   * @param protocol the protocol, or {@code null}
   * @param identifier the identifier of the requester, or {@code null}
   * @param organizationNumber the organisation number of the requester, or {@code null}
   * @param verified whether the requester has been verified
   */
  public AuditRequester {
    identifier = StringUtils.hasText(identifier) ? identifier : null;
    organizationNumber = StringUtils.hasText(organizationNumber) ? organizationNumber : null;
  }

  /**
   * A requester that is not known at all.
   *
   * @param protocol the protocol, or {@code null} if it is not known either
   * @return an {@link AuditRequester}
   */
  public static @NonNull AuditRequester unknown(final @Nullable AuthenticationProtocol protocol) {
    return new AuditRequester(protocol, null, null, false);
  }

  /**
   * A requester that a request names, but that has not been verified.
   *
   * @param protocol the protocol
   * @param identifier the identifier that the request gives, or {@code null}
   * @return an {@link AuditRequester}
   */
  public static @NonNull AuditRequester named(final @NonNull AuthenticationProtocol protocol,
      final @Nullable String identifier) {
    return new AuditRequester(protocol, identifier, null, false);
  }

  /**
   * A requester that is known in the client registry.
   *
   * @param record the record of the requester
   * @param verified whether the request has been tied to the requester
   * @return an {@link AuditRequester}
   */
  public static @NonNull AuditRequester of(final @NonNull RequesterRecord record, final boolean verified) {
    Objects.requireNonNull(record, "record must not be null");
    return new AuditRequester(record.getProtocol(), record.getIdentifier(), record.organizationNumber(), verified);
  }

  /**
   * Gets this requester, marked as verified.
   *
   * @return an {@link AuditRequester}
   */
  public @NonNull AuditRequester asVerified() {
    return new AuditRequester(this.protocol, this.identifier, this.organizationNumber, true);
  }

  /**
   * Gets the principal of an audit event for this requester: the identifier, or {@value #UNKNOWN_PRINCIPAL} if there
   * is none.
   *
   * @return the principal
   */
  public @NonNull String getPrincipal() {
    return this.identifier != null ? this.identifier : UNKNOWN_PRINCIPAL;
  }

}
