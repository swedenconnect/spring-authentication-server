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
package se.swedenconnect.spring.authnserver.authentication.provider;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * What a {@link UserAuthenticationProvider} is given: what the requester asks for, who is asking, the authentication
 * from the session that may be reused, and the data of the request that only the protocol module understands.
 *
 * @author Martin Lindström
 */
public class UserAuthenticationInputToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** What the requester asks for. */
  private final AuthenticationRequirements authnRequirements;

  /** Who is asking. */
  private final Requester requester;

  /** The identifier of the request. */
  private final String requestId;

  /** Protocol specific data about the request. */
  private final Serializable protocolRequestData;

  /** The authentication from the session that may be reused. */
  private UserAuthentication previousAuthentication;

  /**
   * Constructor.
   *
   * @param authnRequirements what the requester asks for
   * @param requester who is asking
   */
  public UserAuthenticationInputToken(final @Nonnull AuthenticationRequirements authnRequirements,
      final @Nonnull Requester requester) {
    this(authnRequirements, requester, null, null);
  }

  /**
   * Constructor.
   *
   * @param authnRequirements what the requester asks for
   * @param requester who is asking
   * @param requestId the identifier of the request, the ID of the SAML {@code AuthnRequest}. OpenID Connect has no such
   *          identifier, so {@code null} is given for that protocol
   * @param protocolRequestData protocol specific data about the request, may be {@code null}
   */
  public UserAuthenticationInputToken(final @Nonnull AuthenticationRequirements authnRequirements,
      final @Nonnull Requester requester, final @Nullable String requestId,
      final @Nullable Serializable protocolRequestData) {
    super(List.of());
    this.authnRequirements = Objects.requireNonNull(authnRequirements, "authnRequirements must not be null");
    this.requester = Objects.requireNonNull(requester, "requester must not be null");
    this.requestId = requestId;
    this.protocolRequestData = protocolRequestData;
    this.setAuthenticated(false);
  }

  /**
   * Gets what the requester asks for.
   *
   * @return the authentication requirements
   */
  public @Nonnull AuthenticationRequirements getAuthnRequirements() {
    return this.authnRequirements;
  }

  /**
   * Gets who is asking.
   *
   * @return the requester
   */
  public @Nonnull Requester getRequester() {
    return this.requester;
  }

  /**
   * Gets the identifier of the request.
   *
   * @return the request identifier, or {@code null} if the protocol has none
   */
  public @Nullable String getRequestId() {
    return this.requestId;
  }

  /**
   * Gets the protocol specific data about the request. A provider that needs to look at the actual request asks for it
   * and casts it to the type its protocol module uses.
   *
   * @return the protocol specific request data, or {@code null} if there is none
   */
  public @Nullable Serializable getProtocolRequestData() {
    return this.protocolRequestData;
  }

  /**
   * Gets the authentication from the session that may be reused.
   *
   * @return the previous authentication, or {@code null} if there is none
   */
  public @Nullable UserAuthentication getPreviousAuthentication() {
    return this.previousAuthentication;
  }

  /**
   * Assigns the authentication from the session that may be reused.
   *
   * @param previousAuthentication the previous authentication, may be {@code null}
   */
  public void setPreviousAuthentication(final @Nullable UserAuthentication previousAuthentication) {
    this.previousAuthentication = previousAuthentication;
  }

  /**
   * Maps to {@link #getRequester()}.
   */
  @Override
  public @Nonnull Object getPrincipal() {
    return this.requester;
  }

  /**
   * Always returns the empty string.
   */
  @Override
  public @Nonnull Object getCredentials() {
    return "";
  }

  /**
   * Gets a string that identifies the request, for logging.
   *
   * @return a log string
   */
  public @Nonnull String getLogString() {
    return this.requestId != null
        ? "requester: '%s', request: '%s'".formatted(this.requester, this.requestId)
        : "requester: '%s'".formatted(this.requester);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String toString() {
    return this.getLogString();
  }

}
