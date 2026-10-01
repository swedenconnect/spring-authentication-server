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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * An issued access token, kept by the OpenID Provider with what the UserInfo endpoint needs. The token itself is an
 * opaque random value that reveals nothing about the user.
 *
 * @param value the token value
 * @param clientId the {@code client_id} of the client the token was issued to
 * @param subject the {@code sub} of the user for the client
 * @param scopes the scopes the token was issued for
 * @param userInfoClaims the identity claims for the UserInfo endpoint, as a JSON object
 * @param issuedAt when the token was issued
 * @param expiresAt when the token expires
 * @param singleUse whether the token may only be used once
 * @param correlationId the correlation ID of the authentication flow, so that the client's call to the UserInfo
 *     endpoint is audited under it, or {@code null}
 * @author Martin Lindström
 */
public record AccessTokenData(@NonNull String value, @NonNull String clientId, @NonNull String subject,
    @NonNull List<String> scopes, @NonNull String userInfoClaims, @NonNull Instant issuedAt,
    @NonNull Instant expiresAt, boolean singleUse, @Nullable String correlationId) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param value the token value
   * @param clientId the {@code client_id}
   * @param subject the {@code sub}
   * @param scopes the scopes
   * @param userInfoClaims the UserInfo claims as JSON
   * @param issuedAt when the token was issued
   * @param expiresAt when the token expires
   * @param singleUse whether the token may only be used once
   * @param correlationId the correlation ID of the authentication flow, or {@code null}
   */
  public AccessTokenData {
    Objects.requireNonNull(value, "value must not be null");
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(subject, "subject must not be null");
    scopes = List.copyOf(Objects.requireNonNull(scopes, "scopes must not be null"));
    Objects.requireNonNull(userInfoClaims, "userInfoClaims must not be null");
    Objects.requireNonNull(issuedAt, "issuedAt must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
  }

  /**
   * Tells whether the token has expired.
   *
   * @param now the current time
   * @return {@code true} if the token has expired and {@code false} otherwise
   */
  public boolean isExpired(final @NonNull Instant now) {
    return !now.isBefore(this.expiresAt);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "client-id='%s', expires-at=%s, single-use=%s".formatted(this.clientId, this.expiresAt, this.singleUse);
  }

}
