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
 * An issued authorization code and everything it is bound to: the client, the redirect URI, the PKCE challenge, the
 * nonce, and what the ID token says about the authentication, together with the {@code sub} and the claims that were
 * released when the code was issued.
 * <p>
 * The object holds strings, instants and JSON only, so that it can be kept in a store outside of the JVM.
 * </p>
 *
 * @param code the code
 * @param clientId the {@code client_id} of the client the code was issued to
 * @param redirectUri the redirect URI of the request
 * @param codeChallenge the PKCE code challenge, or {@code null}
 * @param codeChallengeMethod the PKCE code challenge method, or {@code null}
 * @param nonce the {@code nonce} of the request, or {@code null}
 * @param scopes the requested scopes that the OpenID Provider offers
 * @param subject the {@code sub} of the user for the client
 * @param authnInstant when the user authenticated, the {@code auth_time} of the ID token
 * @param acr the authentication context class of the authentication, the {@code acr} of the ID token
 * @param idTokenClaims the identity claims for the ID token, as a JSON object
 * @param userInfoClaims the identity claims for the UserInfo endpoint, as a JSON object
 * @param issuedAt when the code was issued
 * @param expiresAt when the code expires
 * @param retainUntil until when the code is kept after it has been used, so that a second use can be detected
 * @param correlationId the correlation ID of the authentication flow, so that the client's call to the token endpoint
 *     is audited under it, or {@code null}
 * @author Martin Lindström
 */
public record AuthorizationCodeData(
    @NonNull String code, @NonNull String clientId, @NonNull String redirectUri, @Nullable String codeChallenge,
    @Nullable String codeChallengeMethod, @Nullable String nonce, @NonNull List<String> scopes,
    @NonNull String subject, @NonNull Instant authnInstant, @NonNull String acr,
    @NonNull String idTokenClaims, @NonNull String userInfoClaims, @NonNull Instant issuedAt,
    @NonNull Instant expiresAt, @NonNull Instant retainUntil, @Nullable String correlationId)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param code the code
   * @param clientId the {@code client_id}
   * @param redirectUri the redirect URI
   * @param codeChallenge the PKCE code challenge, or {@code null}
   * @param codeChallengeMethod the PKCE code challenge method, or {@code null}
   * @param nonce the nonce, or {@code null}
   * @param scopes the scopes
   * @param subject the {@code sub}
   * @param authnInstant when the user authenticated
   * @param acr the authentication context class
   * @param idTokenClaims the ID token claims as JSON
   * @param userInfoClaims the UserInfo claims as JSON
   * @param issuedAt when the code was issued
   * @param expiresAt when the code expires
   * @param retainUntil until when the code is kept after use
   * @param correlationId the correlation ID of the authentication flow, or {@code null}
   */
  public AuthorizationCodeData {
    Objects.requireNonNull(code, "code must not be null");
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(redirectUri, "redirectUri must not be null");
    scopes = List.copyOf(Objects.requireNonNull(scopes, "scopes must not be null"));
    Objects.requireNonNull(subject, "subject must not be null");
    Objects.requireNonNull(authnInstant, "authnInstant must not be null");
    Objects.requireNonNull(acr, "acr must not be null");
    Objects.requireNonNull(idTokenClaims, "idTokenClaims must not be null");
    Objects.requireNonNull(userInfoClaims, "userInfoClaims must not be null");
    Objects.requireNonNull(issuedAt, "issuedAt must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    Objects.requireNonNull(retainUntil, "retainUntil must not be null");
  }

  /**
   * Tells whether the code has expired.
   *
   * @param now the current time
   * @return {@code true} if the code has expired and {@code false} otherwise
   */
  public boolean isExpired(final @NonNull Instant now) {
    return !now.isBefore(this.expiresAt);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "client-id='%s', expires-at=%s".formatted(this.clientId, this.expiresAt);
  }

}
