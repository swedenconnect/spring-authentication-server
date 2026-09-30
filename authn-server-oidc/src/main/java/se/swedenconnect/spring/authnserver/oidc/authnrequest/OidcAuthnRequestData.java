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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;

/**
 * The OpenID Connect specific data about a processed authentication request, carried as the protocol request data of
 * the {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
 * UserAuthenticationInputToken}. It holds what is needed to answer the request and to issue tokens.
 *
 * @param responseTarget where and how to answer
 * @param nonce the {@code nonce}, or {@code null}
 * @param codeChallenge the PKCE code challenge, or {@code null}
 * @param codeChallengeMethod the PKCE code challenge method, always {@code S256} when a challenge is present
 * @param scopes all requested scopes, including those that the OpenID Provider does not offer
 * @param claimsRequest the {@code claims} parameter as a JSON string, or {@code null}
 * @author Martin Lindström
 */
public record OidcAuthnRequestData(@Nonnull OidcResponseTarget responseTarget, @Nullable String nonce,
    @Nullable String codeChallenge, @Nullable String codeChallengeMethod, @Nonnull List<String> scopes,
    @Nullable String claimsRequest) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param responseTarget where and how to answer
   * @param nonce the {@code nonce}, or {@code null}
   * @param codeChallenge the PKCE code challenge, or {@code null}
   * @param codeChallengeMethod the PKCE code challenge method, or {@code null}
   * @param scopes all requested scopes
   * @param claimsRequest the {@code claims} parameter as a JSON string, or {@code null}
   */
  public OidcAuthnRequestData {
    Objects.requireNonNull(responseTarget, "responseTarget must not be null");
    scopes = List.copyOf(Objects.requireNonNull(scopes, "scopes must not be null"));
  }

}
