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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Keeps issued authorization codes.
 * <p>
 * A code may only be used once. The store keeps a used code until its {@link AuthorizationCodeData#retainUntil()},
 * together with the access token that was issued for it, so that a second use can be detected and the access token
 * revoked, as RFC 6749, Section 4.1.2, says.
 * </p>
 * <p>
 * The default, {@link InMemoryAuthorizationCodeStore}, only serves the node it runs on.
 * </p>
 *
 * @author Martin Lindström
 */
public interface AuthorizationCodeStore {

  /**
   * Saves an issued code.
   *
   * @param code the code
   */
  void save(final @NonNull AuthorizationCodeData code);

  /**
   * Redeems a code. The first call for a code that has not expired marks it as used. Later calls tell that the code
   * has been used before.
   *
   * @param code the code value
   * @return the redemption, or {@code null} if the code is not known or has expired
   */
  @Nullable Redemption redeem(final @NonNull String code);

  /**
   * Registers the access token that was issued for a code, so that it can be revoked if the code is used again.
   *
   * @param code the code value
   * @param accessToken the access token value
   */
  void registerAccessToken(final @NonNull String code, final @NonNull String accessToken);

  /**
   * The result of redeeming a code.
   *
   * @param code the code
   * @param replay {@code true} if the code had been used before
   * @param accessToken the access token issued at the first use, or {@code null}
   */
  record Redemption(@NonNull AuthorizationCodeData code, boolean replay, @Nullable String accessToken) {
  }

}
