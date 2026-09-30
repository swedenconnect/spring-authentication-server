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
 * Keeps issued access tokens.
 * <p>
 * The default, {@link InMemoryAccessTokenStore}, only serves the node it runs on.
 * </p>
 *
 * @author Martin Lindström
 */
public interface AccessTokenStore {

  /**
   * Saves an issued access token.
   *
   * @param token the token
   */
  void save(final @NonNull AccessTokenData token);

  /**
   * Gets an access token that is valid: known, not expired, not revoked and, for a single use token, not used.
   *
   * @param value the token value
   * @return the token, or {@code null} if it is not valid
   */
  @Nullable AccessTokenData get(final @NonNull String value);

  /**
   * Marks a single use token as used. A token that is not single use is not affected.
   *
   * @param value the token value
   * @return {@code true} if the token was valid and is now marked as used, or is not single use, and {@code false} if
   *     it was not valid
   */
  boolean markUsed(final @NonNull String value);

  /**
   * Revokes an access token.
   *
   * @param value the token value
   */
  void revoke(final @NonNull String value);

}
