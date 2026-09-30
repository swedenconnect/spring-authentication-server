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

import java.time.Instant;

import org.jspecify.annotations.NonNull;

/**
 * Remembers the {@code jti} values of the client assertions that have been used for client authentication
 * ({@code private_key_jwt} and {@code client_secret_jwt}), so that an assertion cannot be used twice.
 * <p>
 * The default, {@link InMemoryClientAssertionReplayCache}, only serves the node it runs on.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface ClientAssertionReplayCache {

  /**
   * Registers a {@code jti} of a client, and tells whether it had been seen before.
   *
   * @param clientId the {@code client_id}
   * @param jti the {@code jti} of the assertion
   * @param expiresAt when the assertion expires, until which the value is remembered
   * @return {@code true} if the value is new and {@code false} if it has been used before
   */
  boolean register(final @NonNull String clientId, final @NonNull String jti, final @NonNull Instant expiresAt);

}
