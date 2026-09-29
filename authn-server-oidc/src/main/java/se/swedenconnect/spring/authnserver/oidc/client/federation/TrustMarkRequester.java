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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Instant;
import java.util.Objects;

import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Asks a trust mark issuer for a trust mark that a client holds but that the resolve response did not carry.
 *
 * @author Martin Lindström
 */
public interface TrustMarkRequester {

  /**
   * Asks for a trust mark.
   *
   * @param clientId the {@code client_id} of the client, which is its entity identifier
   * @param trustMarkType the trust mark type to ask for
   * @return a {@link TrustMark}, or {@code null} if no issuer is configured for the type or the issuer has not
   *           issued the trust mark to the client
   * @throws ClientRegistryException if the call to the issuer fails or the trust mark does not verify
   */
  @Nullable TrustMark request(final @Nonnull String clientId, final @Nonnull String trustMarkType)
      throws ClientRegistryException;

  /**
   * A trust mark that has been verified.
   *
   * @param type the trust mark type
   * @param expiresAt when the trust mark is no longer valid, or {@code null} if it does not expire
   */
  record TrustMark(@Nonnull String type, @Nullable Instant expiresAt) {

    /**
     * Constructor.
     *
     * @param type the trust mark type
     * @param expiresAt when the trust mark is no longer valid, or {@code null}
     */
    public TrustMark {
      Objects.requireNonNull(type, "type must not be null");
      if (!StringUtils.hasText(type)) {
        throw new IllegalArgumentException("type must not be empty");
      }
    }

  }

}
