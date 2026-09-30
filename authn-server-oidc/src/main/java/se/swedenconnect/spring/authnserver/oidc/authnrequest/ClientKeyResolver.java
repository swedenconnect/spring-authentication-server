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

import java.util.List;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Finds the keys of a client: the keys that may have signed a JWT, such as a request object or a client assertion,
 * and the keys to encrypt for.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface ClientKeyResolver {

  /**
   * Finds the client's keys that match a matcher.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param matcher the matcher
   * @return the matching keys, possibly empty
   * @throws KeySourceException if the keys cannot be obtained
   */
  @NonNull List<JWK> resolve(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher) throws KeySourceException;

  /**
   * Finds the client's keys that match the header of a signed JWT.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param header the header of the signed JWT
   * @return the candidate keys, possibly empty
   * @throws KeySourceException if the keys cannot be obtained
   */
  default @NonNull List<JWK> resolve(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWSHeader header) throws KeySourceException {
    return this.resolve(clientId, metadata, JWKMatcher.forJWSHeader(header));
  }

}
