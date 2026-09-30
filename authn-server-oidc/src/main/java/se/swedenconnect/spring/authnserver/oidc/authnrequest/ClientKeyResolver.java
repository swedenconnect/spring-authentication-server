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

import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Finds the keys of a client that may have signed a JWT, such as a request object.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface ClientKeyResolver {

  /**
   * Finds the client's keys that match the header of a signed JWT.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param header the header of the signed JWT
   * @return the candidate keys, possibly empty
   * @throws KeySourceException if the keys cannot be obtained
   */
  @Nonnull
  List<JWK> resolve(final @Nonnull String clientId, final @Nonnull OIDCClientMetadata metadata,
      final @Nonnull JWSHeader header) throws KeySourceException;

}
