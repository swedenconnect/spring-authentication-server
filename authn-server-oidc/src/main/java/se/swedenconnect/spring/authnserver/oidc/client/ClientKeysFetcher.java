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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.io.IOException;
import java.net.URI;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Fetches the keys that a federation client publishes at its {@code jwks_uri} or {@code signed_jwks_uri}, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">OpenID Federation 1.0, Section
 * 5.2.1</a>. The signature of a signed JWK Set is verified by the caller.
 *
 * @author Martin Lindström
 */
public interface ClientKeysFetcher {

  /**
   * Fetches the JWK Set at a {@code jwks_uri}.
   *
   * @param jwksUri the URI
   * @return the JWK Set
   * @throws IOException if the JWK Set cannot be fetched or read: the host cannot be reached, the answer is not a 2xx
   *     answer, or the body is not a JWK Set
   */
  @NonNull JWKSet fetchJwks(final @NonNull URI jwksUri) throws IOException;

  /**
   * Fetches the signed JWK Set at a {@code signed_jwks_uri}.
   *
   * @param signedJwksUri the URI
   * @return the signed JWT, not verified
   * @throws IOException if the JWT cannot be fetched or read: the host cannot be reached, the answer is not a 200
   *     answer with the content type {@code application/jwk-set+jwt}, or the body is not a signed JWT
   */
  @NonNull SignedJWT fetchSignedJwks(final @NonNull URI signedJwksUri) throws IOException;

}
