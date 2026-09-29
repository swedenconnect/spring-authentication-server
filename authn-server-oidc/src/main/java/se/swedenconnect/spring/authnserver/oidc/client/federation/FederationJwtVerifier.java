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

import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Verifies the signed JWTs that the federation endpoints answer with: the explicit type of the JWT, its signature
 * against the configured keys of the entity that issued it, the issuer and the subject, and that the JWT has not
 * expired.
 *
 * @author Martin Lindström
 */
class FederationJwtVerifier {

  /**
   * Verifies a signed JWT and returns its claims.
   *
   * @param jwt the JWT to verify
   * @param type the value that the {@code typ} header must have
   * @param keys the keys that the signature is verified against
   * @param issuer the entity identifier that the {@code iss} claim must have
   * @param subject the entity identifier that the {@code sub} claim must have
   * @param requiredClaims the claims that must be present
   * @return the claims of the JWT
   * @throws ClientRegistryException if the JWT does not verify
   */
  static @Nonnull JWTClaimsSet verify(final @Nonnull SignedJWT jwt, final @Nonnull String type,
      final @Nonnull JWKSet keys, final @Nonnull String issuer, final @Nonnull String subject,
      final @Nonnull Set<String> requiredClaims) throws ClientRegistryException {

    Objects.requireNonNull(jwt, "jwt must not be null");
    final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(type)));
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
        JWSAlgorithm.Family.SIGNATURE, new ImmutableJWKSet<>(keys)));
    processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
        new JWTClaimsSet.Builder().issuer(issuer).subject(subject).build(), requiredClaims));
    try {
      return processor.process(jwt, null);
    }
    catch (final Exception e) {
      throw new ClientRegistryException(
          "Failed to verify %s issued by %s for %s - %s".formatted(type, issuer, subject, e.getMessage()), e);
    }
  }

  // Hidden constructor
  private FederationJwtVerifier() {
  }

}
