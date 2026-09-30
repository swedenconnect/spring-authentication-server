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
package se.swedenconnect.spring.authnserver.oidc.keys;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkMetadataProperties;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

/**
 * Support for the OpenID Provider keys: the key length requirements and the conversion into a public JWK.
 *
 * @author Martin Lindström
 */
final class KeySupport {

  /** The minimum RSA key length, in bits, of Sweden Connect Security Requirements, Section 3. */
  static final int MIN_RSA_KEY_LENGTH = 2048;

  /** The allowed EC curves, which all have at least 256 bits. */
  static final Set<Curve> ALLOWED_CURVES = Set.of(Curve.P_256, Curve.P_384, Curve.P_521);

  /**
   * Checks that the key of a credential is an RSA key of at least {@value #MIN_RSA_KEY_LENGTH} bits or an EC key on one
   * of the {@link #ALLOWED_CURVES}.
   *
   * @param credential the credential
   * @param use what the key is used for, for the error message
   * @throws IllegalArgumentException if the key does not meet the requirements
   */
  static void assertKeyRequirements(final @NonNull PkiCredential credential, final @NonNull String use) {
    final PublicKey publicKey = credential.getPublicKey();
    if (publicKey instanceof final RSAPublicKey rsa) {
      if (rsa.getModulus().bitLength() < MIN_RSA_KEY_LENGTH) {
        throw new IllegalArgumentException(
            "The OIDC %s key '%s' is an RSA key of %d bits - at least %d bits are required".formatted(
                use, credential.getName(), rsa.getModulus().bitLength(), MIN_RSA_KEY_LENGTH));
      }
    }
    else if (publicKey instanceof final ECPublicKey ec) {
      final Curve curve = Curve.forECParameterSpec(ec.getParams());
      if (curve == null || !ALLOWED_CURVES.contains(curve)) {
        throw new IllegalArgumentException(
            "The OIDC %s key '%s' is an EC key on an unsupported curve - P-256, P-384 or P-521 is required"
                .formatted(use, credential.getName()));
      }
    }
    else {
      throw new IllegalArgumentException("The OIDC %s key '%s' has the unsupported key type %s - RSA or EC is required"
          .formatted(use, credential.getName(), publicKey.getAlgorithm()));
    }
  }

  /**
   * Gets the EC curve of a key.
   *
   * @param publicKey the key
   * @return the curve, or {@code null} if the key is not an EC key
   */
  static @Nullable Curve getCurve(final @NonNull PublicKey publicKey) {
    return publicKey instanceof final ECPublicKey ec ? Curve.forECParameterSpec(ec.getParams()) : null;
  }

  /**
   * Gets the JOSE algorithm assigned in the metadata of a credential ({@code jose-alg}).
   *
   * @param credential the credential
   * @return the algorithm, or {@code null} if none has been assigned
   */
  static @Nullable Algorithm getAssignedAlgorithm(final @NonNull PkiCredential credential) {
    return JwkMetadataProperties.getJoseAlgorithm(credential.getMetadata());
  }

  /**
   * Creates the public JWK of a credential, with its key ID and the supplied use.
   *
   * @param credential the credential
   * @param use the key use
   * @return a public JWK
   * @throws IllegalArgumentException if no key ID could be established
   */
  static @NonNull JWK toPublicJwk(final @NonNull PkiCredential credential, final @NonNull KeyUse use) {
    final JWK jwk = JwkTransformerFunction.publicJwkFunction()
        .withKeyUseFunction(c -> use)
        .withKeyOpsFunction(c -> null)
        .apply(credential);
    if (jwk.getKeyID() == null || jwk.getKeyID().isBlank()) {
      throw new IllegalArgumentException("No key ID could be established for the OIDC key '%s'"
          .formatted(credential.getName()));
    }
    return jwk;
  }

  /**
   * Keeps only the algorithms that a key assigned an algorithm may be used with.
   *
   * @param credential the credential
   * @param candidates the algorithms that the key type supports
   * @param use what the key is used for, for the error message
   * @param <A> the algorithm type
   * @return the algorithms
   * @throws IllegalArgumentException if the assigned algorithm is not among the candidates
   */
  static <A extends Algorithm> @NonNull List<A> restrictToAssigned(final @NonNull PkiCredential credential,
      final @NonNull List<A> candidates, final @NonNull String use) {
    final Algorithm assigned = getAssignedAlgorithm(credential);
    if (assigned == null) {
      return candidates;
    }
    final List<A> restricted = candidates.stream().filter(a -> a.getName().equals(assigned.getName())).toList();
    if (restricted.isEmpty()) {
      throw new IllegalArgumentException("The algorithm %s assigned to the OIDC %s key '%s' cannot be used with the key"
          .formatted(assigned.getName(), use, credential.getName()));
    }
    return restricted;
  }

  // Hidden constructor
  private KeySupport() {
  }

}
