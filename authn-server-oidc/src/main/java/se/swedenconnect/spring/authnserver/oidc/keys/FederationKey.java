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

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * A Federation Entity Key of the OpenID Provider, the key that its OpenID Federation entity configuration is signed
 * with. It is separate from the OpenID Connect signing keys, as OpenID Federation 1.0, Section 3.1.1, recommends.
 * <p>
 * An {@link State#ACTIVE active} key is published in the {@code jwks} of the entity configuration and used for
 * signing. A {@link State#FUTURE future} key is published but never used, so that other entities know it before a key
 * rollover.
 * </p>
 * <p>
 * The algorithms are those that both the Swedish OpenID Federation profile, Section 6, and Sweden Connect Security
 * Requirements, Section 3, allow: {@code RS256}, {@code RS384} and {@code RS512} for an RSA key, and the {@code ES}
 * algorithm of its curve for an EC key. When the credential metadata assigns an algorithm ({@code jose-alg}), the key
 * signs with that algorithm only. The key ID follows the same rules as for the OpenID Connect keys.
 * </p>
 *
 * @author Martin Lindström
 */
public final class FederationKey {

  /**
   * The state of a federation key.
   */
  public enum State {

    /** The key is published and used for signing. */
    ACTIVE,

    /** The key is published but not used, ahead of a key rollover. */
    FUTURE
  }

  /** The RSA signing algorithms, the default first. */
  private static final List<JWSAlgorithm> RSA_ALGORITHMS =
      List.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512);

  /** The credential. */
  private final PkiCredential credential;

  /** The state. */
  private final State state;

  /** The public JWK. */
  private final JWK jwk;

  /** The algorithms that the key can produce, the preferred one first. */
  private final List<JWSAlgorithm> algorithms;

  /**
   * Constructor.
   *
   * @param credential the credential
   * @param state the state of the key
   * @throws IllegalArgumentException if the key does not meet the requirements
   */
  public FederationKey(final @NonNull PkiCredential credential, final @NonNull State state) {
    this.credential = Objects.requireNonNull(credential, "credential must not be null");
    this.state = Objects.requireNonNull(state, "state must not be null");
    KeySupport.assertKeyRequirements(credential, "federation");
    this.algorithms = KeySupport.restrictToAssigned(credential, supportedAlgorithms(credential), "federation");
    this.jwk = KeySupport.toPublicJwk(credential, KeyUse.SIGNATURE);
  }

  /**
   * Creates an active key.
   *
   * @param credential the credential
   * @return a {@link FederationKey}
   */
  public static @NonNull FederationKey active(final @NonNull PkiCredential credential) {
    return new FederationKey(credential, State.ACTIVE);
  }

  /**
   * Creates a future key.
   *
   * @param credential the credential
   * @return a {@link FederationKey}
   */
  public static @NonNull FederationKey future(final @NonNull PkiCredential credential) {
    return new FederationKey(credential, State.FUTURE);
  }

  /**
   * Gets the state of the key.
   *
   * @return the state
   */
  public @NonNull State getState() {
    return this.state;
  }

  /**
   * Tells whether the key is active.
   *
   * @return {@code true} if the key is active and {@code false} otherwise
   */
  public boolean isActive() {
    return this.state == State.ACTIVE;
  }

  /**
   * Gets the key ID.
   *
   * @return the key ID
   */
  public @NonNull String getKeyId() {
    return this.jwk.getKeyID();
  }

  /**
   * Gets the public JWK of the key, with its key ID and {@code use} set to {@code sig}.
   *
   * @return the public JWK
   */
  public @NonNull JWK getPublicJwk() {
    return this.jwk;
  }

  /**
   * Gets the algorithm that the key signs with.
   *
   * @return the algorithm
   */
  public @NonNull JWSAlgorithm getAlgorithm() {
    return this.algorithms.getFirst();
  }

  /**
   * Signs a JWT with this key. The header holds the algorithm, the key ID and the type.
   *
   * @param claims the claims of the JWT
   * @param type the value of the {@code typ} header
   * @return the signed JWT
   * @throws JOSEException if the JWT cannot be signed
   */
  public @NonNull SignedJWT sign(final @NonNull JWTClaimsSet claims, final @NonNull JOSEObjectType type)
      throws JOSEException {
    final SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(this.getAlgorithm()).keyID(this.getKeyId()).type(type).build(), claims);
    jwt.sign(this.createSigner());
    return jwt;
  }

  /**
   * Creates a signer for the key.
   *
   * @return a {@link JWSSigner}
   * @throws JOSEException if no signer can be created
   */
  private @NonNull JWSSigner createSigner() throws JOSEException {
    if (this.credential.getPublicKey() instanceof RSAPublicKey) {
      return new RSASSASigner(this.credential.getPrivateKey());
    }
    return new ECDSASigner(this.credential.getPrivateKey(),
        Objects.requireNonNull(KeySupport.getCurve(this.credential.getPublicKey())));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "kid='%s', state=%s, algorithm=%s".formatted(this.getKeyId(), this.state, this.getAlgorithm());
  }

  /**
   * Gets the algorithms that the type of a key supports.
   *
   * @param credential the credential
   * @return the algorithms
   */
  private static @NonNull List<JWSAlgorithm> supportedAlgorithms(final @NonNull PkiCredential credential) {
    if (credential.getPublicKey() instanceof RSAPublicKey) {
      return RSA_ALGORITHMS;
    }
    final Curve curve = Objects.requireNonNull(KeySupport.getCurve(credential.getPublicKey()));
    if (Curve.P_256.equals(curve)) {
      return List.of(JWSAlgorithm.ES256);
    }
    return List.of(Curve.P_384.equals(curve) ? JWSAlgorithm.ES384 : JWSAlgorithm.ES512);
  }

}
