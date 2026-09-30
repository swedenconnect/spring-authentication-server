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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * A key that the OpenID Provider signs with, for example ID tokens and UserInfo responses.
 * <p>
 * An {@link State#ACTIVE active} key is published in the JWKS and used for signing. A {@link State#FUTURE future} key
 * is published but never used, so that clients know it before a key rollover. One active key is the default key, used
 * for clients that do not tell which algorithm they want.
 * </p>
 * <p>
 * The algorithms that a key can produce follow from its type: {@code RS256}, {@code RS384}, {@code RS512},
 * {@code PS256}, {@code PS384} and {@code PS512} for an RSA key, and the {@code ES} algorithm of its curve for an EC
 * key. When the credential metadata assigns an algorithm ({@code jose-alg}), the key produces only that algorithm. The
 * key must be an RSA key of at least 2048 bits or an EC key on P-256, P-384 or P-521.
 * </p>
 * <p>
 * The key ID ({@code kid}) is the {@code key-id} of the credential metadata, or else the RFC 7638 thumbprint of the
 * key, so it stays the same across restarts.
 * </p>
 *
 * @author Martin Lindström
 */
public final class SigningKey {

  /**
   * The state of a signing key.
   */
  public enum State {

    /** The key is published and used for signing. */
    ACTIVE,

    /** The key is published but not used, ahead of a key rollover. */
    FUTURE
  }

  /** The RSA signing algorithms, the default first. */
  private static final List<JWSAlgorithm> RSA_ALGORITHMS = List.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384,
      JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);

  /** The credential. */
  private final PkiCredential credential;

  /** The state. */
  private final State state;

  /** Whether this is the default key. */
  private final boolean defaultKey;

  /** The public JWK. */
  private final JWK jwk;

  /** The algorithms that the key can produce, the preferred one first. */
  private final List<JWSAlgorithm> algorithms;

  /**
   * Constructor.
   *
   * @param credential the credential
   * @param state the state of the key
   * @param defaultKey whether this is the default key, only allowed for an active key
   * @throws IllegalArgumentException if the key does not meet the requirements, or a future key is marked as default
   */
  public SigningKey(final @NonNull PkiCredential credential, final @NonNull State state, final boolean defaultKey) {
    this.credential = Objects.requireNonNull(credential, "credential must not be null");
    this.state = Objects.requireNonNull(state, "state must not be null");
    if (defaultKey && state != State.ACTIVE) {
      throw new IllegalArgumentException("The OIDC signing key '%s' is marked as default but is not active"
          .formatted(credential.getName()));
    }
    this.defaultKey = defaultKey;
    KeySupport.assertKeyRequirements(credential, "signing");
    this.algorithms = KeySupport.restrictToAssigned(credential, supportedAlgorithms(credential), "signing");
    this.jwk = KeySupport.toPublicJwk(credential, KeyUse.SIGNATURE);
  }

  /**
   * Creates an active key.
   *
   * @param credential the credential
   * @return a {@link SigningKey}
   */
  public static @NonNull SigningKey active(final @NonNull PkiCredential credential) {
    return new SigningKey(credential, State.ACTIVE, false);
  }

  /**
   * Creates an active key that is the default key.
   *
   * @param credential the credential
   * @return a {@link SigningKey}
   */
  public static @NonNull SigningKey activeDefault(final @NonNull PkiCredential credential) {
    return new SigningKey(credential, State.ACTIVE, true);
  }

  /**
   * Creates a future key.
   *
   * @param credential the credential
   * @return a {@link SigningKey}
   */
  public static @NonNull SigningKey future(final @NonNull PkiCredential credential) {
    return new SigningKey(credential, State.FUTURE, false);
  }

  /**
   * Gets the credential.
   *
   * @return the credential
   */
  public @NonNull PkiCredential getCredential() {
    return this.credential;
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
   * Tells whether the key has been marked as the default key.
   *
   * @return {@code true} if the key is marked as default and {@code false} otherwise
   */
  public boolean isDefaultKey() {
    return this.defaultKey;
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
   * Gets the algorithms that the key can produce, the preferred one first.
   *
   * @return the algorithms
   */
  public @NonNull List<JWSAlgorithm> getAlgorithms() {
    return this.algorithms;
  }

  /**
   * Gets the algorithm that the key signs with when the client has not asked for one.
   *
   * @return the preferred algorithm
   */
  public @NonNull JWSAlgorithm getPreferredAlgorithm() {
    return this.algorithms.getFirst();
  }

  /**
   * Tells whether the key can produce an algorithm.
   *
   * @param algorithm the algorithm
   * @return {@code true} if the key can produce the algorithm and {@code false} otherwise
   */
  public boolean supports(final @NonNull JWSAlgorithm algorithm) {
    return this.algorithms.contains(algorithm);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "kid='%s', state=%s, default=%s, algorithms=%s".formatted(
        this.getKeyId(), this.state, this.defaultKey, this.algorithms);
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
