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

import jakarta.annotation.Nonnull;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * A key that the OpenID Provider decrypts with, for example encrypted request objects.
 * <p>
 * An {@link State#ACTIVE active} key is published in the JWKS and used for decryption. A {@link State#PREVIOUS
 * previous} key is not published, but is still used for decryption for a while after a key rollover.
 * </p>
 * <p>
 * The algorithms that a key supports follow from its type: {@code RSA-OAEP-256} and {@code RSA-OAEP} for an RSA key,
 * and {@code ECDH-ES}, {@code ECDH-ES+A128KW}, {@code ECDH-ES+A192KW} and {@code ECDH-ES+A256KW} for an EC key. When
 * the credential metadata assigns an algorithm ({@code jose-alg}), the key supports only that algorithm. The key must
 * be an RSA key of at least 2048 bits or an EC key on P-256, P-384 or P-521.
 * </p>
 * <p>
 * The key ID ({@code kid}) is the {@code key-id} of the credential metadata, or else the RFC 7638 thumbprint of the
 * key, so it stays the same across restarts.
 * </p>
 *
 * @author Martin Lindström
 */
public final class DecryptionKey {

  /**
   * The state of a decryption key.
   */
  public enum State {

    /** The key is published and used for decryption. */
    ACTIVE,

    /** The key is not published, but is still used for decryption after a key rollover. */
    PREVIOUS
  }

  /** The RSA key management algorithms. */
  private static final List<JWEAlgorithm> RSA_ALGORITHMS = List.of(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP);

  /** The EC key management algorithms. */
  private static final List<JWEAlgorithm> EC_ALGORITHMS = List.of(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW,
      JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW);

  /** The credential. */
  private final PkiCredential credential;

  /** The state. */
  private final State state;

  /** The public JWK. */
  private final JWK jwk;

  /** The algorithms that the key supports. */
  private final List<JWEAlgorithm> algorithms;

  /**
   * Constructor.
   *
   * @param credential the credential
   * @param state the state of the key
   * @throws IllegalArgumentException if the key does not meet the requirements
   */
  public DecryptionKey(final @Nonnull PkiCredential credential, final @Nonnull State state) {
    this.credential = Objects.requireNonNull(credential, "credential must not be null");
    this.state = Objects.requireNonNull(state, "state must not be null");
    KeySupport.assertKeyRequirements(credential, "decryption");
    this.algorithms = KeySupport.restrictToAssigned(credential,
        credential.getPublicKey() instanceof RSAPublicKey ? RSA_ALGORITHMS : EC_ALGORITHMS, "decryption");
    this.jwk = KeySupport.toPublicJwk(credential, KeyUse.ENCRYPTION);
  }

  /**
   * Creates an active key.
   *
   * @param credential the credential
   * @return a {@link DecryptionKey}
   */
  public static @Nonnull DecryptionKey active(final @Nonnull PkiCredential credential) {
    return new DecryptionKey(credential, State.ACTIVE);
  }

  /**
   * Creates a previous key.
   *
   * @param credential the credential
   * @return a {@link DecryptionKey}
   */
  public static @Nonnull DecryptionKey previous(final @Nonnull PkiCredential credential) {
    return new DecryptionKey(credential, State.PREVIOUS);
  }

  /**
   * Gets the credential.
   *
   * @return the credential
   */
  public @Nonnull PkiCredential getCredential() {
    return this.credential;
  }

  /**
   * Gets the state of the key.
   *
   * @return the state
   */
  public @Nonnull State getState() {
    return this.state;
  }

  /**
   * Tells whether the key is active, that is, published.
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
  public @Nonnull String getKeyId() {
    return this.jwk.getKeyID();
  }

  /**
   * Gets the public JWK of the key, with its key ID and {@code use} set to {@code enc}.
   *
   * @return the public JWK
   */
  public @Nonnull JWK getPublicJwk() {
    return this.jwk;
  }

  /**
   * Gets the key management algorithms that the key supports.
   *
   * @return the algorithms
   */
  public @Nonnull List<JWEAlgorithm> getAlgorithms() {
    return this.algorithms;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull String toString() {
    return "kid='%s', state=%s, algorithms=%s".formatted(this.getKeyId(), this.state, this.algorithms);
  }

}
