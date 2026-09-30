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
import jakarta.annotation.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * The keys of the OpenID Provider: the signing keys and the decryption keys.
 * <p>
 * The rules, checked when the object is created:
 * </p>
 * <ul>
 * <li>There is at least one active signing key.</li>
 * <li>Exactly one active signing key is the default key. When there is only one active signing key and none is
 * marked, that key is the default key.</li>
 * <li>The key IDs of the signing keys are unique, and so are the key IDs of the decryption keys.</li>
 * </ul>
 * <p>
 * The published JWKS holds the active and future signing keys and the active decryption keys. A previous decryption
 * key is not published, but is returned by {@link #getDecryptionKeys()}, so that it is still used for decryption.
 * </p>
 *
 * @author Martin Lindström
 */
public final class OidcKeys {

  /** The signing keys. */
  private final List<SigningKey> signingKeys;

  /** The decryption keys. */
  private final List<DecryptionKey> decryptionKeys;

  /** The default signing key. */
  private final SigningKey defaultSigningKey;

  /** The published keys. */
  private final JWKSet publishedKeys;

  /**
   * Constructor.
   *
   * @param signingKeys the signing keys
   * @param decryptionKeys the decryption keys, may be {@code null} or empty
   * @throws IllegalArgumentException if the keys break any of the rules
   */
  public OidcKeys(final @Nonnull List<SigningKey> signingKeys, final @Nullable List<DecryptionKey> decryptionKeys) {
    this.signingKeys = List.copyOf(Objects.requireNonNull(signingKeys, "signingKeys must not be null"));
    this.decryptionKeys = decryptionKeys != null ? List.copyOf(decryptionKeys) : List.of();

    final List<SigningKey> active = this.getActiveSigningKeys();
    if (active.isEmpty()) {
      throw new IllegalArgumentException("The OpenID Provider has no active signing key - ID tokens must be signed");
    }
    final List<SigningKey> defaults = active.stream().filter(SigningKey::isDefaultKey).toList();
    if (defaults.size() > 1) {
      throw new IllegalArgumentException("Several OIDC signing keys are marked as default - only one may be: "
          + defaults.stream().map(SigningKey::getKeyId).toList());
    }
    if (defaults.isEmpty() && active.size() > 1) {
      throw new IllegalArgumentException(
          "The OpenID Provider has several active signing keys but none is marked as default - mark one of: "
              + active.stream().map(SigningKey::getKeyId).toList());
    }
    this.defaultSigningKey = defaults.isEmpty() ? active.getFirst() : defaults.getFirst();

    assertUniqueKeyIds(this.signingKeys.stream().map(SigningKey::getKeyId).toList(), "signing");
    assertUniqueKeyIds(this.decryptionKeys.stream().map(DecryptionKey::getKeyId).toList(), "decryption");

    final List<JWK> published = new ArrayList<>();
    this.signingKeys.forEach(k -> published.add(k.getPublicJwk()));
    this.decryptionKeys.stream().filter(DecryptionKey::isActive).forEach(k -> published.add(k.getPublicJwk()));
    this.publishedKeys = new JWKSet(published);
  }

  /**
   * Gets all signing keys, active and future.
   *
   * @return the signing keys
   */
  public @Nonnull List<SigningKey> getSigningKeys() {
    return this.signingKeys;
  }

  /**
   * Gets the active signing keys, the default key first.
   *
   * @return the active signing keys
   */
  public @Nonnull List<SigningKey> getActiveSigningKeys() {
    final List<SigningKey> active = new ArrayList<>();
    for (final SigningKey key : this.signingKeys) {
      if (key.isActive()) {
        if (key == this.defaultSigningKey) {
          active.addFirst(key);
        }
        else {
          active.add(key);
        }
      }
    }
    return active;
  }

  /**
   * Gets the default signing key.
   *
   * @return the default signing key
   */
  public @Nonnull SigningKey getDefaultSigningKey() {
    return this.defaultSigningKey;
  }

  /**
   * Gets the keys to decrypt with: the active keys and the previous keys.
   *
   * @return the decryption keys
   */
  public @Nonnull List<DecryptionKey> getDecryptionKeys() {
    return this.decryptionKeys;
  }

  /**
   * Gets the published keys: the active and future signing keys and the active decryption keys, without private key
   * material.
   *
   * @return the published keys
   */
  public @Nonnull JWKSet getPublishedKeys() {
    return this.publishedKeys;
  }

  /**
   * Gets the signing algorithms that the active keys can produce, those of the default key first.
   *
   * @return the signing algorithms
   */
  public @Nonnull List<JWSAlgorithm> getSigningAlgorithms() {
    final Set<JWSAlgorithm> algorithms = new LinkedHashSet<>();
    this.getActiveSigningKeys().forEach(k -> algorithms.addAll(k.getAlgorithms()));
    return List.copyOf(algorithms);
  }

  /**
   * Gets the key management algorithms that the active decryption keys support. These are the algorithms that a client
   * may encrypt with.
   *
   * @return the key management algorithms, empty if there is no active decryption key
   */
  public @Nonnull List<JWEAlgorithm> getDecryptionAlgorithms() {
    final Set<JWEAlgorithm> algorithms = new LinkedHashSet<>();
    this.decryptionKeys.stream().filter(DecryptionKey::isActive).forEach(k -> algorithms.addAll(k.getAlgorithms()));
    return List.copyOf(algorithms);
  }

  /**
   * Checks that key IDs are unique.
   *
   * @param keyIds the key IDs
   * @param use what the keys are used for, for the error message
   */
  private static void assertUniqueKeyIds(final @Nonnull List<String> keyIds, final @Nonnull String use) {
    final Set<String> seen = new HashSet<>();
    for (final String keyId : keyIds) {
      if (!seen.add(keyId)) {
        throw new IllegalArgumentException("Several OIDC %s keys have the key ID '%s'".formatted(use, keyId));
      }
    }
  }

}
