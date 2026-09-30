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

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * The Federation Entity Keys of the OpenID Provider.
 * <p>
 * The rules, checked when the object is created: there is at least one key, at least one key is active, and the key
 * IDs are unique. All keys are published, and the first active key signs.
 * </p>
 *
 * @author Martin Lindström
 */
public final class FederationKeys {

  /** The keys. */
  private final List<FederationKey> keys;

  /** The published keys. */
  private final JWKSet publishedKeys;

  /**
   * Constructor.
   *
   * @param keys the keys
   * @throws IllegalArgumentException if the keys break any of the rules
   */
  public FederationKeys(final @NonNull List<FederationKey> keys) {
    this.keys = List.copyOf(Objects.requireNonNull(keys, "keys must not be null"));
    if (this.keys.isEmpty()) {
      throw new IllegalArgumentException("No OpenID Federation keys are configured");
    }
    if (this.keys.stream().noneMatch(FederationKey::isActive)) {
      throw new IllegalArgumentException("No OpenID Federation key is active - at least one key must be active");
    }
    final Set<String> seen = new HashSet<>();
    for (final FederationKey key : this.keys) {
      if (!seen.add(key.getKeyId())) {
        throw new IllegalArgumentException(
            "Several OpenID Federation keys have the key ID '%s'".formatted(key.getKeyId()));
      }
    }
    this.publishedKeys = new JWKSet(this.keys.stream().map(FederationKey::getPublicJwk).toList());
  }

  /**
   * Gets all keys, active and future.
   *
   * @return the keys
   */
  public @NonNull List<FederationKey> getKeys() {
    return this.keys;
  }

  /**
   * Gets the key that signs: the first active key.
   *
   * @return the signing key
   */
  public @NonNull FederationKey getSigningKey() {
    return this.keys.stream().filter(FederationKey::isActive).findFirst().orElseThrow();
  }

  /**
   * Gets the published keys: all keys, without private key material.
   *
   * @return the published keys
   */
  public @NonNull JWKSet getPublishedKeys() {
    return this.publishedKeys;
  }

  /**
   * Gets the key IDs and states of the keys. Two sets of keys with the same state give the same value, so it tells
   * whether a key has been added, removed or has changed state.
   *
   * @return the key IDs and states
   */
  public @NonNull List<String> getKeyStates() {
    return this.keys.stream().map(k -> k.getKeyId() + ":" + k.getState()).toList();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return this.keys.toString();
  }

}
