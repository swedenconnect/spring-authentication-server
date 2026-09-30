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
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;

/**
 * Chooses the key, and the algorithm, that the OpenID Provider signs a message to a client with.
 * <p>
 * The choice depends on what the client has declared:
 * </p>
 * <ul>
 * <li>One algorithm, such as {@code id_token_signed_response_alg}: an active key that can produce it, the default key
 * if it can.</li>
 * <li>A list of accepted algorithms, such as {@code id_token_signing_alg_values_supported} of OpenID Connect Relying
 * Party Metadata Choices: the default key if it can produce one of them, otherwise another active key that can. The
 * algorithm is the first one in the client's list that the key can produce.</li>
 * <li>Nothing: the default key, with its preferred algorithm. The registration default ({@code RS256} for ID tokens) is
 * not applied, following Sweden Connect OpenID Connect Metadata Requirements, Section 4.1.</li>
 * </ul>
 * <p>
 * When a client declares both, the single algorithm wins. When no active key can produce an algorithm that the client
 * accepts, the selection fails. Future keys are never used.
 * </p>
 *
 * @author Martin Lindström
 */
public class SigningKeySelector {

  /** The client metadata parameter for the accepted ID token signing algorithms. */
  public static final String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";

  /** The client metadata parameter for the accepted UserInfo signing algorithms. */
  public static final String USERINFO_SIGNING_ALG_VALUES_SUPPORTED = "userinfo_signing_alg_values_supported";

  /** The keys. */
  private final OidcKeys keys;

  /**
   * Constructor.
   *
   * @param keys the keys of the OpenID Provider
   */
  public SigningKeySelector(final @Nonnull OidcKeys keys) {
    this.keys = Objects.requireNonNull(keys, "keys must not be null");
  }

  /**
   * Chooses the key for signing an ID token to a client.
   *
   * @param client the client metadata
   * @return the selected key and algorithm
   * @throws UnrecoverableErrorException if no active key can produce an algorithm that the client accepts
   */
  public @Nonnull SelectedSigningKey selectForIdToken(final @Nonnull OIDCClientMetadata client)
      throws UnrecoverableErrorException {
    return this.select(client.getIDTokenJWSAlg(),
        parseAlgorithms(client.getCustomField(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED)));
  }

  /**
   * Chooses the key for signing a UserInfo response to a client. Whether UserInfo responses are signed at all is
   * decided by the caller.
   *
   * @param client the client metadata
   * @return the selected key and algorithm
   * @throws UnrecoverableErrorException if no active key can produce an algorithm that the client accepts
   */
  public @Nonnull SelectedSigningKey selectForUserInfo(final @Nonnull OIDCClientMetadata client)
      throws UnrecoverableErrorException {
    return this.select(client.getUserInfoJWSAlg(),
        parseAlgorithms(client.getCustomField(USERINFO_SIGNING_ALG_VALUES_SUPPORTED)));
  }

  /**
   * Chooses a key from what a client has declared.
   *
   * @param declared the one algorithm that the client has declared, or {@code null}
   * @param accepted the algorithms that the client accepts, or {@code null} if it has not declared any. An empty
   *     list accepts nothing
   * @return the selected key and algorithm
   * @throws UnrecoverableErrorException if no active key can produce an algorithm that the client accepts
   */
  public @Nonnull SelectedSigningKey select(final @Nullable JWSAlgorithm declared,
      final @Nullable List<JWSAlgorithm> accepted) throws UnrecoverableErrorException {

    final List<SigningKey> candidates = this.keys.getActiveSigningKeys();
    if (declared != null) {
      return candidates.stream()
          .filter(k -> k.supports(declared))
          .findFirst()
          .map(k -> new SelectedSigningKey(k, declared))
          .orElseThrow(() -> new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
              "No active signing key can produce the algorithm %s that the client requires"
                  .formatted(declared.getName())));
    }
    if (accepted != null) {
      for (final SigningKey key : candidates) {
        for (final JWSAlgorithm algorithm : accepted) {
          if (key.supports(algorithm)) {
            return new SelectedSigningKey(key, algorithm);
          }
        }
      }
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "No active signing key can produce any of the algorithms %s that the client accepts"
              .formatted(accepted.stream().map(Algorithm::getName).toList()));
    }
    final SigningKey defaultKey = this.keys.getDefaultSigningKey();
    return new SelectedSigningKey(defaultKey, defaultKey.getPreferredAlgorithm());
  }

  /**
   * Parses the value of a client metadata parameter holding a list of algorithms. The value {@code none} is left out,
   * since the message is signed.
   *
   * @param value the value, a list of strings, or a single string
   * @return the algorithms, or {@code null} if the value is absent
   */
  static @Nullable List<JWSAlgorithm> parseAlgorithms(final @Nullable Object value) {
    if (value == null) {
      return null;
    }
    final List<JWSAlgorithm> algorithms = new ArrayList<>();
    final Collection<?> values = value instanceof final Collection<?> c ? c : List.of(value);
    for (final Object v : values) {
      if (v instanceof final String name && !name.isBlank() && !Algorithm.NONE.getName().equals(name)) {
        algorithms.add(JWSAlgorithm.parse(name));
      }
    }
    return algorithms;
  }

  /**
   * A selected key and the algorithm to sign with.
   *
   * @param key the key
   * @param algorithm the algorithm
   */
  public record SelectedSigningKey(@Nonnull SigningKey key, @Nonnull JWSAlgorithm algorithm) {
  }

}
