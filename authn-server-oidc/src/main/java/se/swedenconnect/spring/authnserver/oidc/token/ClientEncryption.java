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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;

/**
 * Encrypts messages to a client, such as ID tokens and UserInfo responses, with the client's encryption key from
 * {@code jwks} or {@code jwks_uri}.
 * <p>
 * The algorithms are those that Sweden Connect Security Requirements, Section 3.2, allows: {@code RSA-OAEP},
 * {@code RSA-OAEP-256} and {@code ECDH-ES}, with {@code A128CBC-HS256}, {@code A256CBC-HS512}, {@code A128GCM} or
 * {@code A256GCM}. The content encryption defaults to {@code A128CBC-HS256}, as OpenID Connect Dynamic Client
 * Registration says. A client whose declared algorithms are not allowed, or that has no key for them, is a client
 * configuration problem, reported as {@link OidcUnrecoverableError#INVALID_CLIENT_CONFIGURATION} and logged.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientEncryption {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientEncryption.class);

  /** The key management algorithms that messages may be encrypted with. */
  public static final List<JWEAlgorithm> SUPPORTED_ALGORITHMS =
      List.of(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.ECDH_ES);

  /** The content encryption algorithms that messages may be encrypted with. */
  public static final List<EncryptionMethod> SUPPORTED_METHODS = List.of(EncryptionMethod.A128CBC_HS256,
      EncryptionMethod.A256CBC_HS512, EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);

  /** Finds the encryption keys of clients. */
  private final ClientKeyResolver clientKeyResolver;

  /**
   * Constructor.
   *
   * @param clientKeyResolver finds the encryption keys of clients
   */
  public ClientEncryption(final @NonNull ClientKeyResolver clientKeyResolver) {
    this.clientKeyResolver = Objects.requireNonNull(clientKeyResolver, "clientKeyResolver must not be null");
  }

  /**
   * Encrypts a payload for a client.
   *
   * @param payload the payload, a signed JWT or a JSON claims set
   * @param nestedJwt whether the payload is a signed JWT, which gives the header {@code "cty": "JWT"}
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param algorithm the key management algorithm that the client has declared
   * @param method the content encryption algorithm that the client has declared, or {@code null} for the default
   * @param what what is encrypted, for log and error messages, for example "ID token"
   * @return the serialized JWE
   * @throws UnrecoverableErrorException with {@link OidcUnrecoverableError#INVALID_CLIENT_CONFIGURATION} if the payload
   *     cannot be encrypted for the client
   */
  public @NonNull String encrypt(final @NonNull Payload payload, final boolean nestedJwt,
      final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWEAlgorithm algorithm, final @Nullable EncryptionMethod method, final @NonNull String what)
      throws UnrecoverableErrorException {

    final JWK key = this.getKey(clientId, metadata, algorithm, method, what);
    final EncryptionMethod enc = method != null ? method : EncryptionMethod.A128CBC_HS256;
    try {
      final JWEEncrypter encrypter = key instanceof final RSAKey rsaKey
          ? new RSAEncrypter(rsaKey)
          : new ECDHEncrypter((ECKey) key);
      final JWEHeader.Builder header = new JWEHeader.Builder(algorithm, enc).keyID(key.getKeyID());
      if (nestedJwt) {
        header.contentType("JWT");
      }
      final JWEObject jwe = new JWEObject(header.build(), payload);
      jwe.encrypt(encrypter);
      return jwe.serialize();
    }
    catch (final JOSEException e) {
      throw configurationError("The %s could not be encrypted with %s/%s - %s"
          .formatted(what, algorithm, enc, e.getMessage()), clientId);
    }
  }

  /**
   * Checks that a message can be encrypted for the client: that the declared algorithms are allowed and that the
   * client has a key for them.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param algorithm the key management algorithm that the client has declared
   * @param method the content encryption algorithm that the client has declared, or {@code null} for the default
   * @param what what is to be encrypted, for log and error messages
   * @throws UnrecoverableErrorException with {@link OidcUnrecoverableError#INVALID_CLIENT_CONFIGURATION} if the
   *     message cannot be encrypted
   */
  public void check(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWEAlgorithm algorithm, final @Nullable EncryptionMethod method, final @NonNull String what)
      throws UnrecoverableErrorException {
    this.getKey(clientId, metadata, algorithm, method, what);
  }

  /**
   * Gets the client's key for the declared algorithms.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param algorithm the key management algorithm
   * @param method the content encryption algorithm, or {@code null} for the default
   * @param what what is to be encrypted
   * @return the key
   * @throws UnrecoverableErrorException if the algorithms are not allowed or the client has no usable key
   */
  private @NonNull JWK getKey(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWEAlgorithm algorithm, final @Nullable EncryptionMethod method, final @NonNull String what)
      throws UnrecoverableErrorException {

    final EncryptionMethod enc = method != null ? method : EncryptionMethod.A128CBC_HS256;
    if (!SUPPORTED_ALGORITHMS.contains(algorithm) || !SUPPORTED_METHODS.contains(enc)) {
      throw configurationError("The %s encryption algorithms %s/%s are not supported"
          .formatted(what, algorithm, enc), clientId);
    }
    final JWKMatcher matcher = new JWKMatcher.Builder()
        .keyType(KeyType.forAlgorithm(algorithm))
        .keyUses(KeyUse.ENCRYPTION, null)
        .algorithms(algorithm, null)
        .build();
    final List<JWK> keys;
    try {
      keys = this.clientKeyResolver.resolve(clientId, metadata, matcher);
    }
    catch (final KeySourceException e) {
      throw configurationError("The encryption keys of the client could not be obtained - " + e.getMessage(),
          clientId);
    }
    if (keys.isEmpty()) {
      throw configurationError("The client has no key for %s encryption with %s".formatted(what, algorithm),
          clientId);
    }
    return keys.getFirst();
  }

  /**
   * Creates the exception for a client that a message cannot be encrypted for, and logs it.
   *
   * @param message the message
   * @param clientId the {@code client_id}
   * @return an {@link UnrecoverableErrorException}
   */
  private static @NonNull UnrecoverableErrorException configurationError(final @NonNull String message,
      final @NonNull String clientId) {
    log.warn("Client configuration error - {} [requester: 'OIDC:{}']", message, clientId);
    return new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION, message);
  }

}
