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

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
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
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.attributes.DeliveredClaims;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector;

/**
 * Builds the ID token for an authorization code, following the Swedish OpenID Connect Profile, Section 3.2.1.
 * <p>
 * The token holds {@code iss}, {@code sub}, {@code aud}, {@code exp}, {@code iat}, {@code auth_time}, which is the time
 * of the original authentication also when single sign-on was used, {@code nonce} when the request had one, and
 * {@code acr}, the authentication context that was used, always. The identity claims that are to be delivered in the
 * ID token are added.
 * </p>
 * <p>
 * The token is always signed, with the key chosen for the client by the {@link SigningKeySelector}. When the client has
 * registered {@code id_token_encrypted_response_alg}, the signed token is encrypted with the client's encryption key,
 * using the algorithms that Sweden Connect Security Requirements, Section 3.2, allows: {@code RSA-OAEP},
 * {@code RSA-OAEP-256} and {@code ECDH-ES}, with {@code A128CBC-HS256}, {@code A256CBC-HS512}, {@code A128GCM} or
 * {@code A256GCM}. The content encryption defaults to {@code A128CBC-HS256}, as OpenID Connect Dynamic Client
 * Registration says.
 * </p>
 *
 * @author Martin Lindström
 */
public class IdTokenBuilder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(IdTokenBuilder.class);

  /** The default ID token lifetime, 5 minutes. */
  public static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);

  /** The key management algorithms that ID tokens may be encrypted with. */
  public static final List<JWEAlgorithm> SUPPORTED_ENCRYPTION_ALGORITHMS =
      List.of(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.ECDH_ES);

  /** The content encryption algorithms that ID tokens may be encrypted with. */
  public static final List<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = List.of(EncryptionMethod.A128CBC_HS256,
      EncryptionMethod.A256CBC_HS512, EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);

  /** The issuer. */
  private final String issuer;

  /** Chooses the signing key. */
  private final SigningKeySelector signingKeySelector;

  /** Finds the encryption keys of clients. */
  private final ClientKeyResolver clientKeyResolver;

  /** The lifetime of an ID token. */
  private final Duration lifetime;

  /**
   * Constructor.
   *
   * @param issuer the issuer
   * @param signingKeySelector chooses the signing key
   * @param clientKeyResolver finds the encryption keys of clients
   * @param lifetime the lifetime of an ID token
   */
  public IdTokenBuilder(final @NonNull String issuer, final @NonNull SigningKeySelector signingKeySelector,
      final @NonNull ClientKeyResolver clientKeyResolver, final @NonNull Duration lifetime) {
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.signingKeySelector = Objects.requireNonNull(signingKeySelector, "signingKeySelector must not be null");
    this.clientKeyResolver = Objects.requireNonNull(clientKeyResolver, "clientKeyResolver must not be null");
    this.lifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
  }

  /**
   * Builds, signs and, when the client asks for it, encrypts the ID token.
   *
   * @param code the authorization code the token is issued for
   * @param metadata the client metadata
   * @param now the issuance time
   * @return the serialized ID token
   * @throws UnrecoverableErrorException with {@link OidcUnrecoverableError#INVALID_CLIENT_CONFIGURATION} if the token
   *     cannot be encrypted for the client, and {@link CommonUnrecoverableError#INTERNAL} if it cannot be signed
   */
  public @NonNull String build(final @NonNull AuthorizationCodeData code, final @NonNull OIDCClientMetadata metadata,
      final @NonNull Instant now) throws UnrecoverableErrorException {

    final AuthenticatedUser user = code.user();
    final IDTokenClaimsSet claims = new IDTokenClaimsSet(new Issuer(this.issuer), new Subject(code.subject()),
        List.of(new Audience(code.clientId())), Date.from(now.plus(this.lifetime)), Date.from(now));
    claims.setAuthenticationTime(Date.from(user.getAuthnInstant()));
    if (code.nonce() != null) {
      claims.setNonce(new Nonce(code.nonce()));
    }
    claims.setACR(new ACR(user.getAuthnContextUri()));
    DeliveredClaims.parse(code.idTokenClaims()).forEach(claims::setClaim);

    final SigningKeySelector.SelectedSigningKey key = this.signingKeySelector.selectForIdToken(metadata);
    final SignedJWT signed;
    try {
      signed = key.key().sign(claims.toJWTClaimsSet(), key.algorithm());
    }
    catch (final JOSEException | ParseException e) {
      log.error("Failed to sign ID token with key '{}' - {}", key.key().getKeyId(), e.getMessage(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to sign ID token", e);
    }
    if (metadata.getIDTokenJWEAlg() == null) {
      return signed.serialize();
    }
    return this.encrypt(signed, code.clientId(), metadata);
  }

  /**
   * Checks that an ID token can be encrypted for the client, if the client asks for encryption: that the declared
   * algorithms are allowed and that the client has a key for them.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @throws UnrecoverableErrorException with {@link OidcUnrecoverableError#INVALID_CLIENT_CONFIGURATION} if the token
   *     cannot be encrypted
   */
  public void checkEncryption(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata)
      throws UnrecoverableErrorException {
    if (metadata.getIDTokenJWEAlg() != null) {
      this.getEncryptionKey(clientId, metadata);
    }
  }

  /**
   * Encrypts a signed ID token.
   *
   * @param signed the signed token
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @return the serialized encrypted token
   * @throws UnrecoverableErrorException if the token cannot be encrypted
   */
  private @NonNull String encrypt(final @NonNull SignedJWT signed, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata) throws UnrecoverableErrorException {

    final JWK key = this.getEncryptionKey(clientId, metadata);
    final JWEAlgorithm algorithm = metadata.getIDTokenJWEAlg();
    final EncryptionMethod method = getEncryptionMethod(metadata);
    try {
      final JWEEncrypter encrypter = key instanceof final RSAKey rsaKey
          ? new RSAEncrypter(rsaKey)
          : new ECDHEncrypter((ECKey) key);
      final JWEObject jwe = new JWEObject(new JWEHeader.Builder(algorithm, method)
          .contentType("JWT")
          .keyID(key.getKeyID())
          .build(), new Payload(signed));
      jwe.encrypt(encrypter);
      return jwe.serialize();
    }
    catch (final JOSEException e) {
      log.warn("Client configuration error - the ID token could not be encrypted with {}/{} - {} "
          + "[requester: 'OIDC:{}']", algorithm, method, e.getMessage(), clientId);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "The ID token could not be encrypted for the client", e);
    }
  }

  /**
   * Gets the key to encrypt ID tokens for the client with.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata, which declares {@code id_token_encrypted_response_alg}
   * @return the key
   * @throws UnrecoverableErrorException if the algorithms are not allowed or the client has no usable key
   */
  private @NonNull JWK getEncryptionKey(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata)
      throws UnrecoverableErrorException {

    final JWEAlgorithm algorithm = Objects.requireNonNull(metadata.getIDTokenJWEAlg());
    final EncryptionMethod method = getEncryptionMethod(metadata);
    if (!SUPPORTED_ENCRYPTION_ALGORITHMS.contains(algorithm) || !SUPPORTED_ENCRYPTION_METHODS.contains(method)) {
      throw configurationError("The ID token encryption algorithms %s/%s are not supported"
          .formatted(algorithm, method), clientId);
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
      throw configurationError("The client has no key for ID token encryption with " + algorithm, clientId);
    }
    return keys.getFirst();
  }

  /**
   * Gets the content encryption algorithm, {@code A128CBC-HS256} when the client has not registered one.
   *
   * @param metadata the client metadata
   * @return the content encryption algorithm
   */
  private static @NonNull EncryptionMethod getEncryptionMethod(final @NonNull OIDCClientMetadata metadata) {
    return metadata.getIDTokenJWEEnc() != null ? metadata.getIDTokenJWEEnc() : EncryptionMethod.A128CBC_HS256;
  }

  /**
   * Creates the exception for a client that ID tokens cannot be encrypted for, and logs it.
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
