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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorResponseException;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;

/**
 * Decodes JWTs that a client sends in an authentication request: request objects, and the signature request
 * parameter of the Signature Extension for OpenID Connect.
 * <p>
 * A JWT may be signed, encrypted, or both, in which case it is signed and then encrypted (nested). An encrypted JWT is
 * decrypted with the decryption keys of the OpenID Provider. A signature is verified with the keys of the client, see
 * {@link ClientKeyResolver}. An unsigned JWT is accepted by this class; whether the request may use one is decided by
 * the caller.
 * </p>
 * <p>
 * The claims are checked as OpenID Connect Core, Section 6.3, and the Swedish OpenID Connect Profile, Section 2.1.7,
 * describe: {@code client_id} and {@code iss}, when present, must be the {@code client_id} of the request, and
 * {@code aud}, when present, must hold the issuer or the authorization endpoint of the OpenID Provider. A signed
 * request object must hold {@code iss} and {@code aud}. A JWT past its {@code exp}, or before its {@code nbf}, is
 * rejected.
 * </p>
 *
 * @author Martin Lindström
 */
public class RequestObjectDecoder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RequestObjectDecoder.class);

  /** The signature algorithms that are accepted. */
  public static final List<JWSAlgorithm> SUPPORTED_SIGNING_ALGORITHMS = List.of(
      JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
      JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
      JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

  /** The keys of the OpenID Provider. */
  private final OidcKeys keys;

  /** Finds the keys of the client. */
  private final ClientKeyResolver clientKeyResolver;

  /** The accepted audiences: the issuer and the authorization endpoint. */
  private final Set<String> audiences;

  /** The allowed clock skew. */
  private final Duration clockSkew;

  /**
   * Constructor.
   *
   * @param keys the keys of the OpenID Provider
   * @param clientKeyResolver finds the keys of the client
   * @param issuer the issuer of the OpenID Provider
   * @param authorizationEndpoint the URL of the authorization endpoint
   * @param clockSkew the allowed clock skew
   */
  public RequestObjectDecoder(final @NonNull OidcKeys keys, final @NonNull ClientKeyResolver clientKeyResolver,
      final @NonNull String issuer, final @NonNull String authorizationEndpoint, final @NonNull Duration clockSkew) {
    this.keys = Objects.requireNonNull(keys, "keys must not be null");
    this.clientKeyResolver = Objects.requireNonNull(clientKeyResolver, "clientKeyResolver must not be null");
    this.audiences = Set.of(Objects.requireNonNull(issuer, "issuer must not be null"),
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint must not be null"));
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
  }

  /**
   * Decodes a request object.
   *
   * @param requestObject the request object
   * @param clientId the {@code client_id} of the request
   * @param metadata the client metadata
   * @param logString the log string of the request
   * @return the decoded request object
   * @throws OidcErrorResponseException with {@code invalid_request_object} if the request object is invalid
   */
  public @NonNull DecodedJwt decodeRequestObject(final @NonNull String requestObject, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws OidcErrorResponseException {
    return this.decode(requestObject, clientId, metadata, true, "request object", logString);
  }

  /**
   * Decodes a JWT sent as a request parameter, such as the signature request parameter. It must be signed.
   *
   * @param jwt the JWT
   * @param clientId the {@code client_id} of the request
   * @param metadata the client metadata
   * @param name the name of the parameter, for error messages
   * @param logString the log string of the request
   * @return the decoded JWT
   * @throws OidcErrorResponseException with {@code invalid_request} if the JWT is invalid or not signed
   */
  public @NonNull DecodedJwt decodeSignedParameter(final @NonNull String jwt, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String name, final @NonNull String logString)
      throws OidcErrorResponseException {
    final DecodedJwt decoded = this.decode(jwt, clientId, metadata, false, name, logString);
    if (decoded.signingAlgorithm() == null) {
      throw invalid(false, "The %s parameter must be signed".formatted(name), logString, null);
    }
    return decoded;
  }

  /**
   * Decodes a JWT.
   *
   * @param jwt the JWT
   * @param clientId the {@code client_id} of the request
   * @param metadata the client metadata
   * @param requestObject whether the JWT is a request object
   * @param name what the JWT is, for error messages
   * @param logString the log string of the request
   * @return the decoded JWT
   * @throws OidcErrorResponseException if the JWT is invalid
   */
  private @NonNull DecodedJwt decode(final @NonNull String jwt, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final boolean requestObject, final @NonNull String name,
      final @NonNull String logString) throws OidcErrorResponseException {

    JWT parsed;
    try {
      parsed = JWTParser.parse(jwt);
    }
    catch (final ParseException e) {
      throw invalid(requestObject, "The %s could not be parsed".formatted(name), logString, e);
    }

    boolean encrypted = false;
    JWTClaimsSet claims = null;
    if (parsed instanceof final EncryptedJWT encryptedJwt) {
      encrypted = true;
      final Payload payload = this.decrypt(encryptedJwt, requestObject, name, logString);
      final SignedJWT nested = payload.toSignedJWT();
      if (nested != null) {
        parsed = nested;
      }
      else {
        try {
          parsed = PlainJWT.parse(payload.toString());
        }
        catch (final ParseException e) {
          try {
            claims = JWTClaimsSet.parse(payload.toJSONObject());
            parsed = null;
          }
          catch (final ParseException | IllegalStateException e2) {
            throw invalid(requestObject, "The decrypted %s is not a JWT".formatted(name), logString, e2);
          }
        }
      }
    }

    JWSAlgorithm signingAlgorithm = null;
    try {
      if (parsed instanceof final SignedJWT signedJwt) {
        signingAlgorithm = signedJwt.getHeader().getAlgorithm();
        this.verify(signedJwt, clientId, metadata, requestObject, name, logString);
        claims = signedJwt.getJWTClaimsSet();
      }
      else if (parsed instanceof final PlainJWT plainJwt) {
        claims = plainJwt.getJWTClaimsSet();
      }
    }
    catch (final ParseException e) {
      throw invalid(requestObject, "The claims of the %s could not be parsed".formatted(name), logString, e);
    }
    if (claims == null) {
      throw invalid(requestObject, "The %s could not be parsed".formatted(name), logString, null);
    }

    this.checkClaims(claims, clientId, signingAlgorithm != null && requestObject, requestObject, name, logString);
    log.debug("Decoded {} - signed: {}, encrypted: {} [{}]", name,
        signingAlgorithm != null ? signingAlgorithm.getName() : "no", encrypted, logString);
    return new DecodedJwt(claims, signingAlgorithm, encrypted);
  }

  /**
   * Decrypts an encrypted JWT with the decryption keys of the OpenID Provider.
   *
   * @param jwt the encrypted JWT
   * @param requestObject whether the JWT is a request object
   * @param name what the JWT is
   * @param logString the log string
   * @return the payload
   * @throws OidcErrorResponseException if the JWT cannot be decrypted
   */
  private @NonNull Payload decrypt(final @NonNull JWEObject jwt, final boolean requestObject,
      final @NonNull String name, final @NonNull String logString) throws OidcErrorResponseException {

    final JWEHeader header = jwt.getHeader();
    final DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
    for (final DecryptionKey key : this.keys.getDecryptionKeys()) {
      if (header.getKeyID() != null && !header.getKeyID().equals(key.getKeyId())) {
        continue;
      }
      if (!key.getAlgorithms().contains(header.getAlgorithm())) {
        continue;
      }
      try {
        jwt.decrypt(factory.createJWEDecrypter(header, key.getCredential().getPrivateKey()));
        return jwt.getPayload();
      }
      catch (final JOSEException | IllegalStateException e) {
        log.debug("Failed to decrypt {} with key '{}' - {} [{}]", name, key.getKeyId(), e.getMessage(), logString);
      }
    }
    throw invalid(requestObject, "The %s could not be decrypted".formatted(name), logString, null);
  }

  /**
   * Verifies the signature of a JWT with the keys of the client.
   *
   * @param jwt the signed JWT
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param requestObject whether the JWT is a request object
   * @param name what the JWT is
   * @param logString the log string
   * @throws OidcErrorResponseException if the signature cannot be verified
   */
  private void verify(final @NonNull SignedJWT jwt, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final boolean requestObject, final @NonNull String name,
      final @NonNull String logString) throws OidcErrorResponseException {

    final JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
    if (!SUPPORTED_SIGNING_ALGORITHMS.contains(algorithm)) {
      throw invalid(requestObject,
          "The %s is signed with an unsupported algorithm (%s)".formatted(name, algorithm), logString, null);
    }
    final List<JWK> candidates;
    try {
      candidates = this.clientKeyResolver.resolve(clientId, metadata, jwt.getHeader());
    }
    catch (final KeySourceException e) {
      log.info("Failed to get the keys of the client - {} [{}]", e.getMessage(), logString);
      throw invalid(requestObject, "The keys of the client could not be obtained", logString, e);
    }
    final DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
    for (final JWK candidate : candidates) {
      if (!(candidate instanceof final AsymmetricJWK asymmetric)) {
        continue;
      }
      try {
        final JWSVerifier verifier = factory.createJWSVerifier(jwt.getHeader(), asymmetric.toPublicKey());
        if (jwt.verify(verifier)) {
          return;
        }
      }
      catch (final JOSEException e) {
        log.debug("Failed to verify {} with key '{}' - {} [{}]", name, candidate.getKeyID(), e.getMessage(),
            logString);
      }
    }
    throw invalid(requestObject, "The signature of the %s could not be verified".formatted(name), logString, null);
  }

  /**
   * Checks the claims of a decoded JWT.
   *
   * @param claims the claims
   * @param clientId the {@code client_id} of the request
   * @param requireIssuerAndAudience whether {@code iss} and {@code aud} are required
   * @param requestObject whether the JWT is a request object
   * @param name what the JWT is
   * @param logString the log string
   * @throws OidcErrorResponseException for invalid claims
   */
  private void checkClaims(final @NonNull JWTClaimsSet claims, final @NonNull String clientId,
      final boolean requireIssuerAndAudience, final boolean requestObject, final @NonNull String name,
      final @NonNull String logString) throws OidcErrorResponseException {

    final Map<String, Object> json = claims.toJSONObject();
    if (json.containsKey("client_id") && !clientId.equals(json.get("client_id"))) {
      throw invalid(requestObject, "The client_id of the %s does not match the request".formatted(name), logString,
          null);
    }
    if (claims.getIssuer() != null) {
      if (!clientId.equals(claims.getIssuer())) {
        throw invalid(requestObject, "The iss of the %s is not the client".formatted(name), logString, null);
      }
    }
    else if (requireIssuerAndAudience) {
      throw invalid(requestObject, "The %s has no iss".formatted(name), logString, null);
    }
    final List<String> audience = claims.getAudience();
    if (audience != null && !audience.isEmpty()) {
      if (audience.stream().noneMatch(this.audiences::contains)) {
        throw invalid(requestObject,
            "The aud of the %s is neither the issuer nor the authorization endpoint".formatted(name), logString, null);
      }
    }
    else if (requireIssuerAndAudience) {
      throw invalid(requestObject, "The %s has no aud".formatted(name), logString, null);
    }
    final Instant now = Instant.now();
    if (claims.getExpirationTime() != null
        && now.isAfter(claims.getExpirationTime().toInstant().plus(this.clockSkew))) {
      throw invalid(requestObject, "The %s has expired".formatted(name), logString, null);
    }
    if (claims.getNotBeforeTime() != null
        && now.isBefore(claims.getNotBeforeTime().toInstant().minus(this.clockSkew))) {
      throw invalid(requestObject, "The %s is not yet valid".formatted(name), logString, null);
    }
  }

  /**
   * Creates the exception for an invalid JWT, and logs it.
   *
   * @param requestObject whether the JWT is a request object, giving {@code invalid_request_object}, or a parameter,
   *          giving {@code invalid_request}
   * @param description the description
   * @param logString the log string
   * @param cause the cause, may be {@code null}
   * @return an {@link OidcErrorResponseException}
   */
  private static @NonNull OidcErrorResponseException invalid(final boolean requestObject,
      final @NonNull String description, final @NonNull String logString, final @Nullable Throwable cause) {
    log.info("{}{} [{}]", description, cause != null ? " - " + cause.getMessage() : "", logString);
    return new OidcErrorResponseException(
        requestObject ? OAuth2Error.INVALID_REQUEST_OBJECT : OAuth2Error.INVALID_REQUEST, description, cause);
  }

  /**
   * A decoded JWT.
   *
   * @param claims the claims
   * @param signingAlgorithm the algorithm that the JWT was signed with, or {@code null} if it was not signed
   * @param encrypted whether the JWT was encrypted
   */
  public record DecodedJwt(@NonNull JWTClaimsSet claims, @Nullable JWSAlgorithm signingAlgorithm,
      boolean encrypted) {
  }

}
