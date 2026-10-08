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

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestObjectDecoder;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Authenticates the client at the token endpoint.
 * <p>
 * The supported methods are {@code private_key_jwt}, {@code client_secret_basic}, {@code client_secret_post} and
 * {@code client_secret_jwt}, of which the enabled ones are accepted. {@code none} is never accepted. A client must use
 * the method it has registered as {@code token_endpoint_auth_method}, which defaults to {@code client_secret_basic} as
 * OpenID Connect Dynamic Client Registration says.
 * </p>
 * <p>
 * A client assertion ({@code private_key_jwt} and {@code client_secret_jwt}) must have {@code iss} and {@code sub}
 * equal to the {@code client_id}, {@code aud} holding the token endpoint or the issuer, as the Swedish OpenID Connect
 * Profile, Section 3.1.1, recommends, an {@code exp} that has not passed, an {@code iat}, if present, that is not
 * in the future, nor older than the maximum age when one is assigned (see {@link #setMaxJwtAge(Duration)}), and a
 * {@code jti} that has not been used before. The clock skew applies to all time checks. A {@code private_key_jwt}
 * assertion is verified with the keys of the client, and a {@code client_secret_jwt} assertion with the client secret.
 * A client that has registered {@code token_endpoint_auth_signing_alg} must use that algorithm.
 * </p>
 * <p>
 * The client secret is the {@value OidcClientRecord#CLIENT_SECRET} field of the client metadata.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientAuthenticator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientAuthenticator.class);

  /** The methods that can be enabled. */
  public static final List<ClientAuthenticationMethod> SUPPORTED_METHODS = List.of(
      ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
      ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.CLIENT_SECRET_JWT);

  /** The algorithms accepted for {@code client_secret_jwt}. */
  public static final List<JWSAlgorithm> CLIENT_SECRET_JWT_ALGORITHMS =
      List.of(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);

  /** The client registry. */
  private final ClientRegistry clientRegistry;

  /** The enabled methods. */
  private final Set<ClientAuthenticationMethod> enabledMethods;

  /** Finds the keys of clients. */
  private final ClientKeyResolver clientKeyResolver;

  /** Remembers the used assertions. */
  private final ClientAssertionReplayCache replayCache;

  /** The accepted audiences: the token endpoint and the issuer. */
  private final Set<String> audiences;

  /** The allowed clock skew. */
  private final Duration clockSkew;

  /** The maximum age of a client assertion, measured from its {@code iat}, or {@code null} for no limit. */
  private Duration maxJwtAge;

  /**
   * Constructor.
   *
   * @param clientRegistry the client registry
   * @param enabledMethods the enabled methods, a subset of {@link #SUPPORTED_METHODS}
   * @param clientKeyResolver finds the keys of clients
   * @param replayCache remembers the used assertions
   * @param tokenEndpoint the URL of the token endpoint
   * @param issuer the issuer
   * @param clockSkew the allowed clock skew
   */
  public ClientAuthenticator(final @NonNull ClientRegistry clientRegistry,
      final @NonNull Set<ClientAuthenticationMethod> enabledMethods,
      final @NonNull ClientKeyResolver clientKeyResolver, final @NonNull ClientAssertionReplayCache replayCache,
      final @NonNull String tokenEndpoint, final @NonNull String issuer, final @NonNull Duration clockSkew) {
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.enabledMethods = Set.copyOf(Objects.requireNonNull(enabledMethods, "enabledMethods must not be null"));
    if (!SUPPORTED_METHODS.containsAll(this.enabledMethods)) {
      throw new IllegalArgumentException("Unsupported client authentication method in " + enabledMethods);
    }
    this.clientKeyResolver = Objects.requireNonNull(clientKeyResolver, "clientKeyResolver must not be null");
    this.replayCache = Objects.requireNonNull(replayCache, "replayCache must not be null");
    this.audiences = Set.of(Objects.requireNonNull(tokenEndpoint, "tokenEndpoint must not be null"),
        Objects.requireNonNull(issuer, "issuer must not be null"));
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
  }

  /**
   * Assigns the maximum age of a client assertion, measured from its {@code iat}. The clock skew is added to it. An
   * assertion without {@code iat} is accepted. Defaults to {@code null}, which means that the age is not checked.
   *
   * @param maxJwtAge the maximum age, or {@code null} for no limit
   */
  public void setMaxJwtAge(final @Nullable Duration maxJwtAge) {
    if (maxJwtAge != null && (maxJwtAge.isNegative() || maxJwtAge.isZero())) {
      throw new IllegalArgumentException("maxJwtAge must be positive");
    }
    this.maxJwtAge = maxJwtAge;
  }

  /**
   * Authenticates the client of a token request.
   *
   * @param httpRequest the token request
   * @return the record of the authenticated client
   * @throws TokenErrorException with {@code invalid_client} if the client cannot be authenticated,
   *     {@code invalid_request} for a request that uses more than one method, and {@code server_error} if the client
   *     registry fails
   */
  public @NonNull RequesterRecord authenticate(final @NonNull HTTPRequest httpRequest) throws TokenErrorException {

    final ClientAuthentication authentication;
    try {
      final List<ClientAuthentication> candidates = ClientAuthentication.parseCandidates(httpRequest);
      if (candidates == null || candidates.isEmpty()) {
        throw invalidClient("No client authentication in token request", null);
      }
      if (candidates.size() > 1) {
        log.info("Token request uses more than one client authentication method");
        throw new TokenErrorException(OAuth2Error.INVALID_REQUEST,
            "More than one client authentication method was used");
      }
      authentication = candidates.getFirst();
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException e) {
      throw invalidClient("Invalid client authentication - " + e.getMessage(), null);
    }

    final String clientId = authentication.getClientID().getValue();
    final String logString = "requester: 'OIDC:%s'".formatted(clientId);
    final RequesterRecord record;
    try {
      record = this.clientRegistry.lookup(AuthenticationProtocol.OIDC, clientId);
    }
    catch (final ClientRegistryException e) {
      log.error("Failed to look up client in the client registry - {} [{}]", e.getMessage(), logString, e);
      throw new TokenErrorException(OAuth2Error.SERVER_ERROR, "The client could not be looked up", e);
    }
    if (record == null || !(record.protocolMetadata() instanceof final OIDCClientMetadata metadata)) {
      throw invalidClient("Client is not known", logString);
    }

    final ClientAuthenticationMethod method = authentication.getMethod();
    final ClientAuthenticationMethod registered = Objects.requireNonNullElse(metadata.getTokenEndpointAuthMethod(),
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    if (ClientAuthenticationMethod.NONE.equals(registered)) {
      throw invalidClient("The client is registered with token_endpoint_auth_method none, which is not supported",
          logString);
    }
    if (!this.enabledMethods.contains(method)) {
      throw invalidClient("The client authentication method %s is not enabled".formatted(method), logString);
    }
    if (!method.equals(registered)) {
      throw invalidClient("The client authenticated with %s, but has registered %s".formatted(method, registered),
          logString);
    }

    switch (authentication) {
      case final PrivateKeyJWT privateKeyJwt -> this.verifyAssertion(privateKeyJwt, clientId, metadata, logString);
      case final ClientSecretJWT clientSecretJwt ->
          this.verifyAssertion(clientSecretJwt, clientId, metadata, logString);
      case final PlainClientSecret plain -> verifySecret(plain, metadata, logString);
      default -> throw invalidClient("Unsupported client authentication method " + method, logString);
    }
    log.debug("Client authenticated with {} [{}]", method, logString);
    return record;
  }

  /**
   * Gets the enabled methods.
   *
   * @return the enabled methods
   */
  public @NonNull Set<ClientAuthenticationMethod> getEnabledMethods() {
    return this.enabledMethods;
  }

  /**
   * Verifies a client secret sent with {@code client_secret_basic} or {@code client_secret_post}.
   *
   * @param authentication the authentication
   * @param metadata the client metadata
   * @param logString the log string
   * @throws TokenErrorException if the secret is wrong
   */
  private static void verifySecret(final @NonNull PlainClientSecret authentication,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws TokenErrorException {
    final Secret secret = OidcClientRecord.getClientSecret(metadata);
    if (secret == null) {
      throw invalidClient("The client has no client secret", logString);
    }
    if (!secret.equals(authentication.getClientSecret())) {
      throw invalidClient("Invalid client secret", logString);
    }
  }

  /**
   * Verifies a client assertion, {@code private_key_jwt} or {@code client_secret_jwt}.
   *
   * @param authentication the authentication
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param logString the log string
   * @throws TokenErrorException if the assertion is invalid
   */
  private void verifyAssertion(final @NonNull JWTAuthentication authentication, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws TokenErrorException {

    final SignedJWT assertion = authentication.getClientAssertion();
    final JWSAlgorithm algorithm = assertion.getHeader().getAlgorithm();
    final boolean secretJwt = authentication instanceof ClientSecretJWT;
    final List<JWSAlgorithm> allowed =
        secretJwt ? CLIENT_SECRET_JWT_ALGORITHMS : RequestObjectDecoder.SUPPORTED_SIGNING_ALGORITHMS;
    if (!allowed.contains(algorithm)) {
      throw invalidClient("The client assertion is signed with an unsupported algorithm " + algorithm, logString);
    }
    if (metadata.getTokenEndpointAuthJWSAlg() != null && !metadata.getTokenEndpointAuthJWSAlg().equals(algorithm)) {
      throw invalidClient("The client assertion must be signed with " + metadata.getTokenEndpointAuthJWSAlg(),
          logString);
    }
    if (!(secretJwt ? this.verifyWithSecret(assertion, metadata, logString)
        : this.verifyWithKeys(assertion, clientId, metadata, logString))) {
      throw invalidClient("The signature of the client assertion could not be verified", logString);
    }

    final JWTClaimsSet claims;
    try {
      claims = assertion.getJWTClaimsSet();
    }
    catch (final ParseException e) {
      throw invalidClient("The claims of the client assertion could not be parsed", logString);
    }
    if (!clientId.equals(claims.getIssuer()) || !clientId.equals(claims.getSubject())) {
      throw invalidClient("The iss and sub of the client assertion must be the client_id", logString);
    }
    if (claims.getAudience() == null || claims.getAudience().stream().noneMatch(this.audiences::contains)) {
      throw invalidClient("The aud of the client assertion is neither the token endpoint nor the issuer", logString);
    }
    final Instant now = Instant.now();
    if (claims.getExpirationTime() == null) {
      throw invalidClient("The client assertion has no exp", logString);
    }
    final Instant expiresAt = claims.getExpirationTime().toInstant();
    if (now.isAfter(expiresAt.plus(this.clockSkew))) {
      throw invalidClient("The client assertion has expired", logString);
    }
    // iat is optional (OpenID Connect Core, Section 9), but is checked when present ...
    if (claims.getIssueTime() != null) {
      final Instant issued = claims.getIssueTime().toInstant();
      if (issued.isAfter(now.plus(this.clockSkew))) {
        throw invalidClient("The iat of the client assertion is in the future", logString);
      }
      if (this.maxJwtAge != null && now.isAfter(issued.plus(this.maxJwtAge).plus(this.clockSkew))) {
        throw invalidClient("The client assertion is too old", logString);
      }
    }
    if (claims.getJWTID() == null || claims.getJWTID().isBlank()) {
      throw invalidClient("The client assertion has no jti", logString);
    }
    if (!this.replayCache.register(clientId, claims.getJWTID(), expiresAt.plus(this.clockSkew))) {
      throw invalidClient("The client assertion has already been used", logString);
    }
  }

  /**
   * Verifies a {@code private_key_jwt} assertion with the keys of the client. The client may have several keys, for
   * example during a key rollover, and each candidate is tried.
   *
   * @param assertion the assertion
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param logString the log string
   * @return {@code true} if a key verifies the signature and {@code false} otherwise
   * @throws TokenErrorException if the keys cannot be obtained
   */
  private boolean verifyWithKeys(final @NonNull SignedJWT assertion, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws TokenErrorException {
    final List<JWK> candidates;
    try {
      candidates = this.clientKeyResolver.resolve(clientId, metadata, assertion.getHeader());
    }
    catch (final KeySourceException e) {
      log.info("Failed to get the keys of the client - {} [{}]", e.getMessage(), logString);
      throw new TokenErrorException(OAuth2Error.INVALID_CLIENT, "The keys of the client could not be obtained", e);
    }
    final DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
    for (final JWK candidate : candidates) {
      if (candidate instanceof final AsymmetricJWK asymmetric) {
        try {
          final JWSVerifier verifier = factory.createJWSVerifier(assertion.getHeader(), asymmetric.toPublicKey());
          if (assertion.verify(verifier)) {
            return true;
          }
        }
        catch (final JOSEException e) {
          log.debug("Failed to verify client assertion with key '{}' - {} [{}]", candidate.getKeyID(),
              e.getMessage(), logString);
        }
      }
    }
    return false;
  }

  /**
   * Verifies a {@code client_secret_jwt} assertion with the client secret.
   *
   * @param assertion the assertion
   * @param metadata the client metadata
   * @param logString the log string
   * @return {@code true} if the signature is valid and {@code false} otherwise
   * @throws TokenErrorException if the client has no usable secret
   */
  private boolean verifyWithSecret(final @NonNull SignedJWT assertion, final @NonNull OIDCClientMetadata metadata,
      final @NonNull String logString) throws TokenErrorException {
    final Secret secret = OidcClientRecord.getClientSecret(metadata);
    if (secret == null) {
      throw invalidClient("The client has no client secret", logString);
    }
    try {
      return assertion.verify(new MACVerifier(secret.getValueBytes()));
    }
    catch (final JOSEException e) {
      log.debug("Failed to verify client assertion with the client secret - {} [{}]", e.getMessage(), logString);
      return false;
    }
  }

  /**
   * Creates the exception for a client that cannot be authenticated, and logs it.
   *
   * @param description the description
   * @param logString the log string, or {@code null}
   * @return a {@link TokenErrorException}
   */
  private static @NonNull TokenErrorException invalidClient(final @NonNull String description,
      final @Nullable String logString) {
    if (logString != null) {
      log.info("Client authentication failed - {} [{}]", description, logString);
    }
    else {
      log.info("Client authentication failed - {}", description);
    }
    return new TokenErrorException(OAuth2Error.INVALID_CLIENT, description);
  }

}
