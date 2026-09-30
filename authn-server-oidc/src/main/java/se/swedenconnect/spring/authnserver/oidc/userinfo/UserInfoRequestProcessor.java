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
package se.swedenconnect.spring.authnserver.oidc.userinfo;

import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;
import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.attributes.DeliveredClaims;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenData;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientEncryption;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Processes UserInfo requests, as OpenID Connect Core, Section 5.3, and the Swedish OpenID Connect Profile, Section
 * 4.1, describe.
 * <p>
 * The access token is accepted in the {@code Authorization: Bearer} header, or as the {@code access_token} parameter
 * of a form-encoded POST body (RFC 6750, Sections 2.1 and 2.2). The URI query parameter of RFC 6750, Section 2.3, is
 * not accepted, and a request carrying the token in more than one way is rejected. Errors follow RFC 6750, Section 3:
 * a request without a token gets HTTP status 401 with only {@code WWW-Authenticate: Bearer}, a malformed request
 * {@code invalid_request} (400), and a token that is unknown, expired, revoked or already used {@code invalid_token}
 * (401).
 * </p>
 * <p>
 * The response holds {@code sub} and the claims that were released for the UserInfo endpoint when the authentication
 * completed, see {@link DeliveredClaims}. A single use access token is consumed by the first successful call.
 * </p>
 * <p>
 * When UserInfo signing is on, or the client has registered {@code userinfo_signed_response_alg}, the response is a
 * JWT signed with the key chosen for the client, see {@link SigningKeySelector#selectForUserInfo(OIDCClientMetadata)},
 * carrying {@code iss} and {@code aud}. When the client has registered {@code userinfo_encrypted_response_alg}, the
 * response is encrypted, see {@link ClientEncryption}; a signed response is signed and then encrypted, and an unsigned
 * one is a JWT that is only encrypted (OpenID Connect Core, Section 5.3.2). A client for which the response cannot be
 * signed or encrypted gets the error {@code invalid_client_metadata} (400) and no claims.
 * </p>
 *
 * @author Martin Lindström
 */
public class UserInfoRequestProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(UserInfoRequestProcessor.class);

  /** The name of the form parameter carrying the access token. */
  public static final String ACCESS_TOKEN_PARAMETER = "access_token";

  /** The error given when the response cannot be signed or encrypted for the client. */
  public static final BearerTokenError INVALID_CLIENT_METADATA = new BearerTokenError("invalid_client_metadata",
      "The UserInfo response cannot be produced with the registered client metadata", HTTPResponse.SC_BAD_REQUEST);

  /** The syntax of a bearer token, {@code b64token} of RFC 6750, Section 2.1. */
  private static final Pattern B64TOKEN = Pattern.compile("[A-Za-z0-9\\-._~+/]+=*");

  /** The content type of a signed or encrypted response. */
  private static final String APPLICATION_JWT = "application/jwt";

  /** What is signed and encrypted, for log and error messages. */
  private static final String WHAT = "UserInfo response";

  /** The issuer. */
  private final String issuer;

  /** Keeps the access tokens. */
  private final AccessTokenStore accessTokenStore;

  /** The client registry. */
  private final ClientRegistry clientRegistry;

  /** Chooses the signing key. */
  private final SigningKeySelector signingKeySelector;

  /** Encrypts responses for clients. */
  private final ClientEncryption clientEncryption;

  /** Whether responses are signed also when the client has not asked for it. */
  private boolean signUserInfo = true;

  /**
   * Constructor.
   *
   * @param issuer the issuer
   * @param accessTokenStore keeps the access tokens
   * @param clientRegistry the client registry
   * @param signingKeySelector chooses the signing key
   * @param clientEncryption encrypts responses for clients
   */
  public UserInfoRequestProcessor(final @NonNull String issuer, final @NonNull AccessTokenStore accessTokenStore,
      final @NonNull ClientRegistry clientRegistry, final @NonNull SigningKeySelector signingKeySelector,
      final @NonNull ClientEncryption clientEncryption) {
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.accessTokenStore = Objects.requireNonNull(accessTokenStore, "accessTokenStore must not be null");
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.signingKeySelector = Objects.requireNonNull(signingKeySelector, "signingKeySelector must not be null");
    this.clientEncryption = Objects.requireNonNull(clientEncryption, "clientEncryption must not be null");
  }

  /**
   * Processes a UserInfo request.
   *
   * @param request the request
   * @return the UserInfo response or the error response
   */
  public @NonNull HTTPResponse process(final @NonNull HttpServletRequest request) {
    HTTPResponse response;
    try {
      response = this.processRequest(request);
    }
    catch (final UserInfoErrorException e) {
      if (e.getError() != null) {
        response = new UserInfoErrorResponse(e.getError()).toHTTPResponse();
      }
      else {
        response = new HTTPResponse(HTTPResponse.SC_SERVER_ERROR);
        response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setBody("{\"error\":\"server_error\"}");
      }
    }
    response.setCacheControl("no-store");
    response.setPragma("no-cache");
    return response;
  }

  /**
   * Processes a UserInfo request.
   *
   * @param request the request
   * @return the UserInfo response
   * @throws UserInfoErrorException if the request fails
   */
  private @NonNull HTTPResponse processRequest(final @NonNull HttpServletRequest request)
      throws UserInfoErrorException {

    final String tokenValue = getAccessToken(request);
    final AccessTokenData token = this.accessTokenStore.get(tokenValue);
    if (token == null) {
      log.info("UserInfo request with an access token that is unknown, expired, revoked or already used");
      throw new UserInfoErrorException(BearerTokenError.INVALID_TOKEN.setDescription(
          "The access token is not valid"));
    }
    final String logString = "requester: 'OIDC:%s'".formatted(token.clientId());
    final OIDCClientMetadata metadata = this.getClientMetadata(token.clientId(), logString);

    final JSONObject claims = DeliveredClaims.parse(token.userInfoClaims());
    claims.put("sub", token.subject());
    final HTTPResponse response = this.createResponse(claims, token.clientId(), metadata, logString);

    // Consume the token only now, so that a failed call does not use it up. If another call got here first, the token
    // has been used.
    //
    if (!this.accessTokenStore.markUsed(tokenValue)) {
      log.info("UserInfo request with an access token that was used by another request [{}]", logString);
      throw new UserInfoErrorException(BearerTokenError.INVALID_TOKEN.setDescription(
          "The access token is not valid"));
    }
    log.debug("UserInfo response delivered - claims: {} [{}]", claims.keySet(), logString);
    return response;
  }

  /**
   * Creates the response, as plain JSON, as a signed JWT, or as an encrypted JWT.
   *
   * @param claims the claims, including {@code sub}
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param logString the log string
   * @return the response
   * @throws UserInfoErrorException if the response cannot be signed or encrypted for the client
   */
  private @NonNull HTTPResponse createResponse(final @NonNull JSONObject claims, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws UserInfoErrorException {

    final boolean sign = this.signUserInfo || metadata.getUserInfoJWSAlg() != null;
    final JWEAlgorithm encryptionAlgorithm = metadata.getUserInfoJWEAlg();
    final HTTPResponse response = new HTTPResponse(HTTPResponse.SC_OK);

    if (!sign && encryptionAlgorithm == null) {
      response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
      response.setBody(claims.toJSONString());
      return response;
    }
    try {
      final Payload payload;
      if (sign) {
        final SigningKeySelector.SelectedSigningKey key = this.selectSigningKey(metadata, logString);
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(JWTClaimsSet.parse(claims))
            .issuer(this.issuer)
            .audience(clientId);
        final SignedJWT signed = key.key().sign(builder.build(), key.algorithm());
        if (encryptionAlgorithm == null) {
          response.setHeader("Content-Type", APPLICATION_JWT);
          response.setBody(signed.serialize());
          return response;
        }
        payload = new Payload(signed);
      }
      else {
        payload = new Payload(claims);
      }
      final String encrypted = this.clientEncryption.encrypt(payload, sign, clientId, metadata, encryptionAlgorithm,
          metadata.getUserInfoJWEEnc(), WHAT);
      response.setHeader("Content-Type", APPLICATION_JWT);
      response.setBody(encrypted);
      return response;
    }
    catch (final UnrecoverableErrorException e) {
      throw new UserInfoErrorException(INVALID_CLIENT_METADATA);
    }
    catch (final JOSEException | java.text.ParseException e) {
      log.error("Failed to sign the UserInfo response - {} [{}]", e.getMessage(), logString, e);
      throw new UserInfoErrorException(null);
    }
  }

  /**
   * Chooses the signing key, and logs a client configuration problem.
   *
   * @param metadata the client metadata
   * @param logString the log string
   * @return the key and algorithm
   * @throws UnrecoverableErrorException if no active key can produce an algorithm that the client accepts
   */
  private SigningKeySelector.@NonNull SelectedSigningKey selectSigningKey(final @NonNull OIDCClientMetadata metadata,
      final @NonNull String logString) throws UnrecoverableErrorException {
    try {
      return this.signingKeySelector.selectForUserInfo(metadata);
    }
    catch (final UnrecoverableErrorException e) {
      log.warn("Client configuration error - {} [{}]", e.getMessage(), logString);
      throw e;
    }
  }

  /**
   * Gets the metadata of the client that the token was issued to.
   *
   * @param clientId the {@code client_id}
   * @param logString the log string
   * @return the client metadata
   * @throws UserInfoErrorException with {@code invalid_token} if the client is no longer known
   */
  private @NonNull OIDCClientMetadata getClientMetadata(final @NonNull String clientId,
      final @NonNull String logString) throws UserInfoErrorException {
    final RequesterRecord record;
    try {
      record = this.clientRegistry.lookup(AuthenticationProtocol.OIDC, clientId);
    }
    catch (final ClientRegistryException e) {
      log.error("Failed to look up client in the client registry - {} [{}]", e.getMessage(), logString, e);
      throw new UserInfoErrorException(null);
    }
    if (record == null || !(record.protocolMetadata() instanceof final OIDCClientMetadata metadata)) {
      log.info("UserInfo request with an access token for a client that is no longer known [{}]", logString);
      throw new UserInfoErrorException(BearerTokenError.INVALID_TOKEN.setDescription(
          "The access token is not valid"));
    }
    return metadata;
  }

  /**
   * Gets the access token of the request, from the {@code Authorization} header or the form-encoded POST body.
   *
   * @param request the request
   * @return the access token
   * @throws UserInfoErrorException if there is no token, if it is sent in the query or in more than one way, or if
   *     the request is otherwise malformed
   */
  private static @NonNull String getAccessToken(final @NonNull HttpServletRequest request)
      throws UserInfoErrorException {

    if (request.getQueryString() != null
        && URLUtils.parseParameters(request.getQueryString()).containsKey(ACCESS_TOKEN_PARAMETER)) {
      throw invalidRequest("The access token must not be sent in the URI query");
    }

    final List<String> headers = Collections.list(request.getHeaders("Authorization"));
    if (headers.size() > 1) {
      throw invalidRequest("More than one Authorization header");
    }
    String headerToken = null;
    if (headers.size() == 1 && headers.getFirst().regionMatches(true, 0, "Bearer", 0, 6)) {
      final String header = headers.getFirst();
      if (header.length() <= 7 || header.charAt(6) != ' ') {
        throw invalidRequest("Malformed Bearer authorization");
      }
      headerToken = header.substring(7).trim();
      if (!B64TOKEN.matcher(headerToken).matches()) {
        throw invalidRequest("Malformed Bearer authorization");
      }
    }

    String bodyToken = null;
    if ("POST".equalsIgnoreCase(request.getMethod()) && isFormEncoded(request.getContentType())) {
      final String[] values = request.getParameterValues(ACCESS_TOKEN_PARAMETER);
      if (values != null) {
        if (values.length > 1) {
          throw invalidRequest("More than one access_token parameter");
        }
        if (values[0].isBlank()) {
          throw invalidRequest("Empty access_token parameter");
        }
        bodyToken = values[0];
      }
    }

    if (headerToken != null && bodyToken != null) {
      throw invalidRequest("The access token was sent in more than one way");
    }
    if (headerToken == null && bodyToken == null) {
      log.debug("UserInfo request without an access token");
      throw new UserInfoErrorException(BearerTokenError.MISSING_TOKEN);
    }
    return headerToken != null ? headerToken : bodyToken;
  }

  /**
   * Tells whether a content type is {@code application/x-www-form-urlencoded}.
   *
   * @param contentType the content type, or {@code null}
   * @return {@code true} if the content type is form encoded
   */
  private static boolean isFormEncoded(final @Nullable String contentType) {
    if (contentType == null) {
      return false;
    }
    try {
      return MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(MediaType.parseMediaType(contentType));
    }
    catch (final IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Creates the exception for an invalid request, and logs it.
   *
   * @param description the description
   * @return a {@link UserInfoErrorException}
   */
  private static @NonNull UserInfoErrorException invalidRequest(final @NonNull String description) {
    log.info("Invalid UserInfo request - {}", description);
    return new UserInfoErrorException(BearerTokenError.INVALID_REQUEST.setDescription(description));
  }

  /**
   * Assigns whether responses are signed also when the client has not registered
   * {@code userinfo_signed_response_alg}. Defaults to {@code true}.
   *
   * @param signUserInfo whether responses are signed
   */
  public void setSignUserInfo(final boolean signUserInfo) {
    this.signUserInfo = signUserInfo;
  }

  /**
   * An error that ends a UserInfo request.
   */
  private static class UserInfoErrorException extends Exception {

    @Serial
    private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

    /** The error, or {@code null} for an internal error. */
    private final transient BearerTokenError error;

    /**
     * Constructor.
     *
     * @param error the error, or {@code null} for an internal error
     */
    UserInfoErrorException(final @Nullable BearerTokenError error) {
      super(error != null ? error.getDescription() : "Internal error", null, false, false);
      this.error = error;
    }

    /**
     * Gets the error.
     *
     * @return the error, or {@code null} for an internal error
     */
    @Nullable BearerTokenError getError() {
      return this.error;
    }
  }

}
