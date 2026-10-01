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

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.util.JWTClaimsSetUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.audit.AuditRequestContext;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorResponseException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Reads an OpenID Connect authentication request received with GET or POST, looks up the client in the
 * {@link ClientRegistry}, resolves a request object, and establishes where to answer.
 * <p>
 * A request object, passed by value ({@code request}) or by reference ({@code request_uri}), is decoded by the
 * {@link RequestObjectDecoder}, and its parameters replace those of the request, as OpenID Connect Core, Section
 * 6.3.3, states. A {@code request_uri} is only fetched if it is one of the client's registered {@code request_uris}.
 * </p>
 * <p>
 * An unknown client, a client registered with the token endpoint authentication method {@code none}, which is not
 * supported, a failing client registry, and a missing or unregistered redirect URI end at the OpenID Provider
 * as an {@link UnrecoverableErrorException}, since there is nowhere safe to send a response. So does a response mode
 * other than {@code query} and {@code form_post}, which gives HTTP status 400. Once the redirect URI and the response
 * mode have been established, the {@link OidcResponseTarget} is kept on the HTTP request and a later failure is sent
 * to the client.
 * </p>
 * <p>
 * If the request object cannot be fetched or decoded, the error is sent to the client when the plain parameters of
 * the request hold a registered redirect URI and a supported response mode. Otherwise it ends at the OpenID Provider.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcAuthnRequestAuthenticationConverter implements AuthenticationConverter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcAuthnRequestAuthenticationConverter.class);

  /** The client registry where the client is looked up. */
  private final ClientRegistry clientRegistry;

  /** Decodes request objects. */
  private final RequestObjectDecoder requestObjectDecoder;

  /** Fetches request objects passed by reference. */
  private final RequestUriFetcher requestUriFetcher;

  /**
   * Constructor.
   *
   * @param clientRegistry the client registry where the client is looked up
   * @param requestObjectDecoder decodes request objects
   * @param requestUriFetcher fetches request objects passed by reference
   */
  public OidcAuthnRequestAuthenticationConverter(final @NonNull ClientRegistry clientRegistry,
      final @NonNull RequestObjectDecoder requestObjectDecoder, final @NonNull RequestUriFetcher requestUriFetcher) {
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.requestObjectDecoder = Objects.requireNonNull(requestObjectDecoder, "requestObjectDecoder must not be null");
    this.requestUriFetcher = Objects.requireNonNull(requestUriFetcher, "requestUriFetcher must not be null");
  }

  /**
   * Reads the request, looks up the client and establishes where to answer.
   *
   * @param request the HTTP request
   * @return an {@link OidcAuthnRequestAuthenticationToken}
   * @throws UnrecoverableErrorException if the request cannot be answered
   * @throws OidcErrorResponseException if the request object is invalid, and a response can be sent
   */
  @Override
  public @NonNull OidcAuthnRequestAuthenticationToken convert(final @NonNull HttpServletRequest request)
      throws UnrecoverableErrorException, OidcErrorResponseException {

    final Map<String, List<String>> parameters = getParameters(request);

    final String clientId = getSingleValue(parameters, "client_id");
    if (clientId == null) {
      log.info("Received authentication request without client_id");
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_AUTHN_REQUEST,
          "Missing client_id in authentication request");
    }
    final String logString = OidcAuthnRequestAuthenticationToken.logString(clientId);

    // Look up the client ...
    //
    final RequesterRecord record;
    try {
      record = this.clientRegistry.lookup(AuthenticationProtocol.OIDC, clientId);
    }
    catch (final ClientRegistryException e) {
      log.error("Failed to look up client in the client registry - {} [{}]", e.getMessage(), logString, e);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.CLIENT_LOOKUP_FAILED,
          "Failed to look up client in the client registry", e);
    }
    if (record == null || !(record.protocolMetadata() instanceof final OIDCClientMetadata metadata)) {
      log.info("Client is not known [{}]", logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.UNKNOWN_CLIENT,
          "Client %s is not known".formatted(clientId));
    }
    log.debug("Client found in the client registry [{}]", logString);
    final AuditRequestContext auditContext =
        AuditRequestContext.get(request).setRequester(AuditRequester.of(record, false));

    // Public clients are not supported ...
    //
    if (ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
      log.warn("Client configuration error - token_endpoint_auth_method 'none' is not supported [{}]", logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "The client is registered with token_endpoint_auth_method none, which is not supported");
    }

    // Resolve a request object ...
    //
    Map<String, List<String>> merged = parameters;
    RequestObjectDecoder.DecodedJwt requestObject = null;
    if (parameters.containsKey("request") || parameters.containsKey("request_uri")) {
      final OidcResponseTarget fallback = getResponseTarget(clientId, metadata, parameters);
      if (fallback != null) {
        OidcResponseTarget.setOnRequest(request, fallback);
      }
      try {
        requestObject = this.resolveRequestObject(parameters, clientId, metadata, logString);
      }
      catch (final OidcErrorResponseException e) {
        if (fallback == null) {
          // The cause is left out, since an authentication exception in the cause chain would be handled by
          // Spring Security's exception translation ...
          throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_AUTHN_REQUEST, e.getDescription());
        }
        throw e;
      }
      merged = merge(parameters, requestObject);
    }

    // Establish where to answer ...
    //
    final String redirectUri = getSingleValue(merged, "redirect_uri");
    if (redirectUri == null) {
      log.info("Missing redirect_uri in authentication request [{}]", logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_REDIRECT_URI,
          "Missing redirect_uri in authentication request");
    }
    if (!isRegisteredRedirectUri(redirectUri, metadata)) {
      log.info("The redirect_uri '{}' is not registered for the client [{}]", redirectUri, logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_REDIRECT_URI,
          "The redirect_uri is not registered for the client");
    }
    final String responseMode = getResponseMode(merged);
    if (responseMode == null) {
      log.info("Unsupported response_mode '{}' [{}]", getFirstValue(merged, "response_mode"), logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.UNSUPPORTED_RESPONSE_MODE,
          "Unsupported response_mode");
    }
    final OidcResponseTarget target =
        new OidcResponseTarget(clientId, redirectUri, responseMode, getFirstValue(merged, "state"));
    OidcResponseTarget.setOnRequest(request, target);
    auditContext.setRequester(AuditRequester.of(record, true));

    return new OidcAuthnRequestAuthenticationToken(record, merged, requestObject, target);
  }

  /**
   * Fetches, if needed, and decodes the request object.
   *
   * @param parameters the parameters of the request
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param logString the log string
   * @return the decoded request object
   * @throws OidcErrorResponseException if the request object cannot be fetched or decoded
   */
  private RequestObjectDecoder.@NonNull DecodedJwt resolveRequestObject(
      final @NonNull Map<String, List<String>> parameters, final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws OidcErrorResponseException {

    final String request = getSingleValue(parameters, "request");
    final String requestUri = getSingleValue(parameters, "request_uri");
    if (request != null && requestUri != null) {
      log.info("Both request and request_uri given [{}]", logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST,
          "The request and request_uri parameters must not both be given");
    }
    if (request != null) {
      return this.requestObjectDecoder.decodeRequestObject(request, clientId, metadata, logString);
    }
    if (requestUri == null) {
      log.info("Invalid request or request_uri parameter [{}]", logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST,
          "The request or request_uri parameter is invalid");
    }

    final URI uri;
    try {
      uri = new URI(requestUri);
    }
    catch (final URISyntaxException e) {
      log.info("Invalid request_uri [{}]", logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST_URI, "The request_uri is not a valid URI", e);
    }
    final URI withoutFragment = withoutFragment(uri);
    final Set<URI> registered = metadata.getRequestObjectURIs();
    if (registered == null || registered.stream().map(OidcAuthnRequestAuthenticationConverter::withoutFragment)
        .noneMatch(withoutFragment::equals)) {
      log.info("The request_uri '{}' is not registered for the client - not fetched [{}]", requestUri, logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST_URI,
          "The request_uri is not registered for the client");
    }
    final String fetched;
    try {
      fetched = this.requestUriFetcher.fetch(withoutFragment);
    }
    catch (final IOException e) {
      log.info("Failed to fetch request object from '{}' - {} [{}]", requestUri, e.getMessage(), logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST_URI,
          "The request object could not be fetched from the request_uri", e);
    }
    log.debug("Fetched request object from '{}' [{}]", requestUri, logString);
    return this.requestObjectDecoder.decodeRequestObject(fetched, clientId, metadata, logString);
  }

  /**
   * Works out where to answer from the parameters, without failing.
   *
   * @param clientId the {@code client_id}
   * @param metadata the client metadata
   * @param parameters the parameters
   * @return the response target, or {@code null} if the parameters do not give a valid one
   */
  private static @Nullable OidcResponseTarget getResponseTarget(final @NonNull String clientId,
      final @NonNull OIDCClientMetadata metadata, final @NonNull Map<String, List<String>> parameters) {
    final String redirectUri = getSingleValue(parameters, "redirect_uri");
    final String responseMode = getResponseMode(parameters);
    if (redirectUri == null || responseMode == null || !isRegisteredRedirectUri(redirectUri, metadata)) {
      return null;
    }
    return new OidcResponseTarget(clientId, redirectUri, responseMode, getFirstValue(parameters, "state"));
  }

  /**
   * Gets the response mode of the request, {@code query} if none is given.
   *
   * @param parameters the parameters
   * @return {@code query} or {@code form_post}, or {@code null} if another response mode is given
   */
  private static @Nullable String getResponseMode(final @NonNull Map<String, List<String>> parameters) {
    final String responseMode = getFirstValue(parameters, "response_mode");
    if (responseMode == null || ResponseMode.QUERY.getValue().equals(responseMode)) {
      return ResponseMode.QUERY.getValue();
    }
    return ResponseMode.FORM_POST.getValue().equals(responseMode) ? responseMode : null;
  }

  /**
   * Tells whether the redirect URI is one of the client's registered redirect URIs, by simple string comparison.
   *
   * @param redirectUri the redirect URI
   * @param metadata the client metadata
   * @return {@code true} if the redirect URI is registered and {@code false} otherwise
   */
  private static boolean isRegisteredRedirectUri(final @NonNull String redirectUri,
      final @NonNull OIDCClientMetadata metadata) {
    return metadata.getRedirectionURIs() != null
        && metadata.getRedirectionURIs().stream().map(URI::toString).anyMatch(redirectUri::equals);
  }

  /**
   * Merges the parameters of a request object into the parameters of the request. The parameters {@code request} and
   * {@code request_uri} are removed.
   *
   * @param parameters the parameters of the request
   * @param requestObject the request object
   * @return the merged parameters
   */
  private static @NonNull Map<String, List<String>> merge(final @NonNull Map<String, List<String>> parameters,
      final RequestObjectDecoder.@NonNull DecodedJwt requestObject) {
    final Map<String, List<String>> merged = new HashMap<>(parameters);
    merged.remove("request");
    merged.remove("request_uri");
    merged.putAll(JWTClaimsSetUtils.toMultiValuedParameters(requestObject.claims()));
    return merged;
  }

  /**
   * Gets the parameters of the HTTP request.
   *
   * @param request the HTTP request
   * @return the parameters, without empty values
   */
  private static @NonNull Map<String, List<String>> getParameters(final @NonNull HttpServletRequest request) {
    final Map<String, List<String>> parameters = new HashMap<>();
    request.getParameterMap().forEach((name, values) -> {
      final List<String> nonEmpty = Arrays.stream(values).filter(StringUtils::hasText).toList();
      if (!nonEmpty.isEmpty()) {
        parameters.put(name, nonEmpty);
      }
    });
    return parameters;
  }

  /**
   * Gets the value of a parameter that may occur only once.
   *
   * @param parameters the parameters
   * @param name the parameter name
   * @return the value, or {@code null} if the parameter is missing or occurs more than once
   */
  private static @Nullable String getSingleValue(final @NonNull Map<String, List<String>> parameters,
      final @NonNull String name) {
    final List<String> values = parameters.get(name);
    return values != null && values.size() == 1 ? values.getFirst() : null;
  }

  /**
   * Gets the first value of a parameter.
   *
   * @param parameters the parameters
   * @param name the parameter name
   * @return the value, or {@code null}
   */
  private static @Nullable String getFirstValue(final @NonNull Map<String, List<String>> parameters,
      final @NonNull String name) {
    final List<String> values = parameters.get(name);
    return values != null && !values.isEmpty() ? values.getFirst() : null;
  }

  /**
   * Removes the fragment of a URI.
   *
   * @param uri the URI
   * @return the URI without fragment
   */
  private static @NonNull URI withoutFragment(final @NonNull URI uri) {
    if (uri.getRawFragment() == null) {
      return uri;
    }
    final String s = uri.toString();
    return URI.create(s.substring(0, s.indexOf('#')));
  }

}
