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
package se.swedenconnect.spring.authnserver.oidc.audit;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.util.JSONObjectUtils;

import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeData;

/**
 * Creates the OpenID Connect part of the audit events.
 *
 * @author Martin Lindström
 */
public final class OidcAuditData {

  /** The name of the object describing the authentication request. */
  public static final String AUTHN_REQUEST = "authn_request";

  /** The name of the object describing the authorization response. */
  public static final String AUTHORIZATION_RESPONSE = "authorization_response";

  /** The name of the object describing a response. */
  public static final String RESPONSE = "response";

  /**
   * Creates the {@code authn_request} object from the parameters of an authentication request. For a received request
   * these are the parameters as sent, and for an accepted request they include those of the request object.
   *
   * @param parameters the request parameters
   * @param requestObject whether a request object was given
   * @param responseMode the response mode that is used, or {@code null} to take it from the parameters
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData authnRequest(final @NonNull Map<String, List<String>> parameters,
      final boolean requestObject, final @Nullable String responseMode) {
    return ProtocolAuditData.builder(AUTHN_REQUEST)
        .member("client_id", first(parameters, "client_id"))
        .member("redirect_uri", first(parameters, "redirect_uri"))
        .member("response_type", first(parameters, "response_type"))
        .member("response_mode", responseMode != null ? responseMode : first(parameters, "response_mode"))
        .member("scope", split(first(parameters, "scope")))
        .member("acr_values", split(first(parameters, "acr_values")))
        .member("prompt", split(first(parameters, "prompt")))
        .member("state", first(parameters, "state"))
        .member("code_challenge_method", first(parameters, "code_challenge_method"))
        .member("request_object", requestObject)
        .build();
  }

  /**
   * Creates the {@code authn_request} object from a received HTTP request, before any check.
   *
   * @param request the HTTP request
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData authnRequest(final @NonNull HttpServletRequest request) {
    final Map<String, List<String>> parameters = new HashMap<>();
    request.getParameterMap().forEach((name, values) -> parameters.put(name, Arrays.asList(values)));
    return authnRequest(parameters,
        parameters.containsKey("request") || parameters.containsKey("request_uri"), null);
  }

  /**
   * Creates the {@code authorization_response} object.
   *
   * @param target where the response is sent
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData authorizationResponse(final @NonNull OidcResponseTarget target) {
    return target(AUTHORIZATION_RESPONSE, target);
  }

  /**
   * Creates the {@code response} object for an authorization error that is sent to the redirect URI.
   *
   * @param target where the response is sent
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData authorizationErrorResponse(final @NonNull OidcResponseTarget target) {
    return target(RESPONSE, target);
  }

  /**
   * Creates the {@code response} object for a token response that holds an ID token.
   *
   * @param code the authorization code that was redeemed
   * @param idTokenEncrypted whether the ID token was encrypted
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData tokenResponse(final @NonNull AuthorizationCodeData code,
      final boolean idTokenEncrypted) {
    return ProtocolAuditData.builder(RESPONSE)
        .member("sub", code.subject())
        .member("acr", code.acr())
        .member("auth_time", code.authnInstant())
        .member("scope", code.scopes())
        .member("redirect_uri", code.redirectUri())
        .member("id_token_signed", true)
        .member("id_token_encrypted", idTokenEncrypted)
        .build();
  }

  /**
   * Creates the {@code response} object for a UserInfo response.
   *
   * @param subject the {@code sub} of the user
   * @param signed whether the response was signed
   * @param encrypted whether the response was encrypted
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData userInfoResponse(final @NonNull String subject, final boolean signed,
      final boolean encrypted) {
    return ProtocolAuditData.builder(RESPONSE)
        .member("sub", subject)
        .member("signed", signed)
        .member("encrypted", encrypted)
        .build();
  }

  /**
   * Creates the {@code response} object for an error from the token or the UserInfo endpoint.
   *
   * @param httpStatus the HTTP status of the response
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData httpErrorResponse(final int httpStatus) {
    return ProtocolAuditData.builder(RESPONSE)
        .member("http_status", httpStatus)
        .build();
  }

  /**
   * Gets claims as audit attributes. A string value is kept as it is, each element of an array becomes a value, and an
   * object is written as JSON.
   *
   * @param claims the claims
   * @param excluded names of claims to leave out
   * @return the attributes
   */
  public static @NonNull List<AuditAttribute> claims(final @NonNull Map<String, Object> claims,
      final @NonNull String... excluded) {
    final List<String> excludedNames = List.of(excluded);
    return claims.entrySet().stream()
        .filter(e -> !excludedNames.contains(e.getKey()))
        .filter(e -> e.getValue() != null)
        .map(e -> new AuditAttribute(e.getKey(), toStrings(e.getValue())))
        .toList();
  }

  /**
   * Gets a claim value as strings.
   *
   * @param value the value
   * @return the values
   */
  private static @NonNull List<String> toStrings(final @NonNull Object value) {
    if (value instanceof final Collection<?> collection) {
      return collection.stream().filter(Objects::nonNull).map(OidcAuditData::toStringValue).toList();
    }
    return List.of(toStringValue(value));
  }

  /**
   * Gets one claim value as a string.
   *
   * @param value the value
   * @return the string
   */
  @SuppressWarnings("unchecked")
  private static @NonNull String toStringValue(final @NonNull Object value) {
    if (value instanceof final Map<?, ?> map) {
      return JSONObjectUtils.toJSONString((Map<String, ?>) map);
    }
    if (value instanceof final Instant instant) {
      return instant.toString();
    }
    return String.valueOf(value);
  }

  /**
   * Creates an object describing where a response is sent.
   *
   * @param name the name of the object
   * @param target where the response is sent
   * @return the protocol-specific data
   */
  private static @NonNull ProtocolAuditData target(final @NonNull String name,
      final @NonNull OidcResponseTarget target) {
    return ProtocolAuditData.builder(name)
        .member("redirect_uri", target.redirectUri())
        .member("response_mode", target.responseMode())
        .member("state", target.state())
        .build();
  }

  /**
   * Gets the first value of a parameter.
   *
   * @param parameters the parameters
   * @param name the name of the parameter
   * @return the value, or {@code null}
   */
  private static @Nullable String first(final @NonNull Map<String, List<String>> parameters,
      final @NonNull String name) {
    final List<String> values = parameters.get(name);
    return values != null && !values.isEmpty() ? values.getFirst() : null;
  }

  /**
   * Splits a space separated parameter value.
   *
   * @param value the value
   * @return the values, or {@code null}
   */
  private static @Nullable List<String> split(final @Nullable String value) {
    return StringUtils.hasText(value) ? Arrays.stream(value.trim().split("\\s+")).toList() : null;
  }

  // Hidden constructor
  private OidcAuditData() {
  }

}
