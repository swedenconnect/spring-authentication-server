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
package se.swedenconnect.spring.authnserver.oidc.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Sends responses to the client's redirect URI, in the response mode of the request: as query parameters of a
 * redirect ({@code query}), or posted by a {@link ResponsePage} ({@code form_post}). The {@code state} of the request
 * is added when the request had one. Query parameters are encoded so that a client that decodes them as
 * {@code application/x-www-form-urlencoded} gets back exactly the values sent.
 *
 * @author Martin Lindström
 */
public class OidcResponseSender {

  /** The page that posts responses. */
  private ResponsePage responsePage = new DefaultResponsePage();

  /**
   * Sends an error response.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param target where and how to answer
   * @param error the error, with its description
   * @throws IOException for errors writing the response
   */
  public void sendError(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull OidcResponseTarget target, final @NonNull ErrorObject error) throws IOException {
    final Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("error", Objects.requireNonNull(error.getCode(), "error code must not be null"));
    if (error.getDescription() != null) {
      parameters.put("error_description", error.getDescription());
    }
    this.send(request, response, target, parameters);
  }

  /**
   * Sends a response with the supplied parameters. The {@code state} is added by this method.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param target where and how to answer
   * @param parameters the response parameters, without {@code state}
   * @throws IOException for errors writing the response
   */
  public void send(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull OidcResponseTarget target, final @NonNull Map<String, String> parameters) throws IOException {

    final Map<String, String> allParameters = new LinkedHashMap<>(parameters);
    if (target.state() != null) {
      allParameters.put("state", target.state());
    }
    if (target.isFormPost()) {
      this.responsePage.sendResponse(request, response, target.redirectUri(), allParameters);
      return;
    }
    final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(target.redirectUri());
    allParameters.forEach((name, value) -> builder.queryParam(encode(name), encode(value)));
    response.sendRedirect(builder.build(true).toUriString());
  }

  /**
   * Encodes a query parameter name or value in the {@code application/x-www-form-urlencoded} format, as RFC 6749,
   * Appendix B, requires. A space is encoded as {@code %20}, which decodes to a space both as form data and as a URI.
   *
   * @param value the value to encode
   * @return the encoded value
   */
  private static @NonNull String encode(final @NonNull String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  /**
   * Assigns the page that posts responses. The default is a {@link DefaultResponsePage}.
   *
   * @param responsePage the response page
   */
  public void setResponsePage(final @NonNull ResponsePage responsePage) {
    this.responsePage = Objects.requireNonNull(responsePage, "responsePage must not be null");
  }

}
