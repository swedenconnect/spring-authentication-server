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
package se.swedenconnect.spring.authnserver.oidc.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;

import se.swedenconnect.spring.authnserver.oidc.token.TokenRequestProcessor;

/**
 * A filter that serves the token endpoint. The request is processed by the {@link TokenRequestProcessor}, and the
 * response written directly; the filter chain is not continued.
 *
 * @author Martin Lindström
 */
public class OidcTokenEndpointFilter extends OncePerRequestFilter {

  /** The matcher for the token endpoint. */
  private final RequestMatcher requestMatcher;

  /** Processes the token requests. */
  private final TokenRequestProcessor processor;

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the token endpoint
   * @param processor processes the token requests
   */
  public OidcTokenEndpointFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull TokenRequestProcessor processor) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.processor = Objects.requireNonNull(processor, "processor must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response, final @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    final HTTPRequest httpRequest = JakartaServletUtils.createHTTPRequest(request);
    final HTTPResponse httpResponse = this.processor.process(httpRequest);

    response.setStatus(httpResponse.getStatusCode());
    for (final Map.Entry<String, List<String>> header : httpResponse.getHeaderMap().entrySet()) {
      for (final String value : header.getValue()) {
        if ("Content-Type".equalsIgnoreCase(header.getKey())) {
          response.setContentType(value);
        }
        else {
          response.addHeader(header.getKey(), value);
        }
      }
    }
    if (httpResponse.getBody() != null) {
      response.getWriter().write(httpResponse.getBody());
    }
    response.flushBuffer();
  }

}
