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

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Base class for a filter that publishes a JSON document on an endpoint, such as the JWKS or the discovery document.
 * The document is built once, when the filter is created.
 *
 * @author Martin Lindström
 */
abstract class JsonDocumentEndpointFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(JsonDocumentEndpointFilter.class);

  /** The request matcher for the endpoint. */
  private final RequestMatcher requestMatcher;

  /** The document. */
  private final byte[] document;

  /** The name of the document, for logging. */
  private final String name;

  /**
   * Constructor.
   *
   * @param requestMatcher the request matcher for the endpoint
   * @param document the JSON document
   * @param name the name of the document, for logging
   */
  JsonDocumentEndpointFilter(final @Nonnull RequestMatcher requestMatcher, final @Nonnull String document,
      final @Nonnull String name) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.document = Objects.requireNonNull(document, "document must not be null").getBytes(StandardCharsets.UTF_8);
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(final @Nonnull HttpServletRequest request,
      final @Nonnull HttpServletResponse response, final @Nonnull FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    log.debug("Request for the {} from {}", this.name, request.getRemoteAddr());
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setContentLength(this.document.length);
    response.getOutputStream().write(this.document);
  }

}
