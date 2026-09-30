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
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.oidc.federation.EntityConfigurationContainer;

/**
 * A filter that publishes the OpenID Federation entity configuration of the OpenID Provider, as described in OpenID
 * Federation 1.0, Section 9. The response has the content type {@value #CONTENT_TYPE}.
 *
 * @author Martin Lindström
 */
public class OidcEntityConfigurationEndpointFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcEntityConfigurationEndpointFilter.class);

  /** The content type of an entity configuration. */
  public static final String CONTENT_TYPE = "application/entity-statement+jwt";

  /** Holds the entity configuration. */
  private final EntityConfigurationContainer container;

  /** The request matcher for the endpoint. */
  private final RequestMatcher requestMatcher;

  /**
   * Constructor.
   *
   * @param container holds the entity configuration
   * @param requestMatcher the request matcher for the endpoint
   */
  public OidcEntityConfigurationEndpointFilter(final @NonNull EntityConfigurationContainer container,
      final @NonNull RequestMatcher requestMatcher) {
    this.container = Objects.requireNonNull(container, "container must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
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
    log.debug("Request for the entity configuration from {}", request.getRemoteAddr());
    final byte[] body;
    try {
      body = this.container.getEntityConfiguration().serialize().getBytes(StandardCharsets.US_ASCII);
    }
    catch (final RuntimeException e) {
      log.error("Failed to produce the entity configuration", e);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return;
    }
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(CONTENT_TYPE);
    response.setContentLength(body.length);
    response.getOutputStream().write(body);
  }

}
