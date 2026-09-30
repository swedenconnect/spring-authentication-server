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
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.oidc.userinfo.UserInfoRequestProcessor;

/**
 * A filter that serves the UserInfo endpoint. The request is processed by the {@link UserInfoRequestProcessor}, and
 * the response written directly; the filter chain is not continued.
 *
 * @author Martin Lindström
 */
public class OidcUserInfoEndpointFilter extends OncePerRequestFilter {

  /** The matcher for the UserInfo endpoint. */
  private final RequestMatcher requestMatcher;

  /** Processes the UserInfo requests. */
  private final UserInfoRequestProcessor processor;

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the UserInfo endpoint
   * @param processor processes the UserInfo requests
   */
  public OidcUserInfoEndpointFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull UserInfoRequestProcessor processor) {
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
    OidcTokenEndpointFilter.write(this.processor.process(request), response);
  }

}
