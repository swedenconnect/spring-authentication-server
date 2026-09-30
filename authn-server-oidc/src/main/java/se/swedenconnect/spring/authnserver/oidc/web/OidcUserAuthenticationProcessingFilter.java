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

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.response.OidcUserAuthenticationResponder;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * A filter that authenticates the user for a processed OpenID Connect authentication request and answers the client.
 * <p>
 * The processed request is found in the request attribute that {@link OidcAuthnRequestProcessingFilter} puts it in.
 * It is handed to the authentication providers through the {@link UserAuthenticationFlow}. If a provider redirects
 * the user to pages of its own, the flow continues on the resume path, see {@link OidcResumedAuthenticationHandler}.
 * Otherwise the authorization code is issued and sent to the client.
 * </p>
 * <p>
 * Errors are thrown and answered to the client by {@link OidcErrorResponseProcessingFilter}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcUserAuthenticationProcessingFilter extends OncePerRequestFilter {

  /** The matcher for the authorization endpoint. */
  private final RequestMatcher requestMatcher;

  /** Hands the request to the authentication providers. */
  private final UserAuthenticationFlow flow;

  /** Answers the client. */
  private final OidcUserAuthenticationResponder responder;

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the authorization endpoint
   * @param flow hands the request to the authentication providers
   * @param responder answers the client
   */
  public OidcUserAuthenticationProcessingFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull UserAuthenticationFlow flow, final @NonNull OidcUserAuthenticationResponder responder) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.flow = Objects.requireNonNull(flow, "flow must not be null");
    this.responder = Objects.requireNonNull(responder, "responder must not be null");
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
    if (!(request.getAttribute(OidcAuthnRequestProcessingFilter.INPUT_TOKEN_ATTRIBUTE)
        instanceof final UserAuthenticationInputToken token)) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "No processed authentication request available");
    }
    final UserAuthentication authentication = this.flow.authenticate(token, request, response);
    if (authentication == null) {
      // The user has been redirected to the pages of an authentication module ...
      return;
    }
    this.responder.sendResponse(request, response, token, authentication);
  }

}
