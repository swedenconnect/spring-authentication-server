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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestAuthenticationToken;

/**
 * A filter that receives OpenID Connect authentication requests on the authorization endpoint, and processes them
 * into the protocol-neutral authentication requirements, see {@link OidcAuthnRequestAuthenticationConverter} and
 * {@link OidcAuthnRequestAuthenticationProvider}.
 * <p>
 * The result, a {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
 * UserAuthenticationInputToken}, is handed to an {@link AuthenticationSuccessHandler}. Without a handler, it is put in
 * the request attribute {@link #INPUT_TOKEN_ATTRIBUTE} and the filter chain continues, so that
 * {@link OidcUserAuthenticationProcessingFilter} authenticates the user. The security context is left alone, since it
 * holds the authentication that may be reused for single sign-on.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcAuthnRequestProcessingFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcAuthnRequestProcessingFilter.class);

  /** The name of the request attribute that holds the processed request. */
  public static final String INPUT_TOKEN_ATTRIBUTE =
      OidcAuthnRequestProcessingFilter.class.getPackageName() + ".UserAuthenticationInputToken";

  /** The matcher for the authorization endpoint. */
  private final RequestMatcher requestMatcher;

  /** Reads the request. */
  private final OidcAuthnRequestAuthenticationConverter converter;

  /** Validates the request and builds the authentication requirements. */
  private final OidcAuthnRequestAuthenticationProvider provider;

  /** What to do with the result. */
  private AuthenticationSuccessHandler successHandler = null;

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the authorization endpoint
   * @param converter reads the request
   * @param provider validates the request and builds the authentication requirements
   */
  public OidcAuthnRequestProcessingFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull OidcAuthnRequestAuthenticationConverter converter,
      final @NonNull OidcAuthnRequestAuthenticationProvider provider) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.converter = Objects.requireNonNull(converter, "converter must not be null");
    this.provider = Objects.requireNonNull(provider, "provider must not be null");
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
    final OidcAuthnRequestAuthenticationToken token = this.converter.convert(request);
    final Authentication result = this.provider.authenticate(token);
    log.debug("Authentication request processed [{}]", token.getLogString());

    if (this.successHandler != null) {
      this.successHandler.onAuthenticationSuccess(request, response, result);
      return;
    }
    request.setAttribute(INPUT_TOKEN_ATTRIBUTE, result);
    filterChain.doFilter(request, response);
  }

  /**
   * Assigns the handler of a processed request. When assigned, the filter chain is not continued; the handler writes
   * the response.
   *
   * @param successHandler the handler
   */
  public void setSuccessHandler(final @NonNull AuthenticationSuccessHandler successHandler) {
    this.successHandler = Objects.requireNonNull(successHandler, "successHandler must not be null");
  }

}
