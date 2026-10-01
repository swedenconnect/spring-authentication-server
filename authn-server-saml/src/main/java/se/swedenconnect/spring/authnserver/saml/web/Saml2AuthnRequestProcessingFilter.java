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
package se.swedenconnect.spring.authnserver.saml.web;

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

import se.swedenconnect.spring.authnserver.audit.AuditRequestContext;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.AuditStage;
import se.swedenconnect.spring.authnserver.audit.FlowCorrelation;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * A filter that receives SAML authentication requests on the authentication endpoints, and processes them into the
 * protocol-neutral authentication requirements, see {@link Saml2AuthnRequestAuthenticationConverter} and
 * {@link Saml2AuthnRequestAuthenticationProvider}.
 * <p>
 * The result, a {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
 * UserAuthenticationInputToken}, is handed to an {@link AuthenticationSuccessHandler}. Without a handler, it is put
 * in the request attribute {@link #INPUT_TOKEN_ATTRIBUTE} and the filter chain continues, so that
 * {@link Saml2UserAuthenticationProcessingFilter} authenticates the user. The security context is left alone, since
 * it holds the authentication that may be reused for single sign-on.
 * </p>
 * <p>
 * Each request starts a new authentication flow, with a new correlation ID for its audit events.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestProcessingFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2AuthnRequestProcessingFilter.class);

  /** The name of the request attribute that holds the processed request. */
  public static final String INPUT_TOKEN_ATTRIBUTE =
      Saml2AuthnRequestProcessingFilter.class.getPackageName() + ".UserAuthenticationInputToken";

  /** The matcher for the authentication endpoints. */
  private final RequestMatcher requestMatcher;

  /** Decodes the request. */
  private final Saml2AuthnRequestAuthenticationConverter converter;

  /** Validates the request and builds the authentication requirements. */
  private final Saml2AuthnRequestAuthenticationProvider provider;

  /** What to do with the result. */
  private AuthenticationSuccessHandler successHandler = null;

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the authentication endpoints
   * @param converter decodes the request
   * @param provider validates the request and builds the authentication requirements
   */
  public Saml2AuthnRequestProcessingFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull Saml2AuthnRequestAuthenticationConverter converter,
      final @NonNull Saml2AuthnRequestAuthenticationProvider provider) {
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
    // A new authentication flow starts ...
    //
    FlowCorrelation.startFlow();
    AuditRequestContext.get(request)
        .setRequester(AuditRequester.unknown(AuthenticationProtocol.SAML))
        .setStage(AuditStage.AUTHN_REQUEST);

    final Saml2AuthnRequestAuthenticationToken token = this.converter.convert(request);
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
