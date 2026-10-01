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
import org.springframework.http.HttpStatus;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.oauth2.sdk.ErrorObject;

import se.swedenconnect.spring.authnserver.audit.AuthnEventPublisher;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.audit.OidcAuditData;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorMapping;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorResponseException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseSender;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;

/**
 * A filter that answers errors with an OpenID Connect error response to the client's redirect URI.
 * <p>
 * An {@link OidcErrorResponseException} or an {@link AuthenticationErrorException} thrown further down the filter
 * chain is sent to the client, in the requested response mode and with {@code state}, provided that the
 * {@link OidcResponseTarget} has been established for the request. Without it, the error ends at the OpenID Provider
 * as an {@link UnrecoverableErrorException}.
 * </p>
 * <p>
 * An {@link UnrecoverableErrorException} for {@link OidcUnrecoverableError#UNSUPPORTED_RESPONSE_MODE} is answered with
 * HTTP status 400, as OpenID Connect Core, Section 3.1.2.6, requires. Other unrecoverable errors, and other
 * exceptions, are passed on.
 * </p>
 * <p>
 * An error response that is sent is audited as an {@code authn_error_response} event, and the HTTP status 400 as an
 * {@code authn_unrecoverable_error} event.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcErrorResponseProcessingFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcErrorResponseProcessingFilter.class);

  /** The matcher for the authorization endpoint. */
  private final RequestMatcher requestMatcher;

  /** Sends the error response. */
  private final OidcResponseSender responseSender;

  /** Publishes the audit events. */
  private AuthnEventPublisher eventPublisher = AuthnEventPublisher.noop();

  /** For finding the error in a cause chain. */
  private final ThrowableAnalyzer throwableAnalyzer = new ServletThrowableAnalyzer();

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the authorization endpoint
   * @param responseSender sends the error response
   */
  public OidcErrorResponseProcessingFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull OidcResponseSender responseSender) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
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
    try {
      filterChain.doFilter(request, response);
    }
    catch (final IOException e) {
      throw e;
    }
    catch (final ServletException | RuntimeException e) {
      final Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(e);

      if (this.throwableAnalyzer.getFirstThrowableOfType(UnrecoverableErrorException.class, causeChain)
          instanceof final UnrecoverableErrorException unrecoverable) {
        if (unrecoverable.getError() == OidcUnrecoverableError.UNSUPPORTED_RESPONSE_MODE && !response.isCommitted()) {
          this.eventPublisher.publishUnrecoverableError(request, unrecoverable);
          response.sendError(HttpStatus.BAD_REQUEST.value(), unrecoverable.getMessage());
          return;
        }
        throw e;
      }

      final ErrorObject error;
      if (this.throwableAnalyzer.getFirstThrowableOfType(OidcErrorResponseException.class, causeChain)
          instanceof final OidcErrorResponseException oidcError) {
        error = oidcError.toErrorObject();
      }
      else if (this.throwableAnalyzer.getFirstThrowableOfType(AuthenticationErrorException.class, causeChain)
          instanceof final AuthenticationErrorException authnError) {
        error = OidcErrorMapping.of(authnError);
      }
      else {
        throw e;
      }

      final OidcResponseTarget target = OidcResponseTarget.fromRequest(request);
      if (target == null) {
        log.error("An error that should be reported to the client occurred, but no redirect URI has been established"
            + " - {}", error.getDescription());
        throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "No response target available");
      }
      if (response.isCommitted()) {
        throw new ServletException("Unable to send OIDC error response since the response is already committed", e);
      }
      log.debug("Sending error response '{}' to '{}' [requester: 'OIDC:{}']", error.getCode(), target.redirectUri(),
          target.clientId());
      this.eventPublisher.publishErrorResponse(request, OidcAuditData.authorizationErrorResponse(target),
          error.getCode(), error.getDescription());
      this.responseSender.sendError(request, response, target, error);
    }
  }

  /**
   * Assigns the publisher of the audit events. The default publishes nothing.
   *
   * @param eventPublisher the event publisher
   */
  public void setEventPublisher(final @NonNull AuthnEventPublisher eventPublisher) {
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
  }

  /**
   * A {@link ThrowableAnalyzer} that also follows the root cause of a {@link ServletException}.
   */
  private static final class ServletThrowableAnalyzer extends ThrowableAnalyzer {

    /** {@inheritDoc} */
    @Override
    protected void initExtractorMap() {
      super.initExtractorMap();
      this.registerExtractor(ServletException.class, throwable -> {
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
        return ((ServletException) throwable).getRootCause();
      });
    }
  }

}
