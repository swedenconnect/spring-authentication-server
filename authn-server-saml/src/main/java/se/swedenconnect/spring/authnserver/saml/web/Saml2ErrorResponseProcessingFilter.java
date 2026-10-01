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
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.audit.AuthnEventPublisher;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.audit.Saml2AuditData;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseSender;

/**
 * A filter that answers errors with a SAML error response to the Service Provider.
 * <p>
 * A {@link SamlErrorStatusException} or an {@link AuthenticationErrorException} thrown further down the filter chain
 * is sent to the Service Provider as an error response, provided that the {@link Saml2ResponseAttributes} have been
 * established for the request. Without them, and for any other exception, the error is passed on and ends at the
 * Identity Provider.
 * </p>
 * <p>
 * An error response that is sent is audited as an {@code authn_error_response} event.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2ErrorResponseProcessingFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2ErrorResponseProcessingFilter.class);

  /** The matcher for the SAML endpoints. */
  private final RequestMatcher requestMatcher;

  /** Builds the error response. */
  private final Saml2ResponseBuilder responseBuilder;

  /** Sends the error response. */
  private final Saml2ResponseSender responseSender;

  /** Publishes the audit events. */
  private AuthnEventPublisher eventPublisher = AuthnEventPublisher.noop();

  /** For finding the error in a cause chain. */
  private final ThrowableAnalyzer throwableAnalyzer = new ServletThrowableAnalyzer();

  /**
   * Constructor.
   *
   * @param requestMatcher the matcher for the SAML endpoints
   * @param responseBuilder builds the error response
   * @param responseSender sends the error response
   */
  public Saml2ErrorResponseProcessingFilter(final @NonNull RequestMatcher requestMatcher,
      final @NonNull Saml2ResponseBuilder responseBuilder, final @NonNull Saml2ResponseSender responseSender) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
    this.responseBuilder = Objects.requireNonNull(responseBuilder, "responseBuilder must not be null");
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
      SamlErrorStatusException samlError = (SamlErrorStatusException)
          this.throwableAnalyzer.getFirstThrowableOfType(SamlErrorStatusException.class, causeChain);
      if (samlError == null && this.throwableAnalyzer.getFirstThrowableOfType(
          AuthenticationErrorException.class, causeChain) instanceof final AuthenticationErrorException authnError) {
        samlError = SamlErrorStatusException.of(authnError);
      }
      if (samlError == null) {
        throw e;
      }
      final Saml2ResponseAttributes responseAttributes = Saml2ResponseAttributes.fromRequest(request);
      if (responseAttributes == null) {
        log.error("An error that should be reported to the SP occurred, but no response data is available - {}",
            samlError.getDescription());
        throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "No response data available",
            samlError);
      }
      if (response.isCommitted()) {
        throw new ServletException("Unable to send SAML error response since the response is already committed", e);
      }
      final Response samlResponse = this.responseBuilder.buildErrorResponse(responseAttributes, samlError);
      this.eventPublisher.publishErrorResponse(request,
          Saml2AuditData.errorResponse(samlResponse, responseAttributes.relayState()),
          samlError.getStatus().subStatusCode(), samlError.getDescription());
      log.debug("Sending error response {}/{} to '{}' [entity-id: '{}', authn-request: '{}']",
          samlError.getStatus().statusCode(), samlError.getStatus().subStatusCode(),
          responseAttributes.destination(), responseAttributes.getEntityId(), responseAttributes.inResponseTo());
      this.responseSender.send(request, response, responseAttributes.destination(), samlResponse,
          responseAttributes.relayState());
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
