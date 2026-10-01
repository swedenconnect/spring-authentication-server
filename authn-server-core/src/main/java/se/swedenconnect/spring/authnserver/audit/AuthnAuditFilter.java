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
package se.swedenconnect.spring.authnserver.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The first filter of the authentication server's filter chain. It keeps the correlation ID to the request, and audits
 * the errors that are shown to the user.
 * <p>
 * The correlation ID is cleared when the request starts and when it ends, whatever the outcome, so that it never
 * reaches the next request on the same thread. In between, the protocol modules assign it, see
 * {@link FlowCorrelation}. For a request on the authentication path of a redirect provider that belongs to an
 * authentication in progress, the filter assigns the correlation ID of that flow, so that events the module publishes
 * while it authenticates the user are audited under it.
 * </p>
 * <p>
 * An {@link UnrecoverableErrorException} that leaves the filter chain is published as an
 * {@link se.swedenconnect.spring.authnserver.audit.events.AuthnUnrecoverableErrorEvent AuthnUnrecoverableErrorEvent}
 * before it is passed on.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthnAuditFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnAuditFilter.class);

  /** Publishes the events. */
  private final AuthnEventPublisher eventPublisher;

  /** The redirect providers and the matchers for their authentication paths. */
  private final Map<UserRedirectAuthenticationProvider, RequestMatcher> redirectProviders = new LinkedHashMap<>();

  /** For finding the error in a cause chain. */
  private final ThrowableAnalyzer throwableAnalyzer = new ServletThrowableAnalyzer();

  /**
   * Constructor.
   *
   * @param eventPublisher publishes the events
   * @param redirectProviders the redirect providers, whose authentication paths are joined to their flows
   */
  public AuthnAuditFilter(final @NonNull AuthnEventPublisher eventPublisher,
      final @NonNull List<UserRedirectAuthenticationProvider> redirectProviders) {
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
    Objects.requireNonNull(redirectProviders, "redirectProviders must not be null")
        .forEach(p -> this.redirectProviders.put(p, PathPatternRequestMatcher.pathPattern(p.getAuthnPath())));
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response, final @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    FlowCorrelation.clear();
    try {
      this.joinModuleFlow(request);
      filterChain.doFilter(request, response);
    }
    catch (final ServletException | RuntimeException e) {
      if (this.throwableAnalyzer.getFirstThrowableOfType(UnrecoverableErrorException.class,
          this.throwableAnalyzer.determineCauseChain(e)) instanceof final UnrecoverableErrorException error) {
        this.eventPublisher.publishUnrecoverableError(request, error);
      }
      throw e;
    }
    finally {
      FlowCorrelation.clear();
    }
  }

  /**
   * If the request is on the authentication path of a redirect provider and belongs to an authentication in progress,
   * the request joins the flow of that authentication.
   *
   * @param request the HTTP request
   */
  private void joinModuleFlow(final @NonNull HttpServletRequest request) {
    if (this.redirectProviders.isEmpty() || RedirectForAuthenticationToken.getAuthnId(request) == null) {
      return;
    }
    for (final Map.Entry<UserRedirectAuthenticationProvider, RequestMatcher> entry
        : this.redirectProviders.entrySet()) {
      if (!entry.getValue().matches(request)) {
        continue;
      }
      try {
        final RedirectForAuthenticationToken token = entry.getKey().getAuthenticatorRepository().getInputToken(request);
        final AuditFlowData flowData = token != null ? token.getAuthnInputToken().getAuditData() : null;
        if (flowData != null) {
          FlowCorrelation.join(flowData.correlationId());
          AuditRequestContext.get(request)
              .setRequester(flowData.requester())
              .setStage(AuditStage.USER_AUTHENTICATION);
          return;
        }
      }
      catch (final RuntimeException e) {
        log.debug("Failed to find the authentication in progress for the authentication path - {}", e.getMessage());
      }
    }
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
