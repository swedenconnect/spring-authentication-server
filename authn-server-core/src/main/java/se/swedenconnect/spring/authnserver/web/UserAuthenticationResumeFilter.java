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
package se.swedenconnect.spring.authnserver.web;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectFlowRepository;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The filter that receives the user on the resume paths of the redirect providers, for the whole server.
 * <p>
 * It finds the authentication in progress that the request concerns, and hands it to the
 * {@link ResumedAuthenticationHandler} of the protocol that the authentication was started for. A request without a
 * matching authentication in progress, or for a protocol that the server does not offer, is an unrecoverable
 * {@link CommonUnrecoverableError#INVALID_SESSION} error.
 * </p>
 *
 * @author Martin Lindström
 */
public class UserAuthenticationResumeFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(UserAuthenticationResumeFilter.class);

  /** The redirect providers and the matchers for their resume paths. */
  private final Map<UserRedirectAuthenticationProvider, RequestMatcher> providers = new LinkedHashMap<>();

  /** The handlers, per protocol. */
  private final Map<AuthenticationProtocol, ResumedAuthenticationHandler> handlers =
      new EnumMap<>(AuthenticationProtocol.class);

  /**
   * Constructor.
   *
   * @param providers the redirect providers
   * @param handlers the handlers of the protocols that the server offers
   */
  public UserAuthenticationResumeFilter(final @Nonnull List<UserRedirectAuthenticationProvider> providers,
      final @Nonnull Collection<ResumedAuthenticationHandler> handlers) {
    Objects.requireNonNull(providers, "providers must not be null")
        .forEach(p -> this.providers.put(p, PathPatternRequestMatcher.pathPattern(p.getResumeAuthnPath())));
    Objects.requireNonNull(handlers, "handlers must not be null")
        .forEach(h -> this.handlers.put(h.getProtocol(), h));
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(final @Nonnull HttpServletRequest request,
      final @Nonnull HttpServletResponse response, final @Nonnull FilterChain filterChain)
      throws ServletException, IOException {

    final List<UserRedirectAuthenticationProvider> matching = this.providers.entrySet().stream()
        .filter(e -> e.getValue().matches(request))
        .map(Map.Entry::getKey)
        .toList();
    if (matching.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    RedirectFlowRepository repository = null;
    AuthenticationProtocol protocol = null;
    for (final UserRedirectAuthenticationProvider provider : matching) {
      protocol = provider.getFlowRepository().getProtocol(request);
      if (protocol != null) {
        repository = provider.getFlowRepository();
        break;
      }
    }
    if (repository == null) {
      log.info("No authentication in progress for authn-id '{}' on the resume path",
          RedirectForAuthenticationToken.getAuthnId(request));
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION,
          "No authentication in progress for the request");
    }
    final ResumedAuthenticationHandler handler = this.handlers.get(protocol);
    if (handler == null) {
      repository.clear(request);
      log.info("The authentication '{}' was started for {}, which is not enabled",
          RedirectForAuthenticationToken.getAuthnId(request), protocol);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION,
          "The authentication in progress was started for %s, which is not enabled".formatted(protocol));
    }

    final ResumedAuthenticationToken token = repository.resume(request);
    log.debug("Resuming the authentication '{}' for {} [{}]", token.getAuthnId(), protocol,
        token.getAuthnInputToken().getLogString());
    handler.resume(request, response, token);
  }

}
