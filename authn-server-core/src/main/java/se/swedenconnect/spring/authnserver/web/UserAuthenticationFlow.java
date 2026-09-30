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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The protocol-neutral part of authenticating the user. A protocol module hands a processed request to it, and it
 * asks the authentication providers, starts a redirect when a provider asks for one, continues a resumed
 * authentication, and keeps the authentication in the session for single sign-on.
 * <p>
 * The session holds one authentication for the whole server, whichever protocol it was made for. It is kept in the
 * Spring Security {@link SecurityContext}. Whether it may be reused for a request is decided by the provider, from its
 * single sign-on policy and voters.
 * </p>
 * <p>
 * The session authentication stays when a request leads to a redirect for a new authentication, and when a request
 * fails before any authentication has started, since neither says anything about the user. It is removed when an
 * authentication that has started ends in an error, whether the provider reported it, including cancel, fraud and
 * possible fraud, or it was raised while the result was completed, see
 * {@link #failAuthentication(HttpServletRequest, HttpServletResponse, AuthenticationErrorException)}. The errors
 * {@link AuthenticationError#NO_AUTHN_CONTEXT} and {@link AuthenticationError#PASSIVE_NOT_POSSIBLE} are not failures
 * of an authentication, since no provider could take the request or the user was never asked.
 * </p>
 *
 * @author Martin Lindström
 */
public class UserAuthenticationFlow {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(UserAuthenticationFlow.class);

  /** The authentication providers, asked in order. */
  private final List<UserAuthenticationProvider> providers;

  /** Where the security context, and thereby the authentication for single sign-on, is saved. */
  private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

  /** Sends the user to a redirect provider's authentication path. */
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  /**
   * Constructor.
   *
   * @param providers the authentication providers, asked in order
   */
  public UserAuthenticationFlow(final @NonNull List<UserAuthenticationProvider> providers) {
    this.providers = List.copyOf(Objects.requireNonNull(providers, "providers must not be null"));
  }

  /**
   * Authenticates the user for a processed request.
   * <p>
   * The authentication from the session that may be reused is given to the providers, which are asked in order. The
   * first provider that does not return {@code null} handles the request. If it asks for a redirect, the
   * authentication is started and the user is redirected to the provider's authentication path, and the method returns
   * {@code null}.
   * </p>
   * <p>
   * Voluntary authentication contexts that no provider supports are removed from the requirements before the providers
   * are asked, see {@link AuthenticationRequirements#isVoluntaryAuthnContexts()}.
   * </p>
   * <p>
   * The result is given the requirements and the protocol data of the request, so that the protocol module can build
   * its response from it.
   * </p>
   *
   * @param token the processed request
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @return the authentication, or {@code null} if the user has been redirected
   * @throws AuthenticationErrorException if the authentication fails, or with
   *     {@link AuthenticationError#NO_AUTHN_CONTEXT} if no provider handles the request
   * @throws UnrecoverableErrorException if a provider returns something that cannot be used
   * @throws IOException if the redirect cannot be sent
   */
  public @Nullable UserAuthentication authenticate(final @NonNull UserAuthenticationInputToken token,
      final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response)
      throws AuthenticationErrorException, UnrecoverableErrorException, IOException {

    token.setPreviousAuthentication(this.getSessionAuthentication());
    this.resolveVoluntaryAuthnContexts(token);

    for (final UserAuthenticationProvider provider : this.providers) {
      final Authentication result;
      try {
        result = provider.authenticateUser(token);
      }
      catch (final AuthenticationErrorException e) {
        this.failAuthentication(request, response, e);
        throw e;
      }
      if (result == null) {
        continue;
      }
      if (result instanceof final RedirectForAuthenticationToken redirectToken) {
        if (!(provider instanceof final UserRedirectAuthenticationProvider redirectProvider)) {
          throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
              "Provider '%s' asked for a redirect, but is not a redirect provider".formatted(provider.getName()));
        }
        redirectProvider.getFlowRepository().start(redirectToken, request);
        log.debug("Redirecting to '{}' for authentication by provider '{}' [{}]", redirectToken.getAuthnPath(),
            provider.getName(), token.getLogString());
        this.redirectStrategy.sendRedirect(request, response, redirectToken.getRedirectPath());
        return null;
      }
      if (result instanceof final UserAuthentication userAuthentication) {
        log.debug("Provider '{}' authenticated '{}' [{}]", provider.getName(), userAuthentication.getName(),
            token.getLogString());
        return prepare(userAuthentication, token);
      }
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Provider '%s' returned an unsupported result type %s".formatted(
              provider.getName(), result.getClass().getSimpleName()));
    }
    log.info("No authentication provider can deliver any of the requested authentication contexts {} [{}]",
        token.getAuthnRequirements().getAuthnContextRequirements(), token.getLogString());
    throw new AuthenticationErrorException(AuthenticationError.NO_AUTHN_CONTEXT,
        "No authentication provider can deliver any of the requested authentication contexts");
  }

  /**
   * Keeps only the voluntary authentication contexts that some provider supports, in the requester's order of
   * preference. If no provider supports any of them, the requirements are left without authentication contexts, so
   * that the authentication proceeds as if none had been requested. Required contexts are left as they are.
   *
   * @param token the processed request
   */
  private void resolveVoluntaryAuthnContexts(final @NonNull UserAuthenticationInputToken token) {
    final AuthenticationRequirements requirements = token.getAuthnRequirements();
    if (!requirements.isVoluntaryAuthnContexts() || requirements.getAuthnContextRequirements().isEmpty()) {
      return;
    }
    final Set<String> supported = this.providers.stream()
        .map(UserAuthenticationProvider::getSupportedAuthnContextUris)
        .flatMap(Collection::stream)
        .collect(Collectors.toSet());
    final List<String> requested = requirements.getAuthnContextRequirements();
    final List<String> usable = requested.stream().filter(supported::contains).toList();
    if (usable.size() < requested.size()) {
      log.debug("Voluntary authentication contexts {} are not supported and are ignored - using {} [{}]",
          requested.stream().filter(u -> !supported.contains(u)).toList(), usable.isEmpty() ? "any" : usable,
          token.getLogString());
      requirements.setAuthnContextRequirements(usable);
    }
  }

  /**
   * Continues an authentication when the user has come back to the resume path. The provider that started it is
   * found among the redirect providers with the same resume path, and it turns the outcome into the result.
   *
   * @param token the resumed token
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @return the authentication
   * @throws AuthenticationErrorException if the authentication failed, in which case the session authentication has
   *     been removed
   * @throws UnrecoverableErrorException if no provider can use what the module delivered
   */
  public @NonNull UserAuthentication resume(final @NonNull ResumedAuthenticationToken token,
      final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response)
      throws AuthenticationErrorException, UnrecoverableErrorException {

    final UserAuthenticationInputToken inputToken = token.getAuthnInputToken();
    for (final UserRedirectAuthenticationProvider provider : this.getRedirectProviders()) {
      if (!provider.getResumeAuthnPath().equals(token.getRedirectToken().getResumeAuthnPath())) {
        continue;
      }
      if (!token.isError() && !provider.supportsUserAuthenticationToken(token.getAuthnToken())) {
        continue;
      }
      try {
        return prepare(provider.resumeAuthentication(token), inputToken);
      }
      catch (final AuthenticationErrorException e) {
        this.failAuthentication(request, response, e);
        throw e;
      }
    }
    log.error("No authentication provider can use the result of the authentication '{}' [{}]",
        token.getAuthnId(), inputToken.getLogString());
    throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
        "No authentication provider can use the result of the authentication");
  }

  /**
   * Keeps the authentication in the session for single sign-on, or removes any authentication from the session if
   * this one may not be reused. The requirements and the protocol data of the request are cleared first, since the
   * request has been answered.
   * <p>
   * Call it before the response is written, so that the session is updated before the response is committed.
   * </p>
   *
   * @param authentication the authentication
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   */
  public void saveAuthentication(final @NonNull UserAuthentication authentication,
      final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response) {

    authentication.clearAuthnRequirements();
    authentication.clearProtocolRequestData();

    final SecurityContext context = SecurityContextHolder.createEmptyContext();
    if (authentication.isReuseForSso()) {
      context.setAuthentication(authentication);
      log.debug("Saving the authentication of '{}' for single sign-on [{}]", authentication.getName(),
          authentication.getLogString());
    }
    else {
      log.debug("The authentication of '{}' may not be reused - it is not saved for single sign-on [{}]",
          authentication.getName(), authentication.getLogString());
    }
    SecurityContextHolder.setContext(context);
    this.securityContextRepository.saveContext(context, request, response);
  }

  /**
   * Records that an authentication that has started ended in an error, by removing the authentication from the
   * session so that the next request cannot reuse it. The flow calls it for errors from the providers. A protocol
   * module calls it for errors raised while it completes the result, such as when the attributes are released.
   * <p>
   * Nothing is done for {@link AuthenticationError#NO_AUTHN_CONTEXT} and
   * {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}, which say nothing about the user.
   * </p>
   * <p>
   * Call it before the error response is written.
   * </p>
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param error the error
   */
  public void failAuthentication(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull AuthenticationErrorException error) {
    if (error.getError() == AuthenticationError.NO_AUTHN_CONTEXT
        || error.getError() == AuthenticationError.PASSIVE_NOT_POSSIBLE) {
      return;
    }
    if (this.getSessionAuthentication() != null) {
      log.debug("The authentication failed ({}) - removing the authentication from the session", error.getError());
    }
    final SecurityContext context = SecurityContextHolder.createEmptyContext();
    SecurityContextHolder.setContext(context);
    this.securityContextRepository.saveContext(context, request, response);
  }

  /**
   * Gets the authentication providers.
   *
   * @return the providers, in the order they are asked
   */
  public @NonNull List<UserAuthenticationProvider> getProviders() {
    return this.providers;
  }

  /**
   * Gets the providers that authenticate the user on pages of their own.
   *
   * @return the redirect providers
   */
  public @NonNull List<UserRedirectAuthenticationProvider> getRedirectProviders() {
    return this.providers.stream()
        .filter(UserRedirectAuthenticationProvider.class::isInstance)
        .map(UserRedirectAuthenticationProvider.class::cast)
        .toList();
  }

  /**
   * Assigns where the security context is saved. The default is a {@link HttpSessionSecurityContextRepository}.
   *
   * @param securityContextRepository the repository
   */
  public void setSecurityContextRepository(final @NonNull SecurityContextRepository securityContextRepository) {
    this.securityContextRepository =
        Objects.requireNonNull(securityContextRepository, "securityContextRepository must not be null");
  }

  /**
   * Assigns the strategy that sends the user to a redirect provider's authentication path. The default is a
   * {@link DefaultRedirectStrategy}, which puts the context path in front of the path.
   *
   * @param redirectStrategy the redirect strategy
   */
  public void setRedirectStrategy(final @NonNull RedirectStrategy redirectStrategy) {
    this.redirectStrategy = Objects.requireNonNull(redirectStrategy, "redirectStrategy must not be null");
  }

  /**
   * Gets the authentication in the session that may be reused.
   *
   * @return the authentication, or {@code null} if the session holds none
   */
  private @Nullable UserAuthentication getSessionAuthentication() {
    return SecurityContextHolder.getContext().getAuthentication() instanceof final UserAuthentication authentication
        ? authentication
        : null;
  }

  /**
   * Gives the result the requirements and the protocol data of the request being answered.
   *
   * @param authentication the result
   * @param token the processed request
   * @return the result
   */
  private static @NonNull UserAuthentication prepare(final @NonNull UserAuthentication authentication,
      final @NonNull UserAuthenticationInputToken token) {
    authentication.setAuthnRequirements(token.getAuthnRequirements());
    authentication.setProtocolRequestData(token.getProtocolRequestData());
    return authentication;
  }

}
