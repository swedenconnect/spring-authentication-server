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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.ModelAndView;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Base class for the {@link Controller} that authenticates the user on the module's own pages.
 * <p>
 * The controller works on one authentication, the one the request carries the identifier of. A controller that spreads
 * the authentication over several pages must carry that identifier along, see
 * {@link RedirectForAuthenticationToken#AUTHN_ID_PARAMETER}, so that every request lands on the right authentication.
 * </p>
 * <p>
 * The controller never needs to know which protocol started the authentication. Completing, in any of the three ways,
 * sends the user back to the resume path, and the flow of the protocol that started it continues there.
 * </p>
 *
 * @param <T> the type of the provider
 * @author Martin Lindström
 */
public abstract class AbstractAuthenticationController<T extends UserRedirectAuthenticationProvider> {

  /**
   * Gets what the authentication was asked to do.
   *
   * @param request the HTTP servlet request
   * @return the redirect token of the authentication
   * @throws UnrecoverableErrorException {@link CommonUnrecoverableError#INVALID_SESSION} if the request does not
   *           belong to an authentication in progress
   */
  protected @NonNull RedirectForAuthenticationToken getInputToken(final @NonNull HttpServletRequest request)
      throws UnrecoverableErrorException {
    final RedirectForAuthenticationToken token =
        this.getProvider().getAuthenticatorRepository().getInputToken(request);
    if (token == null) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION,
          "No authentication in progress for the request");
    }
    return token;
  }

  /**
   * Saves the result of the authentication and sends the user back to the resume path.
   *
   * @param request the HTTP servlet request
   * @param authentication the result of the authentication
   * @return a redirect to the resume path
   * @throws UnrecoverableErrorException {@link CommonUnrecoverableError#INVALID_SESSION} if the request does not
   *           belong to an authentication in progress
   */
  protected @NonNull ModelAndView complete(final @NonNull HttpServletRequest request,
      final @NonNull Authentication authentication) throws UnrecoverableErrorException {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final RedirectForAuthenticationToken token = this.getInputToken(request);
    this.getProvider().getAuthenticatorRepository().complete(authentication, request);
    return resumeView(token);
  }

  /**
   * Saves the error of the authentication and sends the user back to the resume path, where it becomes the error that
   * the requester is given.
   *
   * @param request the HTTP servlet request
   * @param error the error
   * @return a redirect to the resume path
   * @throws UnrecoverableErrorException {@link CommonUnrecoverableError#INVALID_SESSION} if the request does not
   *           belong to an authentication in progress
   */
  protected @NonNull ModelAndView complete(final @NonNull HttpServletRequest request,
      final @NonNull AuthenticationErrorException error) throws UnrecoverableErrorException {
    Objects.requireNonNull(error, "error must not be null");
    final RedirectForAuthenticationToken token = this.getInputToken(request);
    this.getProvider().getAuthenticatorRepository().complete(error, request);
    return resumeView(token);
  }

  /**
   * Reports that the user chose to stop, which is {@link AuthenticationError#CANCEL}, and sends the user back to the
   * resume path.
   *
   * @param request the HTTP servlet request
   * @return a redirect to the resume path
   * @throws UnrecoverableErrorException {@link CommonUnrecoverableError#INVALID_SESSION} if the request does not
   *           belong to an authentication in progress
   */
  protected @NonNull ModelAndView cancel(final @NonNull HttpServletRequest request)
      throws UnrecoverableErrorException {
    return this.complete(request, new AuthenticationErrorException(AuthenticationError.CANCEL));
  }

  /**
   * Gets the provider that this controller authenticates for.
   *
   * @return the provider
   */
  protected abstract @NonNull T getProvider();

  /**
   * Builds the redirect back to the resume path, with the identifier of the authentication.
   *
   * @param token the redirect token of the authentication
   * @return a {@link ModelAndView}
   */
  private static @NonNull ModelAndView resumeView(final @NonNull RedirectForAuthenticationToken token) {
    return new ModelAndView("redirect:" + token.getResumeRedirectPath());
  }

}
