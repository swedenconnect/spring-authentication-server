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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The side of the storage that the protocol flow uses. A protocol filter stores the authentication when the provider
 * asks for a redirect, and picks up the outcome when the user returns to the resume path.
 * <p>
 * The identifier of the authentication is read from the request, see
 * {@link RedirectForAuthenticationToken#getAuthnId(HttpServletRequest)}, so that several authentications may be in
 * progress in the same session at once.
 * </p>
 *
 * @author Martin Lindström
 * @see RedirectAuthenticatorRepository
 */
public interface RedirectFlowRepository {

  /**
   * Starts an authentication by storing the redirect token under its identifier.
   *
   * @param token the redirect token
   * @param request the HTTP servlet request
   */
  void start(@Nonnull final RedirectForAuthenticationToken token, @Nonnull final HttpServletRequest request);

  /**
   * Gets the protocol that the authentication a request concerns was started for. A filter uses it to tell whether the
   * request on the resume path belongs to its protocol.
   *
   * @param request the HTTP servlet request
   * @return the protocol, or {@code null} if the request carries no identifier or there is no such authentication
   */
  @Nullable
  AuthenticationProtocol getProtocol(@Nonnull final HttpServletRequest request);

  /**
   * Picks up the outcome of the authentication that a request on the resume path concerns, and removes it from the
   * storage so that it cannot be resumed twice.
   *
   * @param request the HTTP servlet request
   * @return the token that the flow resumes with
   * @throws UnrecoverableErrorException {@link CommonUnrecoverableError#INVALID_SESSION} if the request carries no
   *           identifier, or the authentication is unknown, has expired, has already been resumed, or has no outcome
   */
  @Nonnull
  ResumedAuthenticationToken resume(@Nonnull final HttpServletRequest request) throws UnrecoverableErrorException;

  /**
   * Removes the authentication that a request concerns, if there is one. It is how a flow that is given up is cleaned
   * away.
   *
   * @param request the HTTP servlet request
   */
  void clear(@Nonnull final HttpServletRequest request);

}
