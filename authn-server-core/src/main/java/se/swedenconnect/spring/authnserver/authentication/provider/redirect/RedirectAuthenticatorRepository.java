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

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * The side of the storage that the module's controller uses. It reads what the authentication was asked to do, and
 * saves the outcome before it sends the user back to the resume path.
 * <p>
 * The identifier of the authentication is read from the request, see
 * {@link RedirectForAuthenticationToken#getAuthnId(HttpServletRequest)}, so a controller that spreads the
 * authentication over several pages must carry the identifier along.
 * </p>
 *
 * @author Martin Lindström
 * @see RedirectFlowRepository
 */
public interface RedirectAuthenticatorRepository {

  /**
   * Gets the redirect token of the authentication that a request concerns. It is the input for the authentication.
   *
   * @param request the HTTP servlet request
   * @return the redirect token, or {@code null} if the request carries no identifier or there is no such
   *           authentication
   */
  @Nullable
  RedirectForAuthenticationToken getInputToken(@Nonnull final HttpServletRequest request);

  /**
   * Saves the result of the authentication that a request concerns.
   *
   * @param result the result of the authentication
   * @param request the HTTP servlet request
   * @throws IllegalStateException if the request carries no identifier or there is no such authentication
   */
  void complete(@Nonnull final Authentication result, @Nonnull final HttpServletRequest request)
      throws IllegalStateException;

  /**
   * Saves the error of the authentication that a request concerns.
   *
   * @param error the error
   * @param request the HTTP servlet request
   * @throws IllegalStateException if the request carries no identifier or there is no such authentication
   */
  void complete(@Nonnull final AuthenticationErrorException error, @Nonnull final HttpServletRequest request)
      throws IllegalStateException;

}
