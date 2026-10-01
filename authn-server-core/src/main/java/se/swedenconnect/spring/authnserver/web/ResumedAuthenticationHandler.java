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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;

/**
 * Continues the flow of one protocol when the user comes back from a module's own pages.
 * <p>
 * The resume paths are handled once for the whole server, by {@link UserAuthenticationResumeFilter}. It finds the
 * authentication in progress, and hands it to the handler of the protocol that the requester used. The handler turns
 * the outcome into a result with
 * {@link UserAuthenticationFlow#resume(ResumedAuthenticationToken, HttpServletRequest, HttpServletResponse)}, and
 * answers the requester, also when the authentication failed.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ResumedAuthenticationHandler {

  /**
   * Gets the protocol that this handler continues.
   *
   * @return the protocol
   */
  @NonNull AuthenticationProtocol getProtocol();

  /**
   * Continues the flow and answers the requester.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param token the resumed authentication, carrying the request that started it and the outcome
   * @throws IOException for errors writing the response
   * @throws ServletException for other errors
   */
  void resume(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull ResumedAuthenticationToken token) throws IOException, ServletException;

}
