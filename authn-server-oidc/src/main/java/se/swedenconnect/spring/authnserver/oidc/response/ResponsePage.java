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
package se.swedenconnect.spring.authnserver.oidc.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

import org.jspecify.annotations.NonNull;

/**
 * Writes the page that posts a response to the client, for the {@code form_post} response mode.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface ResponsePage {

  /**
   * Writes the response page.
   *
   * @param httpServletRequest the HTTP request
   * @param httpServletResponse the HTTP response
   * @param destination the redirect URI that the response is posted to
   * @param parameters the response parameters
   * @throws IOException for errors writing the page
   */
  void sendResponse(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull Map<String, String> parameters) throws IOException;

}
