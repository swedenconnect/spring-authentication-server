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
package se.swedenconnect.spring.authnserver.saml.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Writes the page that posts a SAML response to the Service Provider (the HTTP POST binding).
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
   * @param destination the URL that the response is posted to
   * @param samlResponse the Base64 encoded SAML response
   * @param relayState the relay state, or {@code null}
   * @throws IOException for errors writing the page
   */
  void sendResponse(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull String samlResponse, final @Nullable String relayState) throws IOException;

}
