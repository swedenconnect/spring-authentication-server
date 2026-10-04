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
package se.swedenconnect.spring.authnserver.service.config;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Makes the error page the answer to every error that cannot be reported back to the requester. Spring Boot's error
 * controller answers a request that does not accept HTML with a JSON body, so for the error dispatch of such an error
 * the request is made to accept HTML only. Other errors are left as they are.
 *
 * @author Martin Lindström
 */
public class UnrecoverableErrorPageFilter implements Filter {

  /** {@inheritDoc} */
  @Override
  public void doFilter(final @NonNull ServletRequest request, final @NonNull ServletResponse response,
      final @NonNull FilterChain chain) throws IOException, ServletException {
    if (request instanceof final HttpServletRequest httpRequest
        && request.getDispatcherType() == DispatcherType.ERROR
        && UnrecoverableErrorViewResolver.findError(request.getAttribute(RequestDispatcher.ERROR_EXCEPTION)) != null) {
      chain.doFilter(new HtmlOnlyRequest(httpRequest), response);
      return;
    }
    chain.doFilter(request, response);
  }

  /**
   * A request that accepts HTML only.
   */
  private static final class HtmlOnlyRequest extends HttpServletRequestWrapper {

    /**
     * Constructor.
     *
     * @param request the request
     */
    HtmlOnlyRequest(final @NonNull HttpServletRequest request) {
      super(request);
    }

    /** {@inheritDoc} */
    @Override
    public @Nullable String getHeader(final @NonNull String name) {
      return HttpHeaders.ACCEPT.equalsIgnoreCase(name) ? MediaType.TEXT_HTML_VALUE : super.getHeader(name);
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull Enumeration<String> getHeaders(final @NonNull String name) {
      return HttpHeaders.ACCEPT.equalsIgnoreCase(name)
          ? Collections.enumeration(Collections.singletonList(MediaType.TEXT_HTML_VALUE))
          : super.getHeaders(name);
    }

  }

}
