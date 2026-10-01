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

import java.util.HashMap;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.webmvc.autoconfigure.error.ErrorViewResolver;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Shows the error page for errors that cannot be reported back to the requester, such as an unknown requester or an
 * expired session. The page shows the message of the error in the language of the page. Other errors are left to the
 * default error page.
 *
 * @author Martin Lindström
 */
public class UnrecoverableErrorViewResolver implements ErrorViewResolver {

  /** The name of the view. */
  public static final String VIEW_NAME = "error/idp";

  /** {@inheritDoc} */
  @Override
  public @Nullable ModelAndView resolveErrorView(final @NonNull HttpServletRequest request,
      final @NonNull HttpStatus status, final @NonNull Map<String, Object> model) {
    final UnrecoverableErrorException error = findError(request.getAttribute(RequestDispatcher.ERROR_EXCEPTION));
    if (error == null) {
      return null;
    }
    final Map<String, Object> errorModel = new HashMap<>(model);
    errorModel.put("idpErrorMessageCode", error.getMessageCode());
    errorModel.put("idpErrorDescription", error.getError().getDescription());
    return new ModelAndView(VIEW_NAME, errorModel, status);
  }

  /**
   * Finds an {@link UnrecoverableErrorException} among an exception and its causes.
   *
   * @param exception the exception, may be {@code null}
   * @return the error, or {@code null} if there is none
   */
  private static @Nullable UnrecoverableErrorException findError(final @Nullable Object exception) {
    Throwable t = exception instanceof final Throwable throwable ? throwable : null;
    while (t != null) {
      if (t instanceof final UnrecoverableErrorException error) {
        return error;
      }
      t = t.getCause();
    }
    return null;
  }

}
