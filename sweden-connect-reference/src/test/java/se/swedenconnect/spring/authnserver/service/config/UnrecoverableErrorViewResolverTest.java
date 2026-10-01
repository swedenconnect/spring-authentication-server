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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link UnrecoverableErrorViewResolver}.
 *
 * @author Martin Lindström
 */
class UnrecoverableErrorViewResolverTest {

  private final UnrecoverableErrorViewResolver resolver = new UnrecoverableErrorViewResolver();

  @Test
  void anUnrecoverableErrorGetsTheErrorPage() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, new ServletException("wrapped",
        new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION, "no session")));

    final ModelAndView view = this.resolver.resolveErrorView(request, HttpStatus.INTERNAL_SERVER_ERROR,
        Map.of("status", 500));
    assertThat(view).isNotNull();
    assertThat(view.getViewName()).isEqualTo(UnrecoverableErrorViewResolver.VIEW_NAME);
    assertThat(view.getModel())
        .containsEntry("idpErrorMessageCode", CommonUnrecoverableError.INVALID_SESSION.getMessageCode())
        .containsEntry("idpErrorDescription", CommonUnrecoverableError.INVALID_SESSION.getDescription())
        .containsEntry("status", 500);
  }

  @Test
  void otherErrorsAreLeftToTheDefaultErrorPage() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(this.resolver.resolveErrorView(request, HttpStatus.NOT_FOUND, Map.of())).isNull();
    request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("other"));
    assertThat(this.resolver.resolveErrorView(request, HttpStatus.INTERNAL_SERVER_ERROR, Map.of())).isNull();
  }

}
