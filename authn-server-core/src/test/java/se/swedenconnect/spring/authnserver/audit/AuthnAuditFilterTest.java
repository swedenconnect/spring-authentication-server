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
package se.swedenconnect.spring.authnserver.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import se.swedenconnect.spring.audit.tracing.CorrelationIDHolder;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUnrecoverableErrorEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.SessionBasedRedirectAuthenticationRepository;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Tests for {@link AuthnAuditFilter}.
 *
 * @author Martin Lindström
 */
class AuthnAuditFilterTest {

  private static final String AUTHN_PATH = "/authn/login";

  private final List<Object> events = new ArrayList<>();

  private final SessionBasedRedirectAuthenticationRepository repository =
      new SessionBasedRedirectAuthenticationRepository();

  private AuthnAuditFilter filter;

  @BeforeEach
  void setUp() {
    final UserRedirectAuthenticationProvider provider = mock(UserRedirectAuthenticationProvider.class);
    when(provider.getAuthnPath()).thenReturn(AUTHN_PATH);
    when(provider.getAuthenticatorRepository()).thenReturn(this.repository);
    this.filter = new AuthnAuditFilter(new AuthnEventPublisher(this.events::add), List.of(provider));
  }

  @AfterEach
  void clear() {
    CorrelationIDHolder.clear();
  }

  @Test
  void theCorrelationIdDoesNotLeakIntoTheNextRequest() throws Exception {
    // A leftover from earlier work on the thread is not used
    FlowCorrelation.join("leftover");
    final AtomicReference<String> during = new AtomicReference<>();
    this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain(
        servlet(request -> {
          during.set(FlowCorrelation.current());
          FlowCorrelation.startFlow();
        })));
    assertThat(during.get()).isNull();
    assertThat(CorrelationIDHolder.get()).isNull();
  }

  @Test
  void theCorrelationIdIsClearedWhenTheRequestFails() {
    assertThatThrownBy(() -> this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
        new MockFilterChain(servlet(request -> {
          FlowCorrelation.startFlow();
          throw new IllegalStateException("failure");
        })))).isInstanceOf(IllegalStateException.class);
    assertThat(CorrelationIDHolder.get()).isNull();
    assertThat(this.events).isEmpty();
  }

  @Test
  void anUnrecoverableErrorIsPublishedAndPassedOn() {
    final AtomicReference<String> correlationId = new AtomicReference<>();
    final UnrecoverableErrorException error =
        new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION, "No session");
    assertThatThrownBy(() -> this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
        new MockFilterChain(servlet(request -> {
          correlationId.set(FlowCorrelation.join("flow-1"));
          AuditRequestContext.get(request)
              .setRequester(AuditRequester.named(AuthenticationProtocol.SAML, "sp"))
              .setStage(AuditStage.USER_AUTHENTICATION);
          throw error;
        })))).isSameAs(error);

    assertThat(this.events).singleElement().isInstanceOfSatisfying(AuthnUnrecoverableErrorEvent.class, e -> {
      assertThat(e.getError()).isSameAs(error);
      assertThat(e.getStage()).isEqualTo(AuditStage.USER_AUTHENTICATION);
      assertThat(e.getRequester().getPrincipal()).isEqualTo("sp");
    });
    assertThat(CorrelationIDHolder.get()).isNull();
  }

  @Test
  void anUnrecoverableErrorWrappedInAServletExceptionIsPublished() {
    final UnrecoverableErrorException error = new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "x");
    assertThatThrownBy(() -> this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
        new MockFilterChain(servlet(request -> {
          throw new ServletException("wrapped", error);
        })))).isInstanceOf(ServletException.class);

    assertThat(this.events).singleElement().isInstanceOfSatisfying(AuthnUnrecoverableErrorEvent.class, e -> {
      assertThat(e.getError()).isSameAs(error);
      assertThat(e.getStage()).isNull();
      assertThat(e.getRequester().getPrincipal()).isEqualTo(AuditRequester.UNKNOWN_PRINCIPAL);
    });
  }

  @Test
  void aRequestOnTheAuthnPathOfAModuleJoinsTheFlow() throws Exception {
    final MockHttpSession session = new MockHttpSession();
    final UserAuthenticationInputToken inputToken = new UserAuthenticationInputToken(new AuthenticationRequirements(),
        new Requester(AuthenticationProtocol.SAML, "sp"));
    final AuditRequester requester = AuditRequester.named(AuthenticationProtocol.SAML, "sp").asVerified();
    inputToken.setAuditData(new AuditFlowData("flow-1", requester, null));
    final MockHttpServletRequest start = new MockHttpServletRequest();
    start.setSession(session);
    this.repository.start(
        new RedirectForAuthenticationToken("authn-1", inputToken, List.of(), AUTHN_PATH, "/authn/resume"), start);

    final AtomicReference<String> correlationId = new AtomicReference<>();
    final AtomicReference<AuditRequestContext> context = new AtomicReference<>();
    this.filter.doFilter(moduleRequest(session, AUTHN_PATH, "authn-1"), new MockHttpServletResponse(),
        new MockFilterChain(servlet(request -> {
          correlationId.set(FlowCorrelation.current());
          context.set(AuditRequestContext.get(request));
        })));

    assertThat(correlationId.get()).isEqualTo("flow-1");
    assertThat(context.get().getRequester()).isEqualTo(requester);
    assertThat(context.get().getStage()).isEqualTo(AuditStage.USER_AUTHENTICATION);
    assertThat(CorrelationIDHolder.get()).isNull();
  }

  @Test
  void aRequestThatDoesNotBelongToAFlowInProgressIsNotJoined() throws Exception {
    final AtomicReference<String> correlationId = new AtomicReference<>("not-called");
    final HttpServlet capture = servlet(request -> correlationId.set(FlowCorrelation.current()));

    this.filter.doFilter(moduleRequest(new MockHttpSession(), AUTHN_PATH, "unknown"), new MockHttpServletResponse(),
        new MockFilterChain(capture));
    assertThat(correlationId.get()).isNull();

    correlationId.set("not-called");
    this.filter.doFilter(moduleRequest(new MockHttpSession(), "/other", "authn-1"), new MockHttpServletResponse(),
        new MockFilterChain(capture));
    assertThat(correlationId.get()).isNull();

    correlationId.set("not-called");
    this.filter.doFilter(moduleRequest(new MockHttpSession(), AUTHN_PATH, null), new MockHttpServletResponse(),
        new MockFilterChain(capture));
    assertThat(correlationId.get()).isNull();
  }

  private static MockHttpServletRequest moduleRequest(final MockHttpSession session, final String path,
      final String authnId) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    request.setSession(session);
    if (authnId != null) {
      request.addParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, authnId);
    }
    return request;
  }

  private static HttpServlet servlet(final RequestHandler handler) {
    return new HttpServlet() {
      @Override
      protected void service(final HttpServletRequest request, final HttpServletResponse response)
          throws ServletException {
        handler.handle(request);
      }
    };
  }

  @FunctionalInterface
  private interface RequestHandler {
    void handle(HttpServletRequest request) throws ServletException;
  }

}
