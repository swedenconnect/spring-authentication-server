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
package se.swedenconnect.spring.authnserver.oidc.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ErrorObject;

import se.swedenconnect.spring.authnserver.audit.AuthnEventPublisher;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.oidc.audit.OidcAuditData;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorMapping;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorResponseException;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseSender;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;
import se.swedenconnect.spring.authnserver.oidc.response.OidcUserAuthenticationResponder;
import se.swedenconnect.spring.authnserver.web.ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * Continues the OpenID Connect flow when the user comes back from the pages of an authentication module.
 * <p>
 * The OpenID Connect data of the request that started the authentication tells where the response goes. A successful
 * authentication is answered with an authorization code, and a failed one, or one that cannot be answered, with an
 * error response.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcResumedAuthenticationHandler implements ResumedAuthenticationHandler {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcResumedAuthenticationHandler.class);

  /** Turns the outcome into a result. */
  private final UserAuthenticationFlow flow;

  /** Answers the client. */
  private final OidcUserAuthenticationResponder responder;

  /** Sends error responses. */
  private final OidcResponseSender responseSender;

  /** Publishes the audit events. */
  private AuthnEventPublisher eventPublisher = AuthnEventPublisher.noop();

  /**
   * Constructor.
   *
   * @param flow turns the outcome into a result
   * @param responder answers the client
   * @param responseSender sends error responses
   */
  public OidcResumedAuthenticationHandler(final @NonNull UserAuthenticationFlow flow,
      final @NonNull OidcUserAuthenticationResponder responder, final @NonNull OidcResponseSender responseSender) {
    this.flow = Objects.requireNonNull(flow, "flow must not be null");
    this.responder = Objects.requireNonNull(responder, "responder must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /** {@inheritDoc} */
  @Override
  public void resume(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull ResumedAuthenticationToken token) throws IOException {

    final UserAuthenticationInputToken inputToken = token.getAuthnInputToken();
    final OidcResponseTarget target = OidcUserAuthenticationResponder.getRequestData(inputToken).responseTarget();
    OidcResponseTarget.setOnRequest(request, target);

    final ErrorObject error;
    try {
      final UserAuthentication authentication = this.flow.resume(token, request, response);
      this.responder.sendResponse(request, response, inputToken, authentication);
      return;
    }
    catch (final AuthenticationErrorException e) {
      error = OidcErrorMapping.of(e);
    }
    catch (final OidcErrorResponseException e) {
      error = e.toErrorObject();
    }
    log.debug("Answering a failed authentication: {} [{}]", error.getDescription(), inputToken.getLogString());
    this.eventPublisher.publishErrorResponse(request, OidcAuditData.authorizationErrorResponse(target),
        error.getCode(), error.getDescription());
    this.responseSender.sendError(request, response, target, error);
  }

  /**
   * Assigns the publisher of the audit events. The default publishes nothing.
   *
   * @param eventPublisher the event publisher
   */
  public void setEventPublisher(final @NonNull AuthnEventPublisher eventPublisher) {
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
  }

}
