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
package se.swedenconnect.spring.authnserver.saml.web;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestData;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.authnserver.saml.response.Saml2UserAuthenticationResponder;
import se.swedenconnect.spring.authnserver.web.ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * Continues the SAML flow when the user comes back from the pages of an authentication module.
 * <p>
 * The SAML data of the request that started the authentication tells where the response goes. A successful
 * authentication is answered with an assertion, and a failed one, or one that cannot be answered, with an error
 * response.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2ResumedAuthenticationHandler implements ResumedAuthenticationHandler {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2ResumedAuthenticationHandler.class);

  /** Turns the outcome into a result. */
  private final UserAuthenticationFlow flow;

  /** Answers the Service Provider. */
  private final Saml2UserAuthenticationResponder responder;

  /**
   * Constructor.
   *
   * @param flow turns the outcome into a result
   * @param responder answers the Service Provider
   */
  public Saml2ResumedAuthenticationHandler(final @Nonnull UserAuthenticationFlow flow,
      final @Nonnull Saml2UserAuthenticationResponder responder) {
    this.flow = Objects.requireNonNull(flow, "flow must not be null");
    this.responder = Objects.requireNonNull(responder, "responder must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.SAML;
  }

  /** {@inheritDoc} */
  @Override
  public void resume(final @Nonnull HttpServletRequest request, final @Nonnull HttpServletResponse response,
      final @Nonnull ResumedAuthenticationToken token) {

    final UserAuthenticationInputToken inputToken = token.getAuthnInputToken();
    final Saml2AuthnRequestData requestData = Saml2UserAuthenticationResponder.getRequestData(inputToken);
    final Saml2ResponseAttributes responseAttributes = requestData.responseAttributes();
    Saml2ResponseAttributes.setOnRequest(request, responseAttributes);

    SamlErrorStatusException error;
    try {
      final UserAuthentication authentication = this.flow.resume(token, request, response);
      this.responder.sendResponse(request, response, inputToken, authentication);
      return;
    }
    catch (final AuthenticationErrorException e) {
      error = SamlErrorStatusException.of(e);
    }
    catch (final SamlErrorStatusException e) {
      error = e;
    }
    log.debug("Answering a failed authentication: {} [{}]", error.getDescription(), inputToken.getLogString());
    this.responder.sendErrorResponse(request, response, responseAttributes, error);
  }

}
