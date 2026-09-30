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

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestData;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * Answers the Service Provider once the user has been authenticated, or the authentication has failed.
 * <p>
 * A success is answered with a response holding the assertion. The authentication is kept in the session for single
 * sign-on before the response is sent, and only once the response has been built, so that an authentication that
 * could not be answered is never saved. An error raised while the assertion is built, such as when the attributes are
 * released, removes the authentication from the session, as any failed authentication does.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationResponder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2UserAuthenticationResponder.class);

  /** Builds the assertion. */
  private final Saml2AssertionBuilder assertionBuilder;

  /** Builds the response. */
  private final Saml2ResponseBuilder responseBuilder;

  /** Sends the response. */
  private final Saml2ResponseSender responseSender;

  /** Keeps the authentication in the session. */
  private final UserAuthenticationFlow flow;

  /**
   * Constructor.
   *
   * @param assertionBuilder builds the assertion
   * @param responseBuilder builds the response
   * @param responseSender sends the response
   * @param flow keeps the authentication in the session
   */
  public Saml2UserAuthenticationResponder(final @NonNull Saml2AssertionBuilder assertionBuilder,
      final @NonNull Saml2ResponseBuilder responseBuilder, final @NonNull Saml2ResponseSender responseSender,
      final @NonNull UserAuthenticationFlow flow) {
    this.assertionBuilder = Objects.requireNonNull(assertionBuilder, "assertionBuilder must not be null");
    this.responseBuilder = Objects.requireNonNull(responseBuilder, "responseBuilder must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
    this.flow = Objects.requireNonNull(flow, "flow must not be null");
  }

  /**
   * Builds the assertion and the response, keeps the authentication for single sign-on, and posts the response to the
   * Service Provider.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param token the request being answered
   * @param authentication the authentication
   * @throws AuthenticationErrorException if the attribute release fails in a way that is reported to the Service
   *     Provider, in which case the session authentication has been removed
   * @throws UnrecoverableErrorException if the response cannot be built or sent
   */
  public void sendResponse(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull UserAuthenticationInputToken token, final @NonNull UserAuthentication authentication)
      throws AuthenticationErrorException, UnrecoverableErrorException {

    final Saml2AuthnRequestData requestData = getRequestData(token);
    final Assertion assertion;
    try {
      assertion = this.assertionBuilder.buildAssertion(authentication, requestData, token.getRequester());
    }
    catch (final AuthenticationErrorException e) {
      this.flow.failAuthentication(request, response, e);
      throw e;
    }
    final Saml2ResponseAttributes responseAttributes = requestData.responseAttributes();
    final Response samlResponse = this.responseBuilder.buildResponse(responseAttributes, assertion);

    this.flow.saveAuthentication(authentication, request, response);

    log.debug("Sending response to '{}' for '{}' [{}]", responseAttributes.destination(), authentication.getName(),
        token.getLogString());
    this.responseSender.send(request, response, responseAttributes.destination(), samlResponse,
        responseAttributes.relayState());
  }

  /**
   * Posts an error response to the Service Provider.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param responseAttributes where and how the response is sent
   * @param error the error
   * @throws UnrecoverableErrorException if the response cannot be built or sent
   */
  public void sendErrorResponse(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull Saml2ResponseAttributes responseAttributes, final @NonNull SamlErrorStatusException error)
      throws UnrecoverableErrorException {

    final Response samlResponse = this.responseBuilder.buildErrorResponse(responseAttributes, error);
    log.debug("Sending error response {}/{} to '{}' [entity-id: '{}', authn-request: '{}']",
        error.getStatus().statusCode(), error.getStatus().subStatusCode(), responseAttributes.destination(),
        responseAttributes.getEntityId(), responseAttributes.inResponseTo());
    this.responseSender.send(request, response, responseAttributes.destination(), samlResponse,
        responseAttributes.relayState());
  }

  /**
   * Gets the SAML data of the request being answered.
   *
   * @param token the request
   * @return the SAML request data
   * @throws UnrecoverableErrorException if the request carries no SAML data
   */
  public static @NonNull Saml2AuthnRequestData getRequestData(final @NonNull UserAuthenticationInputToken token)
      throws UnrecoverableErrorException {
    if (token.getProtocolRequestData() instanceof final Saml2AuthnRequestData data) {
      return data;
    }
    throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
        "No SAML request data available for " + token.getLogString());
  }

}
