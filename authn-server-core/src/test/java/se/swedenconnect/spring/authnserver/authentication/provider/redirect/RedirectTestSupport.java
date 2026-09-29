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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.LOA3;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.oidcRequester;
import static se.swedenconnect.spring.authnserver.AuthenticationTestSupport.samlRequester;

import java.util.List;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;

/**
 * Fixtures for the tests of the redirect authentication flow.
 *
 * @author Martin Lindström
 */
final class RedirectTestSupport {

  /** The path that the user is sent to for authentication. */
  static final String AUTHN_PATH = "/authn/login";

  /** The path that the user returns to. */
  static final String RESUME_PATH = "/authn/resume";

  /** A SAML requester. */
  static final Requester SP = samlRequester("https://sp.example.com/sp");

  /** An OpenID Connect requester. */
  static final Requester CLIENT = oidcRequester("the-client");

  /**
   * Creates what a provider is given.
   *
   * @param requester the requester
   * @return a {@link UserAuthenticationInputToken}
   */
  static UserAuthenticationInputToken inputToken(final Requester requester) {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setAuthnContextRequirements(List.of(LOA3));
    requirements.setRequestedAttributes(
        List.of(GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    return new UserAuthenticationInputToken(requirements, requester, "_1a2b3c", "the-request");
  }

  /**
   * Creates a redirect token.
   *
   * @param authnId the identifier of the authentication
   * @param requester the requester
   * @return a {@link RedirectForAuthenticationToken}
   */
  static RedirectForAuthenticationToken redirectToken(final String authnId, final Requester requester) {
    return new RedirectForAuthenticationToken(authnId, inputToken(requester), List.of(LOA3), AUTHN_PATH, RESUME_PATH);
  }

  /**
   * Creates a request in the supplied session, carrying the identifier of an authentication.
   *
   * @param session the session
   * @param authnId the identifier of the authentication, may be {@code null}
   * @return a {@link MockHttpServletRequest}
   */
  static MockHttpServletRequest request(final MockHttpSession session, final String authnId) {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    if (authnId != null) {
      request.setParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, authnId);
    }
    return request;
  }

  // Hidden constructor
  private RedirectTestSupport() {
  }

}
