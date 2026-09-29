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
package se.swedenconnect.spring.authnserver;

import java.time.Instant;
import java.util.List;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Fixtures for the tests of the user authentication.
 *
 * @author Martin Lindström
 */
@SuppressWarnings("HttpUrlsUsage")
public final class AuthenticationTestSupport {

  /** Level of assurance 2. */
  public static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  /** Level of assurance 3. */
  public static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  /** Level of assurance 4. */
  public static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  /** The personal identity number of the test user. */
  public static final String IDENTITY_NUMBER = "197705232382";

  /**
   * Creates a user authenticated at {@link #LOA3} just now.
   *
   * @return an {@link AuthenticatedUser}
   */
  public static AuthenticatedUser user() {
    return user(LOA3, Instant.now());
  }

  /**
   * Creates a user.
   *
   * @param authnContextUri the authentication context URI
   * @param authnInstant the authentication instant
   * @return an {@link AuthenticatedUser}
   */
  public static AuthenticatedUser user(final String authnContextUri, final Instant authnInstant) {
    return new AuthenticatedUser(
        List.of(
            GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, IDENTITY_NUMBER),
            GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Agda"),
            GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, authnContextUri, authnInstant, "192.168.1.14");
  }

  /**
   * Creates an authentication result for the supplied user, with one registered use for the supplied requester.
   *
   * @param user the user
   * @param requester the requester of the original authentication
   * @param requestedAttributes the attributes that requester asked for
   * @return a {@link UserAuthentication}
   */
  public static UserAuthentication authentication(final AuthenticatedUser user, final Requester requester,
      final List<String> requestedAttributes) {
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.registerUse(requester.protocol(), requester.identifier(), "_original", requestedAttributes);
    return authentication;
  }

  /**
   * Creates a SAML requester.
   *
   * @param entityId the entityID
   * @return a {@link Requester}
   */
  public static Requester samlRequester(final String entityId) {
    return new Requester(AuthenticationProtocol.SAML, entityId);
  }

  /**
   * Creates an OpenID Connect requester.
   *
   * @param clientId the client identifier
   * @return a {@link Requester}
   */
  public static Requester oidcRequester(final String clientId) {
    return new Requester(AuthenticationProtocol.OIDC, clientId);
  }

  // Hidden constructor
  private AuthenticationTestSupport() {
  }

}
