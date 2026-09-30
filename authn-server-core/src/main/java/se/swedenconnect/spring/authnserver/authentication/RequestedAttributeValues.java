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
package se.swedenconnect.spring.authnserver.authentication;

import java.util.Collections;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Compares the attribute values that a requester asked for with the authenticated user.
 * <p>
 * A requester may ask for an attribute with specific values, for example an OpenID Connect {@code claims} entry with
 * {@code value} or {@code values}, or a SAML {@code RequestedAttribute} with values or a {@code PrincipalSelection}.
 * A requested attribute matches when any of its requested values equals any of the user's values for the attribute.
 * </p>
 * <p>
 * After a new authentication, see {@link #check(AuthenticationRequirements, AuthenticatedUser, String)}:
 * </p>
 * <ul>
 * <li>Essential values that do not match fail the request with {@link AuthenticationError#UNKNOWN_PRINCIPAL}.</li>
 * <li>Voluntary values that do not match are logged, and the request proceeds.</li>
 * <li>An attribute that the user does not have is logged, and the request proceeds, whether the values are essential
 * or not.</li>
 * </ul>
 * <p>
 * Whether the values are essential is given by {@link GenericRequestedAttribute#isRequestedValuesEssential()}. The logs
 * name the attribute, never the values.
 * </p>
 *
 * @author Martin Lindström
 */
public final class RequestedAttributeValues {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RequestedAttributeValues.class);

  /**
   * Checks the requested attribute values against a user that has just been authenticated.
   *
   * @param requirements what the requester asks for
   * @param user the authenticated user
   * @param logString the log string of the request
   * @throws AuthenticationErrorException with {@link AuthenticationError#UNKNOWN_PRINCIPAL} if essential values do
   *     not match the user
   */
  public static void check(final @NonNull AuthenticationRequirements requirements,
      final @NonNull AuthenticatedUser user, final @NonNull String logString) throws AuthenticationErrorException {

    for (final GenericRequestedAttribute requested : requirements.getRequestedAttributes()) {
      if (requested.getRequestedValues().isEmpty()) {
        continue;
      }
      final GenericAttribute<?> attribute = user.getAttribute(requested.getIdentifier());
      if (attribute == null) {
        log.info("Values were requested for attribute '{}', but the authenticated user does not have it [{}]",
            requested.getIdentifier(), logString);
        continue;
      }
      if (!Collections.disjoint(attribute.getValues(), requested.getRequestedValues())) {
        continue;
      }
      if (requested.isRequestedValuesEssential()) {
        log.info("The authenticated user does not match the essential requested values of attribute '{}' [{}]",
            requested.getIdentifier(), logString);
        throw new AuthenticationErrorException(AuthenticationError.UNKNOWN_PRINCIPAL,
            "The authenticated user does not match the requested values of attribute '%s'"
                .formatted(requested.getIdentifier()));
      }
      log.info("The authenticated user does not match the voluntary requested values of attribute '{}' - "
          + "proceeding [{}]", requested.getIdentifier(), logString);
    }
  }

  /**
   * Tells whether a previous authentication contradicts the requested attribute values, which means that it may not be
   * reused for single sign-on. An attribute the user does not have says nothing, so it is not a contradiction.
   * Essential and voluntary values are treated alike.
   *
   * @param requirements what the requester asks for
   * @param user the previously authenticated user
   * @return {@code true} if a requested attribute has values of which none matches the user
   */
  public static boolean contradicts(final @NonNull AuthenticationRequirements requirements,
      final @NonNull AuthenticatedUser user) {
    for (final GenericRequestedAttribute requested : requirements.getRequestedAttributes()) {
      if (requested.getRequestedValues().isEmpty()) {
        continue;
      }
      final GenericAttribute<?> attribute = user.getAttribute(requested.getIdentifier());
      if (attribute != null && Collections.disjoint(attribute.getValues(), requested.getRequestedValues())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Hidden constructor.
   */
  private RequestedAttributeValues() {
  }

}
