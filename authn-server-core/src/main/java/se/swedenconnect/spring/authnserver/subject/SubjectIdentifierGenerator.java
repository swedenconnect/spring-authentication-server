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
package se.swedenconnect.spring.authnserver.subject;

import jakarta.annotation.Nonnull;

import java.io.Serializable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Generates the identifier of the user that a response carries: the {@code NameID} of a SAML assertion and the
 * {@code sub} claim of an OpenID Connect ID token.
 * <p>
 * A generator is created for one request, and is kept in the user session until the response has been sent. It
 * therefore survives Java serialization.
 * </p>
 * <p>
 * The protocol modules supply the generators that follow the requirements of SAML and OpenID Connect. An application
 * that wants something else, for example identifiers that are looked up in a database, implements this interface and
 * registers its own generator.
 * </p>
 *
 * @author Martin Lindström
 * @see AbstractSubjectIdentifierGenerator
 */
public interface SubjectIdentifierGenerator extends Serializable {

  /**
   * Generates the subject identifier for the supplied user and requester.
   *
   * @param user the authenticated user
   * @param requester the requester that the identifier is generated for
   * @return the subject identifier
   * @throws UnrecoverableErrorException if the identifier can not be generated
   */
  @Nonnull
  String getSubjectIdentifier(final @Nonnull AuthenticatedUser user, final @Nonnull Requester requester)
      throws UnrecoverableErrorException;

}
