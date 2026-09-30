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
package se.swedenconnect.spring.authnserver.saml.nameid;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.subject.SubjectIdentifierGenerator;

/**
 * Generates the {@code NameID} of a SAML assertion.
 * <p>
 * A generator is created by a {@link NameIDGeneratorFactory} when an authentication request is processed, and is used
 * when the assertion is built.
 * </p>
 *
 * @author Martin Lindström
 */
public interface NameIDGenerator extends SubjectIdentifierGenerator {

  /**
   * Generates the {@code NameID} for the supplied user and requester.
   *
   * @param user the authenticated user
   * @param requester the Service Provider that the assertion is issued for
   * @return a {@link NameID}
   * @throws UnrecoverableErrorException if the {@code NameID} can not be generated
   */
  @NonNull NameID getNameID(final @NonNull AuthenticatedUser user, final @NonNull Requester requester)
      throws UnrecoverableErrorException;

  /**
   * Gets the {@code Format} of the {@code NameID}s that this generator produces.
   *
   * @return the format URI
   */
  @NonNull String getFormat();

}
