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
package se.swedenconnect.spring.authnserver.oidc.subject;

import org.jspecify.annotations.NonNull;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.subject.SubjectIdentifierGenerator;

/**
 * Generates the {@code sub} claim of an OpenID Connect ID token.
 * <p>
 * A generator is created by a {@link SubjectGeneratorFactory} from the registration of the client that the tokens are
 * issued for.
 * </p>
 *
 * @author Martin Lindström
 */
public interface SubjectGenerator extends SubjectIdentifierGenerator {

  /**
   * Generates the {@code sub} claim for the supplied user and requester.
   *
   * @param user the authenticated user
   * @param requester the client that the tokens are issued for
   * @return a {@link Subject}
   * @throws UnrecoverableErrorException if the {@code sub} claim can not be generated
   */
  default @NonNull Subject getSubject(final @NonNull AuthenticatedUser user, final @NonNull Requester requester)
      throws UnrecoverableErrorException {
    return new Subject(this.getSubjectIdentifier(user, requester));
  }

  /**
   * Gets the subject identifier type that this generator implements.
   *
   * @return a {@link SubjectType}
   */
  @NonNull SubjectType getSubjectType();

}
