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

import java.net.URI;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.openid.connect.sdk.SubjectType;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Creates the {@link SubjectGenerator} to use for a client.
 * <p>
 * The client registry is not built yet, so the registration data that decides the {@code sub} is given directly: the
 * {@code subject_type}, the {@code sector_identifier_uri} and the redirect URIs.
 * </p>
 *
 * @author Martin Lindström
 */
public interface SubjectGeneratorFactory {

  /**
   * Gets the generator to use for a client.
   *
   * @param subjectType the {@code subject_type} of the client, or {@code null} if it has not registered one, in which
   *     case {@code public} is used
   * @param sectorIdentifierUri the {@code sector_identifier_uri} of the client, or {@code null} if it has not
   *     registered one. Only used for the {@code pairwise} type
   * @param redirectUris the redirect URIs of the client. Only used for the {@code pairwise} type, and only when there
   *     is no {@code sector_identifier_uri}
   * @return a {@link SubjectGenerator}
   * @throws UnrecoverableErrorException if the client is registered in a way that leaves the {@code sub} undetermined
   */
  @NonNull SubjectGenerator getSubjectGenerator(final @Nullable SubjectType subjectType,
      final @Nullable URI sectorIdentifierUri, final @Nullable Collection<URI> redirectUris)
      throws UnrecoverableErrorException;

  /**
   * Gets the subject identifier types that the factory supports. They are declared as
   * {@code subject_types_supported} in the OpenID Provider metadata.
   *
   * @return the supported subject identifier types
   */
  @NonNull List<SubjectType> getSupportedSubjectTypes();

}
