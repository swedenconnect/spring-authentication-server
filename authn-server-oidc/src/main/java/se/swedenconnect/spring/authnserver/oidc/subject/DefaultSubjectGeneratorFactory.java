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
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGeneratorFactory;

/**
 * A {@link SubjectGeneratorFactory} that supports the {@code public} and {@code pairwise} subject identifier types.
 * <p>
 * A client that has not registered a {@code subject_type} gets {@code public}, as the Swedish OpenID Connect Profile,
 * Section 6, says it should.
 * </p>
 *
 * @author Martin Lindström
 */
public class DefaultSubjectGeneratorFactory extends AbstractSubjectIdentifierGeneratorFactory
    implements SubjectGeneratorFactory {

  /**
   * Constructor.
   *
   * @param issuer the OpenID Provider issuer identifier
   */
  public DefaultSubjectGeneratorFactory(final @NonNull String issuer) {
    super(issuer);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull SubjectGenerator getSubjectGenerator(final @Nullable SubjectType subjectType,
      final @Nullable URI sectorIdentifierUri, final @Nullable Collection<URI> redirectUris)
      throws UnrecoverableErrorException {

    final SubjectType type = subjectType != null ? subjectType : SubjectType.PUBLIC;

    if (SubjectType.PUBLIC == type) {
      return this.configure(new PublicSubjectGenerator(this.getIssuerQualifier()));
    }
    if (SubjectType.PAIRWISE == type) {
      return this.configure(new PairwiseSubjectGenerator(this.getIssuerQualifier(),
          SectorIdentifiers.resolve(sectorIdentifierUri, redirectUris)));
    }
    throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
        "Unsupported subject_type registered for the client - " + type);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<SubjectType> getSupportedSubjectTypes() {
    return List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE);
  }

}
