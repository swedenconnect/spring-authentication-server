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

import jakarta.annotation.Nonnull;

import java.io.Serial;

import com.nimbusds.openid.connect.sdk.SubjectType;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGenerator;

/**
 * A {@link SubjectGenerator} for the {@code public} subject identifier type. All clients get the same {@code sub} for a
 * user.
 * <p>
 * The issuer is the only qualifier of the identifier. The value of a user attribute is never used as {@code sub}, see
 * the Swedish OpenID Connect Profile, Section 3.2.1.1.
 * </p>
 *
 * @author Martin Lindström
 */
public class PublicSubjectGenerator extends AbstractSubjectIdentifierGenerator implements SubjectGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param issuer the OpenID Provider issuer identifier
   */
  public PublicSubjectGenerator(final @Nonnull String issuer) {
    super(issuer);
  }

  /**
   * Returns {@link SubjectType#PUBLIC}.
   */
  @Override
  public @Nonnull SubjectType getSubjectType() {
    return SubjectType.PUBLIC;
  }

}
