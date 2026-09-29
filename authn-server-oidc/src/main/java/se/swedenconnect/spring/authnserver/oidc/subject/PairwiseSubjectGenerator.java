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
import java.util.Objects;

import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.id.SectorID;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGenerator;

/**
 * A {@link SubjectGenerator} for the {@code pairwise} subject identifier type. Clients that share a sector identifier
 * get the same {@code sub} for a user, and clients in different sectors get different ones.
 * <p>
 * The sector identifier and the issuer are the qualifiers of the identifier. See OpenID Connect Core, Section 8.1, for
 * the requirements on the computation.
 * </p>
 *
 * @author Martin Lindström
 */
public class PairwiseSubjectGenerator extends AbstractSubjectIdentifierGenerator implements SubjectGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The sector identifier. */
  private final SectorID sectorId;

  /**
   * Constructor.
   *
   * @param issuer the OpenID Provider issuer identifier
   * @param sectorId the sector identifier of the client
   */
  public PairwiseSubjectGenerator(final @Nonnull String issuer, final @Nonnull SectorID sectorId) {
    super(issuer, Objects.requireNonNull(sectorId, "sectorId must not be null").getValue());
    this.sectorId = sectorId;
  }

  /**
   * Gets the sector identifier that the {@code sub} is qualified by.
   *
   * @return the sector identifier
   */
  public @Nonnull SectorID getSectorId() {
    return this.sectorId;
  }

  /**
   * Returns {@link SubjectType#PAIRWISE}.
   */
  @Override
  public @Nonnull SubjectType getSubjectType() {
    return SubjectType.PAIRWISE;
  }

}
