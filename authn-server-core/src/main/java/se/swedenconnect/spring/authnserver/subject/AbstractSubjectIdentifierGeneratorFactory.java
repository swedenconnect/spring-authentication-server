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
import jakarta.annotation.Nullable;

import java.util.Objects;

import org.springframework.util.StringUtils;

/**
 * Base class for the protocol specific factories that create the generator to use for a request. It holds the settings
 * that the generators of both protocols share: the qualifier for the issuer, the server secret and the hash algorithm.
 *
 * @author Martin Lindström
 */
public abstract class AbstractSubjectIdentifierGeneratorFactory {

  /** The qualifier for the issuer, normally the SAML entityID or the OpenID Connect issuer. */
  private final String issuerQualifier;

  /** The server secret, or {@code null} if no secret has been assigned. */
  private byte[] secret;

  /** The JCE name of the hash algorithm to use. */
  private String hashAlgorithm = AbstractSubjectIdentifierGenerator.DEFAULT_HASH_ALGORITHM;

  /**
   * Constructor.
   *
   * @param issuerQualifier the qualifier for the issuer
   */
  protected AbstractSubjectIdentifierGeneratorFactory(final @Nonnull String issuerQualifier) {
    if (!StringUtils.hasText(issuerQualifier)) {
      throw new IllegalArgumentException("issuerQualifier must be set and not empty");
    }
    this.issuerQualifier = issuerQualifier;
  }

  /**
   * Gets the qualifier for the issuer.
   *
   * @return the qualifier for the issuer
   */
  protected @Nonnull String getIssuerQualifier() {
    return this.issuerQualifier;
  }

  /**
   * Applies the server secret and the hash algorithm to a newly created generator.
   *
   * @param <T> the type of the generator
   * @param generator the generator
   * @return the supplied generator
   */
  protected <T extends AbstractSubjectIdentifierGenerator> @Nonnull T configure(final @Nonnull T generator) {
    Objects.requireNonNull(generator, "generator must not be null");
    generator.setHashAlgorithm(this.hashAlgorithm);
    generator.setSecret(this.secret);
    return generator;
  }

  /**
   * Assigns the server secret that takes part in the computation of the identifiers. Assigning a secret is strongly
   * recommended, see {@link AbstractSubjectIdentifierGenerator}.
   *
   * @param secret the secret, or {@code null} for no secret
   */
  public void setSecret(final @Nullable byte[] secret) {
    this.secret = secret != null ? secret.clone() : null;
  }

  /**
   * Assigns the JCE name of the hash algorithm to use. The default is
   * {@link AbstractSubjectIdentifierGenerator#DEFAULT_HASH_ALGORITHM}.
   *
   * @param hashAlgorithm the JCE name of the hash algorithm
   */
  public void setHashAlgorithm(final @Nonnull String hashAlgorithm) {
    if (!StringUtils.hasText(hashAlgorithm)) {
      throw new IllegalArgumentException("hashAlgorithm must be set and not empty");
    }
    this.hashAlgorithm = hashAlgorithm;
  }

}
