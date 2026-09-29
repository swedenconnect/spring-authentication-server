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

import java.io.ByteArrayOutputStream;
import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Base class for a {@link SubjectIdentifierGenerator} that computes a stable identifier from the user ID.
 * <p>
 * The user ID is the value of the user's primary attribute. It is combined with a qualifier for the issuer, and
 * optionally with a qualifier for the requester, and the result is hashed. The same user therefore gets the same
 * identifier for the same qualifiers every time, and the identifier does not reveal the user ID.
 * </p>
 * <p>
 * A server secret should be assigned with {@link #setSecret(byte[])}. Without a secret the identifier is a plain hash
 * of values that anyone may know, and since the number of possible Swedish personal identity numbers is small enough
 * to try them all, the identifier can be traced back to the person it was issued for. With a secret the identifier is
 * a MAC over the same data, and only the server can compute it. A warning is logged, once, when an identifier is
 * computed without a secret.
 * </p>
 * <p>
 * A generator holds the secret, and is kept in the user session. Keep that in mind when the session is stored outside
 * the server.
 * </p>
 *
 * @author Martin Lindström
 */
public abstract class AbstractSubjectIdentifierGenerator implements SubjectIdentifierGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The hash algorithm that is used unless another one is assigned, {@value}. */
  public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractSubjectIdentifierGenerator.class);

  /** Whether the warning about a missing server secret has been logged. */
  private static final AtomicBoolean missingSecretWarned = new AtomicBoolean(false);

  /** The qualifier for the issuer, normally the SAML entityID or the OpenID Connect issuer. */
  private final String issuerQualifier;

  /** The qualifier for the requester, or {@code null} if the identifier is not qualified by the requester. */
  private final String requesterQualifier;

  /** The JCE name of the hash algorithm to use. */
  private String hashAlgorithm = DEFAULT_HASH_ALGORITHM;

  /** The server secret, or {@code null} if no secret has been assigned. */
  private byte[] secret;

  /**
   * Constructor for an identifier that is qualified by the issuer only.
   *
   * @param issuerQualifier the qualifier for the issuer
   */
  protected AbstractSubjectIdentifierGenerator(final @Nonnull String issuerQualifier) {
    this(issuerQualifier, null);
  }

  /**
   * Constructor.
   *
   * @param issuerQualifier the qualifier for the issuer
   * @param requesterQualifier the qualifier for the requester, or {@code null} if the identifier is the same for all
   *     requesters
   */
  protected AbstractSubjectIdentifierGenerator(final @Nonnull String issuerQualifier,
      final @Nullable String requesterQualifier) {
    if (!StringUtils.hasText(issuerQualifier)) {
      throw new IllegalArgumentException("issuerQualifier must be set and not empty");
    }
    this.issuerQualifier = issuerQualifier;
    this.requesterQualifier = requesterQualifier;
  }

  /**
   * Computes the identifier from the user ID and the qualifiers.
   */
  @Override
  public @Nonnull String getSubjectIdentifier(final @Nonnull AuthenticatedUser user,
      final @Nonnull Requester requester) throws UnrecoverableErrorException {
    Objects.requireNonNull(user, "user must not be null");
    Objects.requireNonNull(requester, "requester must not be null");
    return this.computeIdentifier(this.getUserId(user));
  }

  /**
   * Computes a stable identifier from the supplied user ID, the qualifiers and the server secret.
   *
   * @param userId the user ID
   * @return the identifier
   * @throws UnrecoverableErrorException if the identifier can not be computed
   */
  protected final @Nonnull String computeIdentifier(final @Nonnull String userId)
      throws UnrecoverableErrorException {
    Objects.requireNonNull(userId, "userId must not be null");
    final byte[] input = this.getInput(userId);
    try {
      if (this.secret == null) {
        if (missingSecretWarned.compareAndSet(false, true)) {
          log.warn("No server secret has been assigned for subject identifier generation - the identifiers that are "
              + "generated can be traced back to the users they were issued for");
        }
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance(this.hashAlgorithm).digest(input));
      }
      final Mac mac = Mac.getInstance(macAlgorithm(this.hashAlgorithm));
      mac.init(new SecretKeySpec(this.secret, mac.getAlgorithm()));
      return Base64.getEncoder().encodeToString(mac.doFinal(input));
    }
    catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Failed to compute subject identifier - " + e.getMessage(), e);
    }
  }

  /**
   * Gets the ID of the supplied user, which is the value of the user's primary attribute.
   *
   * @param user the authenticated user
   * @return the user ID
   * @throws UnrecoverableErrorException if the user has no ID
   */
  protected @Nonnull String getUserId(final @Nonnull AuthenticatedUser user) throws UnrecoverableErrorException {
    final String userId = user.getUsername();
    if (!StringUtils.hasText(userId)) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Failed to compute subject identifier - the user has no ID");
    }
    return userId;
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
   * Gets the qualifier for the requester.
   *
   * @return the qualifier for the requester, or {@code null} if the identifier is the same for all requesters
   */
  protected @Nullable String getRequesterQualifier() {
    return this.requesterQualifier;
  }

  /**
   * Predicate telling whether a server secret has been assigned.
   *
   * @return {@code true} if a secret has been assigned and {@code false} otherwise
   */
  protected boolean hasSecret() {
    return this.secret != null;
  }

  /**
   * Assigns the JCE name of the hash algorithm to use. The default is {@value #DEFAULT_HASH_ALGORITHM}.
   * <p>
   * When a server secret has been assigned, the corresponding MAC algorithm is used, so {@code SHA-256} gives
   * {@code HmacSHA256}.
   * </p>
   *
   * @param hashAlgorithm the JCE name of the hash algorithm
   */
  public void setHashAlgorithm(final @Nonnull String hashAlgorithm) {
    if (!StringUtils.hasText(hashAlgorithm)) {
      throw new IllegalArgumentException("hashAlgorithm must be set and not empty");
    }
    this.hashAlgorithm = hashAlgorithm;
  }

  /**
   * Assigns the server secret that takes part in the computation of the identifier. Assigning a secret is strongly
   * recommended, see the class description.
   *
   * @param secret the secret, or {@code null} for no secret
   */
  public void setSecret(final @Nullable byte[] secret) {
    this.secret = secret != null ? secret.clone() : null;
  }

  /**
   * Gets the input to the hash or MAC computation. The requester qualifier, when present, comes first, then the issuer
   * qualifier, then the user ID, with the qualifiers separated from what follows by an exclamation mark.
   *
   * @param userId the user ID
   * @return the bytes to compute over
   */
  private byte[] getInput(final @Nonnull String userId) {
    final ByteArrayOutputStream input = new ByteArrayOutputStream();
    if (this.requesterQualifier != null) {
      input.writeBytes(this.requesterQualifier.getBytes(StandardCharsets.UTF_8));
      input.write('!');
    }
    input.writeBytes(this.issuerQualifier.getBytes(StandardCharsets.UTF_8));
    input.write('!');
    input.writeBytes(userId.getBytes(StandardCharsets.UTF_8));
    return input.toByteArray();
  }

  /**
   * Gets the JCE name of the MAC algorithm that corresponds to the supplied hash algorithm.
   *
   * @param hashAlgorithm the JCE name of the hash algorithm
   * @return the JCE name of the MAC algorithm
   */
  private static @Nonnull String macAlgorithm(final @Nonnull String hashAlgorithm) {
    return "Hmac" + hashAlgorithm.replace("-", "");
  }

}
