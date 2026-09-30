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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationJwtVerifier;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationClient;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpTrustMarkRequester;

/**
 * The OpenID Provider's own trust marks, that it publishes in its entity configuration.
 * <p>
 * Each trust mark is fetched from the trust mark endpoint of its issuer, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.6">OpenID Federation 1.0, Section 8.6</a>,
 * when the job starts and again when three quarters of its lifetime have passed. A trust mark without {@code exp} is
 * kept as it is and never fetched again.
 * </p>
 * <p>
 * A fetched trust mark is checked before it is published: its signature against the configured keys of the issuer,
 * its {@code typ}, that {@code iss} is the issuer, that {@code sub} is the entity identifier of the OpenID Provider,
 * that {@code trust_mark_type} is the configured type, and that it has not expired. The trust chain of the issuer is
 * not validated.
 * </p>
 * <p>
 * A failed fetch or check never stops the OpenID Provider. It is logged as an error and recorded, see
 * {@link #getStates()}, and a new attempt is made after the retry interval. Meanwhile the current trust mark, if any,
 * is published until it expires.
 * </p>
 * <p>
 * When a cache directory is given, every accepted trust mark is written there, and the trust marks found there are
 * read when the job starts. A stored trust mark that has expired, or does not pass the check, is not used.
 * </p>
 *
 * @author Martin Lindström
 */
public class ProviderTrustMarks implements Runnable, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ProviderTrustMarks.class);

  /** The default interval between two attempts after a failure: five minutes. */
  public static final Duration DEFAULT_RETRY_INTERVAL = Duration.ofMinutes(5);

  /** How often the job looks for trust marks that are due. */
  static final Duration TICK = Duration.ofMinutes(1);

  /** The part of the lifetime of a trust mark that passes before it is fetched again. */
  static final double RENEWAL_FACTOR = 0.75;

  /** The entity identifier of the OpenID Provider. */
  private final String entityId;

  /** The state per trust mark type, in the configured order. */
  private final Map<String, Slot> slots = new LinkedHashMap<>();

  /** The client making the calls. */
  private final FederationClient federationClient;

  /** The directory where trust marks are stored, or {@code null}. */
  private final Path cacheDirectory;

  /** The interval between two attempts after a failure. */
  private final Duration retryInterval;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** Whether the stored trust marks have been read. */
  private boolean loaded = false;

  /** Where the job runs, or {@code null} until it has been started. */
  private ScheduledExecutorService executor;

  /**
   * Constructor using an {@link HttpFederationClient}, no cache directory and the default retry interval.
   *
   * @param entityId the entity identifier of the OpenID Provider
   * @param sources where each trust mark is fetched
   */
  public ProviderTrustMarks(final @NonNull String entityId, final @NonNull List<TrustMarkSource> sources) {
    this(entityId, sources, new HttpFederationClient(), null, DEFAULT_RETRY_INTERVAL, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param entityId the entity identifier of the OpenID Provider
   * @param sources where each trust mark is fetched
   * @param federationClient the client making the calls
   * @param cacheDirectory the directory where trust marks are stored, or {@code null} for no storage
   * @param retryInterval the interval between two attempts after a failure
   * @param clock the clock to use
   */
  public ProviderTrustMarks(final @NonNull String entityId, final @NonNull List<TrustMarkSource> sources,
      final @NonNull FederationClient federationClient, final @Nullable Path cacheDirectory,
      final @NonNull Duration retryInterval, final @NonNull Clock clock) {
    this.entityId = Objects.requireNonNull(entityId, "entityId must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.cacheDirectory = cacheDirectory;
    this.retryInterval = Objects.requireNonNull(retryInterval, "retryInterval must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    if (retryInterval.isZero() || retryInterval.isNegative()) {
      throw new IllegalArgumentException("retryInterval must be a positive duration");
    }
    for (final TrustMarkSource source : Objects.requireNonNull(sources, "sources must not be null")) {
      if (this.slots.put(source.trustMarkType(), new Slot(source)) != null) {
        throw new IllegalArgumentException(
            "The trust mark type '%s' is configured more than once".formatted(source.trustMarkType()));
      }
    }
  }

  /**
   * Gets the entity identifier of the OpenID Provider, the subject of its trust marks.
   *
   * @return the entity identifier
   */
  public @NonNull String getEntityId() {
    return this.entityId;
  }

  /**
   * Reads the stored trust marks, and starts the job, which fetches the trust marks at once and then keeps them up to
   * date. Calling it again does nothing.
   */
  public synchronized void start() {
    this.loadStored();
    if (this.executor != null || this.slots.isEmpty()) {
      return;
    }
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread thread = new Thread(r, "provider-trust-marks");
      thread.setDaemon(true);
      return thread;
    });
    this.executor.scheduleWithFixedDelay(this, 0, TICK.toMillis(), TimeUnit.MILLISECONDS);
    log.info("The trust marks {} of '{}' are kept up to date", this.slots.keySet(), this.entityId);
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    try {
      this.refresh();
    }
    catch (final RuntimeException e) {
      log.error("The trust mark job failed", e);
    }
  }

  /**
   * Reads the trust marks stored in the cache directory, unless it has been done already. A stored trust mark is only
   * used when it passes the check and has not expired.
   */
  public synchronized void loadStored() {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    if (this.cacheDirectory == null) {
      return;
    }
    final Instant now = this.clock.instant();
    for (final Slot slot : this.slots.values()) {
      final Path file = this.fileFor(slot.source.trustMarkType());
      if (!Files.isRegularFile(file)) {
        continue;
      }
      try {
        final String stored = Files.readString(file, StandardCharsets.UTF_8).trim();
        final JWTClaimsSet claims = this.check(SignedJWT.parse(stored), slot.source);
        slot.accept(stored, claims, now, now);
        log.info("Using the stored trust mark '{}', valid until {}", slot.source.trustMarkType(),
            slot.expiresAt != null ? slot.expiresAt : "further notice");
      }
      catch (final IOException | ParseException | RuntimeException e) {
        log.info("The stored trust mark '{}' in {} is not used: {}", slot.source.trustMarkType(), file,
            e.getMessage());
      }
    }
  }

  /**
   * Fetches every trust mark that is due: one that is missing or has expired, when the retry interval has passed since
   * the latest failure, and one that has passed three quarters of its lifetime.
   *
   * @return the number of trust marks that were fetched and accepted
   */
  public int refresh() {
    final List<Slot> due = new ArrayList<>();
    synchronized (this) {
      final Instant now = this.clock.instant();
      this.slots.values().stream().filter(s -> s.isDue(now)).forEach(due::add);
    }
    int accepted = 0;
    for (final Slot slot : due) {
      if (this.fetch(slot)) {
        accepted++;
      }
    }
    return accepted;
  }

  /**
   * Gets the trust marks to publish: the valid ones, in the configured order.
   *
   * @return the trust marks
   */
  public synchronized @NonNull List<TrustMarkEntry> getTrustMarks() {
    final Instant now = this.clock.instant();
    return this.slots.values().stream()
        .filter(s -> s.isValid(now))
        .map(s -> new TrustMarkEntry(s.source.trustMarkType(), Objects.requireNonNull(s.trustMark)))
        .toList();
  }

  /**
   * Gets the state of each trust mark type, in the configured order. It is what a health check reads.
   *
   * @return the states
   */
  public synchronized @NonNull List<TrustMarkState> getStates() {
    final Instant now = this.clock.instant();
    return this.slots.values().stream()
        .map(s -> new TrustMarkState(s.source.trustMarkType(), s.isValid(now), s.isValid(now) ? s.expiresAt : null,
            s.lastFetched, s.lastFailure, s.lastFailureReason, s.failures))
        .toList();
  }

  /**
   * Fetches and checks one trust mark.
   *
   * @param slot the state of the trust mark type
   * @return {@code true} if a trust mark was accepted and {@code false} otherwise
   */
  private boolean fetch(final @NonNull Slot slot) {
    final TrustMarkSource source = slot.source;
    try {
      final SignedJWT response = this.federationClient.trustMark(new FederationRequest<>(
          new TrustMarkRequest(new EntityID(this.entityId), new EntityID(source.issuer()),
              new EntityID(source.trustMarkType())),
          Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, source.endpoint().toString())));
      if (response == null) {
        throw new IllegalStateException("the issuer has not issued the trust mark to '%s'".formatted(this.entityId));
      }
      final JWTClaimsSet claims = this.check(response, source);
      final String serialized = response.serialize();
      synchronized (this) {
        slot.accept(serialized, claims, this.clock.instant(), this.clock.instant());
      }
      log.info("Fetched the trust mark '{}' from {}, valid until {}", source.trustMarkType(), source.issuer(),
          slot.expiresAt != null ? slot.expiresAt : "further notice");
      this.store(source.trustMarkType(), serialized);
      return true;
    }
    catch (final RuntimeException e) {
      final Instant now = this.clock.instant();
      synchronized (this) {
        slot.fail(e.getMessage(), now, now.plus(this.retryInterval));
      }
      log.error("Failed to get the trust mark '{}' from {} ({} failed attempts) - next attempt at {}{}: {}",
          source.trustMarkType(), source.endpoint(), slot.failures, now.plus(this.retryInterval),
          slot.isValid(now) ? ", the current trust mark is published until it expires" : "", e.getMessage());
      return false;
    }
  }

  /**
   * Checks a trust mark.
   *
   * @param trustMark the trust mark
   * @param source where the trust mark comes from
   * @return the claims of the trust mark
   * @throws RuntimeException if the trust mark does not pass the check
   */
  private @NonNull JWTClaimsSet check(final @NonNull SignedJWT trustMark, final @NonNull TrustMarkSource source) {
    final JWTClaimsSet claims = FederationJwtVerifier.verify(trustMark, HttpTrustMarkRequester.TRUST_MARK_TYPE,
        source.issuerKeys(), source.issuer(), this.entityId, Set.of("iat", "trust_mark_type"));
    final Object type = claims.getClaim("trust_mark_type");
    if (!source.trustMarkType().equals(type)) {
      throw new IllegalStateException("the trust mark is of type '%s', not '%s'".formatted(
          type, source.trustMarkType()));
    }
    return claims;
  }

  /**
   * Writes a trust mark to the cache directory, if there is one. A failure is logged, and does not affect the trust
   * mark.
   *
   * @param trustMarkType the trust mark type
   * @param trustMark the trust mark JWT
   */
  private void store(final @NonNull String trustMarkType, final @NonNull String trustMark) {
    if (this.cacheDirectory == null) {
      return;
    }
    final Path file = this.fileFor(trustMarkType);
    try {
      Files.createDirectories(this.cacheDirectory);
      final Path temporary = Files.createTempFile(this.cacheDirectory, "trust-mark", ".tmp");
      Files.writeString(temporary, trustMark, StandardCharsets.UTF_8);
      Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      log.debug("Stored the trust mark '{}' in {}", trustMarkType, file);
    }
    catch (final IOException e) {
      log.warn("Failed to store the trust mark '{}' in {}: {}", trustMarkType, file, e.getMessage());
    }
  }

  /**
   * Gets the file where a trust mark type is stored: the SHA-256 hash of the type, in hex, with the suffix
   * {@code .jwt}.
   *
   * @param trustMarkType the trust mark type
   * @return the file
   */
  private @NonNull Path fileFor(final @NonNull String trustMarkType) {
    try {
      final byte[] hash = MessageDigest.getInstance("SHA-256").digest(trustMarkType.getBytes(StandardCharsets.UTF_8));
      return Objects.requireNonNull(this.cacheDirectory).resolve(HexFormat.of().formatHex(hash) + ".jwt");
    }
    catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }

  /**
   * Stops the job.
   */
  @Override
  public synchronized void close() {
    if (this.executor != null) {
      this.executor.shutdownNow();
      this.executor = null;
    }
  }

  /**
   * The state of one trust mark type.
   */
  private static final class Slot {

    /** Where the trust mark is fetched. */
    private final TrustMarkSource source;

    /** The current trust mark, or {@code null}. */
    private String trustMark;

    /** When the current trust mark expires, or {@code null} if it does not. */
    private Instant expiresAt;

    /** When the current trust mark is fetched again, or {@code null} if it is not. */
    private Instant renewAt;

    /** The earliest time of the next attempt after a failure, or {@code null}. */
    private Instant nextAttempt;

    /** When a trust mark was last accepted. */
    private Instant lastFetched;

    /** When the latest failure happened. */
    private Instant lastFailure;

    /** Why the latest attempt failed. */
    private String lastFailureReason;

    /** The number of failed attempts since the latest successful one. */
    private int failures;

    /**
     * Constructor.
     *
     * @param source where the trust mark is fetched
     */
    private Slot(final @NonNull TrustMarkSource source) {
      this.source = source;
    }

    /**
     * Tells whether a valid trust mark is held.
     *
     * @param now the current time
     * @return {@code true} if a valid trust mark is held and {@code false} otherwise
     */
    private boolean isValid(final @NonNull Instant now) {
      return this.trustMark != null && (this.expiresAt == null || now.isBefore(this.expiresAt));
    }

    /**
     * Tells whether the trust mark should be fetched.
     *
     * @param now the current time
     * @return {@code true} if it should be fetched and {@code false} otherwise
     */
    private boolean isDue(final @NonNull Instant now) {
      if (this.nextAttempt != null && now.isBefore(this.nextAttempt)) {
        return false;
      }
      if (!this.isValid(now)) {
        return true;
      }
      return this.renewAt != null && !now.isBefore(this.renewAt);
    }

    /**
     * Records an accepted trust mark.
     *
     * @param trustMark the trust mark JWT
     * @param claims its claims
     * @param now the current time
     * @param fetched when it was fetched
     */
    private void accept(final @NonNull String trustMark, final @NonNull JWTClaimsSet claims,
        final @NonNull Instant now, final @NonNull Instant fetched) {
      this.trustMark = trustMark;
      this.expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null;
      if (this.expiresAt == null) {
        this.renewAt = null;
      }
      else {
        final Instant issuedAt = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : now;
        final long lifetime = Math.max(0, this.expiresAt.toEpochMilli() - issuedAt.toEpochMilli());
        this.renewAt = issuedAt.plusMillis((long) (lifetime * RENEWAL_FACTOR));
      }
      this.lastFetched = fetched;
      this.nextAttempt = null;
      this.lastFailure = null;
      this.lastFailureReason = null;
      this.failures = 0;
    }

    /**
     * Records a failed attempt.
     *
     * @param reason why it failed
     * @param now the current time
     * @param nextAttempt the earliest time of the next attempt
     */
    private void fail(final @Nullable String reason, final @NonNull Instant now, final @NonNull Instant nextAttempt) {
      this.lastFailure = now;
      this.lastFailureReason = reason;
      this.nextAttempt = nextAttempt;
      this.failures++;
    }

  }

}
