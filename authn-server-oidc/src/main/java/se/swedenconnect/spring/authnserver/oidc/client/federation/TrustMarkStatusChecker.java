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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationTrustMarkStatusRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.trustmark.TrustMarkStatusResponse;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * The background job that checks, at the issuer's trust mark status endpoint, that the trust marks the client
 * registry has asked for on demand are still valid, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.4">OpenID Federation 1.0, Section 8.4</a>.
 * <p>
 * A trust mark is checked when it has no {@code exp}, or when its {@code exp} is later than the next check. A trust
 * mark that expires before the next check is left to expire. The issuer must have a status endpoint configured in the
 * {@link FederationSettings}, otherwise its trust marks are not checked.
 * </p>
 * <p>
 * A trust mark that the issuer reports as anything but {@value #STATUS_ACTIVE} is removed from the cache entry, so a
 * client that needs it is treated as not holding it on its next request. A status endpoint that cannot be reached, or
 * a response that does not verify, leaves the trust mark in place.
 * </p>
 *
 * @author Martin Lindström
 */
public class TrustMarkStatusChecker implements Runnable, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(TrustMarkStatusChecker.class);

  /** The default interval between two checks: one hour. */
  public static final Duration DEFAULT_INTERVAL = Duration.ofHours(1);

  /** The explicit type of a trust mark status response. */
  public static final String TRUST_MARK_STATUS_RESPONSE_TYPE = "trust-mark-status-response+jwt";

  /** The status of a trust mark that is valid. */
  public static final String STATUS_ACTIVE = "active";

  /** Where resolved clients are kept. */
  private final FederationCache cache;

  /** The settings of the federation, giving the issuers. */
  private final FederationSettings settings;

  /** The client making the calls. */
  private final FederationClient federationClient;

  /** The interval between two checks. */
  private final Duration interval;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** Where the job runs, or {@code null} until it has been started. */
  private ScheduledExecutorService executor;

  /**
   * Constructor using an {@link HttpFederationClient} and the default interval.
   *
   * @param cache where resolved clients are kept
   * @param settings the settings of the federation
   */
  public TrustMarkStatusChecker(final @NonNull FederationCache cache, final @NonNull FederationSettings settings) {
    this(cache, settings, new HttpFederationClient(), DEFAULT_INTERVAL, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param cache where resolved clients are kept
   * @param settings the settings of the federation
   * @param federationClient the client making the calls
   * @param interval the interval between two checks
   * @param clock the clock to use
   */
  public TrustMarkStatusChecker(final @NonNull FederationCache cache, final @NonNull FederationSettings settings,
      final @NonNull FederationClient federationClient, final @NonNull Duration interval,
      final @NonNull Clock clock) {
    this.cache = Objects.requireNonNull(cache, "cache must not be null");
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.interval = Objects.requireNonNull(interval, "interval must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    if (interval.isZero() || interval.isNegative()) {
      throw new IllegalArgumentException("interval must be a positive duration");
    }
  }

  /**
   * Starts the job. It runs at the configured interval.
   */
  public synchronized void start() {
    if (this.executor != null) {
      return;
    }
    final long millis = this.interval.toMillis();
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread thread = new Thread(r, "trust-mark-status-checker");
      thread.setDaemon(true);
      return thread;
    });
    this.executor.scheduleWithFixedDelay(this, millis, millis, TimeUnit.MILLISECONDS);
    log.info("The trust mark status check runs every {}", this.interval);
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    try {
      this.check();
    }
    catch (final RuntimeException e) {
      log.error("The trust mark status check failed", e);
    }
  }

  /**
   * Makes one pass over the cached clients and checks the trust marks that qualify.
   *
   * @return the number of trust marks that were removed
   */
  public int check() {
    final Instant now = this.clock.instant();
    final Instant nextCheck = now.plus(this.interval);
    int removed = 0;
    for (final CachedClientRecord entry : this.cache.getEntries()) {
      for (final OnDemandTrustMark mark : entry.onDemandTrustMarks().values()) {
        if (!mark.isValid(now) || mark.trustMark() == null) {
          continue;
        }
        if (mark.trustMarkExpiresAt() != null && !mark.trustMarkExpiresAt().isAfter(nextCheck)) {
          continue;
        }
        if (!this.isActive(entry.clientId(), mark)) {
          this.remove(entry.clientId(), mark);
          removed++;
        }
      }
    }
    return removed;
  }

  /**
   * Asks the issuer about the status of a trust mark.
   *
   * @param clientId the client that holds the trust mark
   * @param mark the trust mark
   * @return {@code false} if the issuer reports that the trust mark is not valid, and {@code true} otherwise
   */
  private boolean isActive(final @NonNull String clientId, final @NonNull OnDemandTrustMark mark) {
    final FederationSettings.TrustMarkIssuer issuer = this.settings.getTrustMarkIssuer(mark.type());
    if (issuer == null || issuer.statusEndpoint() == null) {
      log.debug("No trust mark status endpoint is configured for '{}' - the trust mark of '{}' is not checked",
          mark.type(), clientId);
      return true;
    }
    final String trustMark = Objects.requireNonNull(mark.trustMark());
    try {
      final TrustMarkStatusResponse response = this.federationClient.trustMarkStatus(new FederationRequest<>(
          new FederationTrustMarkStatusRequest(trustMark, issuer.entityId()),
          Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT, issuer.statusEndpoint().toString())));
      if (response == null || response.isError() || response.getSignedJWT() == null) {
        throw new ClientRegistryException("No trust mark status response from " + issuer.statusEndpoint());
      }
      final JWTClaimsSet claims = FederationJwtVerifier.verify(response.getSignedJWT(),
          TRUST_MARK_STATUS_RESPONSE_TYPE, this.settings.getTrustMarkIssuerKeys(issuer), issuer.entityId(), null,
          Set.of("iat", "trust_mark", "status"));
      if (!trustMark.equals(claims.getStringClaim("trust_mark"))) {
        throw new ClientRegistryException("The trust mark status response from %s is about another trust mark"
            .formatted(issuer.statusEndpoint()));
      }
      final String status = claims.getStringClaim("status");
      if (STATUS_ACTIVE.equals(status)) {
        log.debug("The trust mark '{}' of '{}' is active", mark.type(), clientId);
        return true;
      }
      log.info("The issuer {} reports the trust mark '{}' of '{}' as '{}' - it is removed",
          issuer.entityId(), mark.type(), clientId, status);
      return false;
    }
    catch (final ClientRegistryException | ParseException e) {
      log.warn("Failed to check the status of the trust mark '{}' of '{}' - it is kept: {}",
          mark.type(), clientId, e.getMessage());
      return true;
    }
  }

  /**
   * Removes a trust mark from the cache entry of a client. The entry is read again, so that a change made since the
   * pass started is not lost, and the trust mark is only removed if it has not been replaced.
   *
   * @param clientId the client
   * @param mark the trust mark
   */
  private void remove(final @NonNull String clientId, final @NonNull OnDemandTrustMark mark) {
    final CachedClientRecord current = this.cache.get(clientId);
    if (current == null) {
      return;
    }
    final OnDemandTrustMark held = current.onDemandTrustMarks().get(mark.type());
    if (held != null && Objects.equals(held.trustMark(), mark.trustMark())) {
      this.cache.put(current.withoutTrustMark(mark.type()));
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

}
