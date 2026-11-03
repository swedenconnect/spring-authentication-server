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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * The background job that reads the keys of the clients from the configuration and from client repositories again,
 * see {@link ValidatingClientBackend#refreshClients()}. Without it, the OpenID Provider would keep encrypting to an old
 * key, since encryption, unlike a signed JWT naming an unknown key, gives no cause to read the keys again. The job also
 * validates again a client whose temporary mark has run out, so that the mark does not depend on a request arriving.
 * <p>
 * Federation clients are not covered. They read their keys when they are resolved.
 * </p>
 * <p>
 * When the {@link ClientValidationStore} is shared by several nodes, a round runs on one node at a time, see
 * {@link ClientValidationStore#getJobLock()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientKeysRefresher implements Runnable, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientKeysRefresher.class);

  /** The default interval between two rounds: one hour. */
  public static final Duration DEFAULT_INTERVAL = Duration.ofHours(1);

  /** The name of the job, for the {@link JobLock} of the store. */
  public static final String JOB_NAME = "oidc-client-keys-refresh";

  /** The backends whose clients are covered. */
  private final List<ValidatingClientBackend> backends;

  /** Decides which node runs a round. */
  private final JobLock jobLock;

  /** The interval between two rounds. */
  private final Duration interval;

  /** Where the job runs, or {@code null} until it has been started. */
  private ScheduledExecutorService executor;

  /**
   * Constructor.
   *
   * @param backends the backends whose clients are covered
   * @param jobLock decides which node runs a round
   * @param interval the interval between two rounds
   */
  public ClientKeysRefresher(final @NonNull List<ValidatingClientBackend> backends, final @NonNull JobLock jobLock,
      final @NonNull Duration interval) {
    this.backends = List.copyOf(Objects.requireNonNull(backends, "backends must not be null"));
    this.jobLock = Objects.requireNonNull(jobLock, "jobLock must not be null");
    this.interval = Objects.requireNonNull(interval, "interval must not be null");
    if (interval.isZero() || interval.isNegative()) {
      throw new IllegalArgumentException("interval must be a positive duration");
    }
  }

  /**
   * Starts the job. The first round runs one interval after the start, since the clients are validated when the
   * OpenID Provider starts.
   */
  public synchronized void start() {
    if (this.executor != null) {
      return;
    }
    final long millis = this.interval.toMillis();
    this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
      final Thread thread = new Thread(r, "oidc-client-keys-refresher");
      thread.setDaemon(true);
      return thread;
    });
    this.executor.scheduleWithFixedDelay(this, millis, millis, TimeUnit.MILLISECONDS);
    log.info("The keys of the OpenID Connect clients from the configuration and client repositories are read again "
        + "every {}", this.interval);
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    try {
      this.refresh();
    }
    catch (final RuntimeException e) {
      log.error("Reading the keys of the OpenID Connect clients again failed", e);
    }
  }

  /**
   * Runs one round over the backends. Nothing is done when another node runs the round.
   *
   * @return {@code true} if the round ran on this node and {@code false} otherwise
   */
  public boolean refresh() {
    if (!this.jobLock.tryAcquire(JOB_NAME, this.interval)) {
      log.debug("The keys of the OpenID Connect clients are read again on another node this round");
      return false;
    }
    for (final ValidatingClientBackend backend : this.backends) {
      try {
        backend.refreshClients();
      }
      catch (final RuntimeException e) {
        log.error("Reading the keys of the clients of the source '{}' again failed: {}", backend.getName(),
            e.getMessage(), e);
      }
    }
    return true;
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
