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

import java.time.Duration;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.util.StringUtils;

/**
 * How the {@link FederationClientCollector} works.
 *
 * @param enabled whether the job runs
 * @param interval how often the job runs
 * @param intermediates the entity identifiers of the intermediates that the walk starts from, instead of the trust
 *          anchor. Empty to start from the trust anchor
 * @param keepUntilExpiry whether a cached client that the resolver no longer knows is kept until its cache entry
 *          expires, instead of being dropped at once
 * @author Martin Lindström
 */
public record FederationCollectorSettings(
    boolean enabled,
    @NonNull Duration interval,
    @NonNull List<String> intermediates,
    boolean keepUntilExpiry) {

  /** The default interval between two runs of the job: 30 minutes. */
  public static final Duration DEFAULT_INTERVAL = Duration.ofMinutes(30);

  /**
   * Constructor.
   *
   * @param enabled whether the job runs
   * @param interval how often the job runs
   * @param intermediates the entity identifiers of the intermediates that the walk starts from, or an empty list
   * @param keepUntilExpiry whether a client that the resolver no longer knows is kept until its cache entry expires
   */
  public FederationCollectorSettings {
    Objects.requireNonNull(interval, "interval must not be null");
    if (interval.isZero() || interval.isNegative()) {
      throw new IllegalArgumentException("interval must be a positive duration");
    }
    intermediates = List.copyOf(Objects.requireNonNull(intermediates, "intermediates must not be null"));
    if (intermediates.stream().anyMatch(i -> !StringUtils.hasText(i))) {
      throw new IllegalArgumentException("intermediates must not hold empty values");
    }
  }

  /**
   * Creates the default settings: the job runs every {@link #DEFAULT_INTERVAL}, starts from the trust anchor, and keeps
   * a client that the resolver no longer knows until its cache entry expires.
   *
   * @return a {@link FederationCollectorSettings}
   */
  public static @NonNull FederationCollectorSettings defaults() {
    return new FederationCollectorSettings(true, DEFAULT_INTERVAL, List.of(), true);
  }

}
