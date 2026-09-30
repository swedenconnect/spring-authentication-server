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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;

/**
 * A {@link ClientAssertionReplayCache} that keeps the values in memory. It only serves the node it runs on.
 *
 * @author Martin Lindström
 */
public class InMemoryClientAssertionReplayCache implements ClientAssertionReplayCache {

  /** The values, as {@code client_id} and {@code jti}, with their expiry. */
  private final Map<String, Instant> entries = new ConcurrentHashMap<>();

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   */
  public InMemoryClientAssertionReplayCache() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock
   */
  public InMemoryClientAssertionReplayCache(final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public boolean register(final @NonNull String clientId, final @NonNull String jti,
      final @NonNull Instant expiresAt) {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(e -> !now.isBefore(e));
    return this.entries.putIfAbsent(clientId + " " + jti, expiresAt) == null;
  }

}
