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
import org.jspecify.annotations.Nullable;

/**
 * An {@link AuthorizationCodeStore} that keeps the codes in memory. It only serves the node it runs on, so a
 * deployment with several nodes needs sticky sessions or a shared store.
 *
 * @author Martin Lindström
 */
public class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

  /** The entries, by code. */
  private final Map<String, Entry> entries = new ConcurrentHashMap<>();

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   */
  public InMemoryAuthorizationCodeStore() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock
   */
  public InMemoryAuthorizationCodeStore(final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void save(final @NonNull AuthorizationCodeData code) {
    this.purge();
    this.entries.put(code.code(), new Entry(code, false, null));
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Redemption redeem(final @NonNull String code) {
    final Instant now = this.clock.instant();
    final Redemption[] result = new Redemption[1];
    this.entries.computeIfPresent(code, (key, entry) -> {
      if (!now.isBefore(entry.code().retainUntil())) {
        return null;
      }
      if (entry.used()) {
        result[0] = new Redemption(entry.code(), true, entry.accessToken());
        return entry;
      }
      if (entry.code().isExpired(now)) {
        return entry;
      }
      result[0] = new Redemption(entry.code(), false, null);
      return new Entry(entry.code(), true, null);
    });
    return result[0];
  }

  /** {@inheritDoc} */
  @Override
  public void registerAccessToken(final @NonNull String code, final @NonNull String accessToken) {
    this.entries.computeIfPresent(code, (key, entry) -> new Entry(entry.code(), entry.used(), accessToken));
  }

  /**
   * Removes the entries that no longer need to be kept.
   */
  private void purge() {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(e -> !now.isBefore(e.code().retainUntil()));
  }

  /**
   * An entry of the store.
   *
   * @param code the code
   * @param used whether the code has been used
   * @param accessToken the access token issued for the code, or {@code null}
   */
  private record Entry(@NonNull AuthorizationCodeData code, boolean used, @Nullable String accessToken) {
  }

}
