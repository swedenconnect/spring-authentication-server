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
 * An {@link AccessTokenStore} that keeps the tokens in memory. It only serves the node it runs on, so a deployment with
 * several nodes needs sticky sessions or a shared store.
 *
 * @author Martin Lindström
 */
public class InMemoryAccessTokenStore implements AccessTokenStore {

  /** The entries, by token value. */
  private final Map<String, Entry> entries = new ConcurrentHashMap<>();

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   */
  public InMemoryAccessTokenStore() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock
   */
  public InMemoryAccessTokenStore(final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void save(final @NonNull AccessTokenData token) {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(e -> e.token().isExpired(now));
    this.entries.put(token.value(), new Entry(token, false));
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable AccessTokenData get(final @NonNull String value) {
    final Entry entry = this.entries.get(value);
    if (entry == null || entry.token().isExpired(this.clock.instant()) || entry.used()) {
      return null;
    }
    return entry.token();
  }

  /** {@inheritDoc} */
  @Override
  public boolean markUsed(final @NonNull String value) {
    final Instant now = this.clock.instant();
    final boolean[] result = new boolean[1];
    this.entries.computeIfPresent(value, (key, entry) -> {
      if (entry.token().isExpired(now) || entry.used()) {
        return entry;
      }
      result[0] = true;
      return entry.token().singleUse() ? new Entry(entry.token(), true) : entry;
    });
    return result[0];
  }

  /** {@inheritDoc} */
  @Override
  public void revoke(final @NonNull String value) {
    this.entries.remove(value);
  }

  /**
   * An entry of the store.
   *
   * @param token the token
   * @param used whether a single use token has been used
   */
  private record Entry(@NonNull AccessTokenData token, boolean used) {
  }

}
