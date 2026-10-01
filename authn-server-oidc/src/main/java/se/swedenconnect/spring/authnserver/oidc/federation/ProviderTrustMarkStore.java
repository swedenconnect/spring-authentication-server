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

import java.time.Instant;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * Where {@link ProviderTrustMarks} keeps the state of the OpenID Provider's own trust marks: the current trust mark of
 * each type, when it is fetched again, and the failures since the latest successful fetch.
 * <p>
 * The library ships an {@link InMemoryProviderTrustMarkStore}, for a single node, and a
 * {@link RedisProviderTrustMarkStore}, where the nodes of a deployment share the trust marks: one node at a time
 * fetches them, and every node publishes them.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ProviderTrustMarkStore {

  /**
   * Gets the state of a trust mark type.
   *
   * @param trustMarkType the trust mark type
   * @return the state, or {@code null} if nothing has been recorded for the type
   */
  @Nullable Entry get(final @NonNull String trustMarkType);

  /**
   * Records the state of a trust mark type.
   *
   * @param trustMarkType the trust mark type
   * @param entry the state
   */
  void put(final @NonNull String trustMarkType, final @NonNull Entry entry);

  /**
   * Gets the lock that decides which node fetches the trust marks. The default is {@link JobLock#LOCAL}, which is
   * always granted.
   *
   * @return a {@link JobLock}
   */
  default @NonNull JobLock getJobLock() {
    return JobLock.LOCAL;
  }

  /**
   * The state of one trust mark type.
   *
   * @param trustMark the current trust mark JWT, or {@code null}
   * @param expiresAt when the current trust mark expires, or {@code null} if it does not
   * @param renewAt when the current trust mark is fetched again, or {@code null} if it is not
   * @param nextAttempt the earliest time of the next attempt after a failure, or {@code null}
   * @param lastFetched when a trust mark was last accepted, or {@code null}
   * @param lastFailure when the latest failure happened, or {@code null}
   * @param lastFailureReason why the latest attempt failed, or {@code null}
   * @param failures the number of failed attempts since the latest successful one
   */
  record Entry(
      @Nullable String trustMark,
      @Nullable Instant expiresAt,
      @Nullable Instant renewAt,
      @Nullable Instant nextAttempt,
      @Nullable Instant lastFetched,
      @Nullable Instant lastFailure,
      @Nullable String lastFailureReason,
      int failures) {

    /** The state of a type that nothing has been recorded for. */
    public static final Entry EMPTY = new Entry(null, null, null, null, null, null, null, 0);

    /**
     * Tells whether a valid trust mark is held.
     *
     * @param now the current time
     * @return {@code true} if a valid trust mark is held and {@code false} otherwise
     */
    public boolean isValid(final @NonNull Instant now) {
      return this.trustMark != null && (this.expiresAt == null || now.isBefore(this.expiresAt));
    }

    /**
     * Tells whether the trust mark should be fetched: it is missing or has expired, or it has passed the time for
     * renewal, and the time of the next attempt after a failure has come.
     *
     * @param now the current time
     * @return {@code true} if it should be fetched and {@code false} otherwise
     */
    public boolean isDue(final @NonNull Instant now) {
      if (this.nextAttempt != null && now.isBefore(this.nextAttempt)) {
        return false;
      }
      if (!this.isValid(now)) {
        return true;
      }
      return this.renewAt != null && !now.isBefore(this.renewAt);
    }

    /**
     * Creates the state after a failed attempt. The current trust mark is kept.
     *
     * @param reason why it failed
     * @param now the current time
     * @param nextAttempt the earliest time of the next attempt
     * @return the new state
     */
    public @NonNull Entry failed(final @Nullable String reason, final @NonNull Instant now,
        final @NonNull Instant nextAttempt) {
      return new Entry(this.trustMark, this.expiresAt, this.renewAt, nextAttempt, this.lastFetched, now, reason,
          this.failures + 1);
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull String toString() {
      return "expires-at=%s, renew-at=%s, next-attempt=%s, failures=%d".formatted(
          this.expiresAt, this.renewAt, this.nextAttempt, this.failures);
    }

  }

}
