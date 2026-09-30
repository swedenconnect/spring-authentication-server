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

import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A trust mark that has been asked for on demand and is held in a {@link CachedClientRecord}.
 *
 * @param type the trust mark type
 * @param trustMark the trust mark JWT, or {@code null} if it is not known, in which case its status cannot be checked
 * @param trustMarkExpiresAt the {@code exp} of the trust mark, or {@code null} if it does not expire
 * @param validUntil until when the trust mark is held: the earlier of its expiry and the expiry of the cache entry it
 *          was added to
 * @author Martin Lindström
 */
public record OnDemandTrustMark(
    @NonNull String type,
    @Nullable String trustMark,
    @Nullable Instant trustMarkExpiresAt,
    @NonNull Instant validUntil) {

  /**
   * Constructor.
   *
   * @param type the trust mark type
   * @param trustMark the trust mark JWT, or {@code null}
   * @param trustMarkExpiresAt the {@code exp} of the trust mark, or {@code null}
   * @param validUntil until when the trust mark is held
   */
  public OnDemandTrustMark {
    Objects.requireNonNull(type, "type must not be null");
    Objects.requireNonNull(validUntil, "validUntil must not be null");
  }

  /**
   * Tells whether the trust mark is still held.
   *
   * @param now the current time
   * @return {@code true} if the trust mark is valid and {@code false} otherwise
   */
  public boolean isValid(final @NonNull Instant now) {
    return now.isBefore(this.validUntil);
  }

}
