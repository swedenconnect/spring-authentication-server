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
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The state of one of the OpenID Provider's own trust marks, as kept by {@link ProviderTrustMarks}. It tells whether a
 * valid trust mark is published and whether the latest attempt to fetch it failed, which is what a health check
 * needs.
 *
 * @param trustMarkType the trust mark type
 * @param published whether a valid trust mark of the type is published
 * @param expiresAt when the published trust mark expires, or {@code null} if none is published or it does not expire
 * @param lastFetched when a trust mark was last fetched and accepted, or {@code null} if never
 * @param lastFailure when the latest failure happened, or {@code null} if the latest attempt succeeded
 * @param lastFailureReason why the latest attempt failed, or {@code null} if it succeeded
 * @param consecutiveFailures the number of failed attempts since the latest successful one
 * @author Martin Lindström
 */
public record TrustMarkState(
    @NonNull String trustMarkType,
    boolean published,
    @Nullable Instant expiresAt,
    @Nullable Instant lastFetched,
    @Nullable Instant lastFailure,
    @Nullable String lastFailureReason,
    int consecutiveFailures) {

  /**
   * Constructor.
   *
   * @param trustMarkType the trust mark type
   * @param published whether a valid trust mark of the type is published
   * @param expiresAt when the published trust mark expires, or {@code null}
   * @param lastFetched when a trust mark was last fetched and accepted, or {@code null}
   * @param lastFailure when the latest failure happened, or {@code null}
   * @param lastFailureReason why the latest attempt failed, or {@code null}
   * @param consecutiveFailures the number of failed attempts since the latest successful one
   */
  public TrustMarkState {
    Objects.requireNonNull(trustMarkType, "trustMarkType must not be null");
  }

  /**
   * Tells whether the latest attempt to fetch the trust mark failed.
   *
   * @return {@code true} if the latest attempt failed and {@code false} otherwise
   */
  public boolean isFailing() {
    return this.consecutiveFailures > 0;
  }

}
