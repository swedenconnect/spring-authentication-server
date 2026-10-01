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
 * What the calls to one federation service have shown: the outcome of the latest call, the most recent failure and
 * the number of failed calls since the latest successful one, so that a failure is not hidden by a later success.
 *
 * @param type the kind of service
 * @param id the identity of the service: the endpoint of a resolver, or the entity identifier of a trust mark issuer
 * @param latestOutcome how the latest call went
 * @param latestCall when the latest call was made
 * @param lastFailure when the most recent failed call was made, or {@code null} if no call has failed
 * @param lastFailureOutcome how the most recent failed call went, or {@code null}
 * @param lastFailureError what went wrong in the most recent failed call, or {@code null}
 * @param failuresSinceSuccess the number of failed calls since the latest successful one
 * @author Martin Lindström
 */
public record FederationServiceState(
    FederationCallEvent.@NonNull ServiceType type,
    @NonNull String id,
    FederationCallEvent.@NonNull Outcome latestOutcome,
    @NonNull Instant latestCall,
    @Nullable Instant lastFailure,
    FederationCallEvent.@Nullable Outcome lastFailureOutcome,
    @Nullable String lastFailureError,
    int failuresSinceSuccess) {

  /**
   * Constructor.
   *
   * @param type the kind of service
   * @param id the identity of the service
   * @param latestOutcome how the latest call went
   * @param latestCall when the latest call was made
   * @param lastFailure when the most recent failed call was made, or {@code null}
   * @param lastFailureOutcome how the most recent failed call went, or {@code null}
   * @param lastFailureError what went wrong in the most recent failed call, or {@code null}
   * @param failuresSinceSuccess the number of failed calls since the latest successful one
   */
  public FederationServiceState {
    Objects.requireNonNull(type, "type must not be null");
    Objects.requireNonNull(id, "id must not be null");
    Objects.requireNonNull(latestOutcome, "latestOutcome must not be null");
    Objects.requireNonNull(latestCall, "latestCall must not be null");
  }

  /**
   * Tells whether the latest call failed.
   *
   * @return {@code true} if the latest call failed and {@code false} otherwise
   */
  public boolean isFailing() {
    return this.latestOutcome != FederationCallEvent.Outcome.SUCCESS;
  }

  /**
   * Creates the state after a call, from the state before it.
   *
   * @param previous the state before the call, or {@code null} if no call has been recorded
   * @param event the call
   * @return the new state
   */
  public static @NonNull FederationServiceState after(final @Nullable FederationServiceState previous,
      final @NonNull FederationCallEvent event) {
    final boolean failed = event.getOutcome() != FederationCallEvent.Outcome.SUCCESS;
    if (failed) {
      return new FederationServiceState(event.getServiceType(), event.getServiceId(), event.getOutcome(),
          event.getTime(), event.getTime(), event.getOutcome(), event.getError(),
          (previous != null ? previous.failuresSinceSuccess() : 0) + 1);
    }
    return new FederationServiceState(event.getServiceType(), event.getServiceId(), event.getOutcome(),
        event.getTime(), previous != null ? previous.lastFailure() : null,
        previous != null ? previous.lastFailureOutcome() : null,
        previous != null ? previous.lastFailureError() : null, 0);
  }

}
