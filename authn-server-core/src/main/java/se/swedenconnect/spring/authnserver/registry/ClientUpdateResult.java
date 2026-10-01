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
package se.swedenconnect.spring.authnserver.registry;

import java.util.Objects;

import org.jspecify.annotations.NonNull;

/**
 * The result of an update that an operator asks for, see {@link ClientRegistryBackend#update()} and
 * {@link ClientRegistryBackend#update(String)}.
 *
 * @param outcome what happened
 * @param message a description of what happened
 * @author Martin Lindström
 */
public record ClientUpdateResult(@NonNull Outcome outcome, @NonNull String message) {

  /**
   * Constructor.
   *
   * @param outcome what happened
   * @param message a description of what happened
   */
  public ClientUpdateResult {
    Objects.requireNonNull(outcome, "outcome must not be null");
    Objects.requireNonNull(message, "message must not be null");
  }

  /**
   * Creates a result telling that the data was updated.
   *
   * @param message a description
   * @return a {@link ClientUpdateResult}
   */
  public static @NonNull ClientUpdateResult updated(final @NonNull String message) {
    return new ClientUpdateResult(Outcome.UPDATED, message);
  }

  /**
   * Creates a result telling that the client is no longer known by its source.
   *
   * @param message a description
   * @return a {@link ClientUpdateResult}
   */
  public static @NonNull ClientUpdateResult removed(final @NonNull String message) {
    return new ClientUpdateResult(Outcome.REMOVED, message);
  }

  /**
   * Creates a result telling that there is nothing to update.
   *
   * @param message a description
   * @return a {@link ClientUpdateResult}
   */
  public static @NonNull ClientUpdateResult nothingToUpdate(final @NonNull String message) {
    return new ClientUpdateResult(Outcome.NOTHING_TO_UPDATE, message);
  }

  /**
   * Creates a result telling that the update failed.
   *
   * @param message a description
   * @return a {@link ClientUpdateResult}
   */
  public static @NonNull ClientUpdateResult failed(final @NonNull String message) {
    return new ClientUpdateResult(Outcome.FAILED, message);
  }

  /**
   * What happened in an update.
   */
  public enum Outcome {

    /** The data was fetched again. */
    UPDATED,

    /** The source no longer knows the client. */
    REMOVED,

    /** The data does not come from a source that can be updated. */
    NOTHING_TO_UPDATE,

    /** The update failed. The data held before is kept. */
    FAILED

  }

}
