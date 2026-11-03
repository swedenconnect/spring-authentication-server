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

import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * Where the outcomes of the validation of clients from the configuration and from client repositories are kept,
 * together with the keys read from the clients' {@code jwks_uri}, see {@link ClientValidation}. The outcomes are kept
 * per client source, named by the backend.
 * <p>
 * The store is pluggable so that the nodes of a deployment can share it. The library ships an
 * {@link InMemoryClientValidationStore} and a {@link RedisClientValidationStore}. The store also gives the lock that
 * makes the {@link ClientKeysRefresher} run on one node at a time.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ClientValidationStore {

  /**
   * Gets the outcome for a client.
   *
   * @param source the name of the client source
   * @param clientId the {@code client_id} of the client
   * @return the outcome, or {@code null} if the store holds none
   */
  @Nullable ValidatedClient get(final @NonNull String source, final @NonNull String clientId);

  /**
   * Puts the outcome for a client, replacing any outcome held for the same client.
   *
   * @param source the name of the client source
   * @param client the outcome
   */
  void put(final @NonNull String source, final @NonNull ValidatedClient client);

  /**
   * Removes the outcome for a client.
   *
   * @param source the name of the client source
   * @param clientId the {@code client_id} of the client
   */
  void remove(final @NonNull String source, final @NonNull String clientId);

  /**
   * Gets every outcome held for a client source.
   *
   * @param source the name of the client source
   * @return the outcomes
   */
  @NonNull Collection<ValidatedClient> getAll(final @NonNull String source);

  /**
   * Gets the lock that the {@link ClientKeysRefresher} uses, so that a round runs on one node at a time. The default
   * is {@link JobLock#LOCAL}, which is always granted.
   *
   * @return a {@link JobLock}
   */
  default @NonNull JobLock getJobLock() {
    return JobLock.LOCAL;
  }

}
