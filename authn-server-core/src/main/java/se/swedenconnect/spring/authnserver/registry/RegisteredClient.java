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

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * A client that a {@link ClientRegistryBackend} holds, as it is shown to an operator: the protocol-neutral part of its
 * record, where it came from and when its data expires.
 *
 * @param requester the requester
 * @param organizationNumber the organisation number, as held in the registry, or {@code null}
 * @param marks the marks that the client holds
 * @param source where the client came from: a SAML metadata source or the name of an OpenID Connect backend
 * @param expiresAt when the data of the client expires, or {@code null} if it does not
 * @author Martin Lindström
 */
public record RegisteredClient(
    @NonNull Requester requester,
    @Nullable String organizationNumber,
    @NonNull Set<String> marks,
    @NonNull String source,
    @Nullable Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param requester the requester
   * @param organizationNumber the organisation number, or {@code null}
   * @param marks the marks that the client holds
   * @param source where the client came from
   * @param expiresAt when the data of the client expires, or {@code null}
   */
  public RegisteredClient {
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(source, "source must not be null");
    marks = Set.copyOf(Objects.requireNonNull(marks, "marks must not be null"));
  }

  /**
   * Creates the entry for a client from its record.
   *
   * @param record the record of the client
   * @param source where the client came from
   * @param expiresAt when the data of the client expires, or {@code null}
   * @return a {@link RegisteredClient}
   */
  public static @NonNull RegisteredClient of(final @NonNull RequesterRecord record, final @NonNull String source,
      final @Nullable Instant expiresAt) {
    return new RegisteredClient(record.requester(), record.organizationNumber(), record.marks(), source, expiresAt);
  }

}
