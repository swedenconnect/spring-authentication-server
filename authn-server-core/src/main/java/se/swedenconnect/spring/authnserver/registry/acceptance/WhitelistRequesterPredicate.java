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
package se.swedenconnect.spring.authnserver.registry.acceptance;

import jakarta.annotation.Nonnull;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * A {@link RequesterPredicate} that accepts the requesters of a list: SAML entityIDs or OpenID Connect
 * {@code client_id}s.
 *
 * @author Martin Lindström
 */
public class WhitelistRequesterPredicate implements RequesterPredicate {

  /** The protocol. */
  private final AuthenticationProtocol protocol;

  /** The accepted requester identities. */
  private final Set<String> identifiers;

  /**
   * Constructor.
   *
   * @param protocol the protocol that the predicate applies to
   * @param identifiers the identities of the accepted requesters
   */
  public WhitelistRequesterPredicate(final @Nonnull AuthenticationProtocol protocol,
      final @Nonnull Collection<String> identifiers) {
    this.protocol = Objects.requireNonNull(protocol, "protocol must not be null");
    this.identifiers = Set.copyOf(Objects.requireNonNull(identifiers, "identifiers must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull AuthenticationProtocol getProtocol() {
    return this.protocol;
  }

  /**
   * Accepts the requester if its identity is in the list.
   */
  @Override
  public boolean test(final @Nonnull RequesterRecord record, final @Nonnull ClientRegistry registry) {
    return this.identifiers.contains(record.getIdentifier());
  }

  /**
   * Gets the identities of the accepted requesters.
   *
   * @return the identities
   */
  public @Nonnull Set<String> getIdentifiers() {
    return this.identifiers;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "whitelist(%s)=%s".formatted(this.protocol, this.identifiers);
  }

}
