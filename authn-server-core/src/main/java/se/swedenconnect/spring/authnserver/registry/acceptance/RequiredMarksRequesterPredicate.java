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
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * A {@link RequesterPredicate} that requires the requester to hold marks: SAML entity categories or OpenID Connect
 * trust mark types.
 * <p>
 * The marks are given as groups. Every group must be satisfied, and a group is satisfied by any one of its marks. So
 * {@code [[A, B], [C]]} means "A or B, and C".
 * </p>
 * <p>
 * When a group is not satisfied by the record, the predicate asks the registry for the marks of the group, see
 * {@link ClientRegistry#requestMark(se.swedenconnect.spring.authnserver.authentication.Requester, String)}, and
 * evaluates the updated record before rejecting. For SAML nothing is obtained this way.
 * </p>
 *
 * @author Martin Lindström
 */
public class RequiredMarksRequesterPredicate implements RequesterPredicate {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RequiredMarksRequesterPredicate.class);

  /** The protocol. */
  private final AuthenticationProtocol protocol;

  /** The groups of marks. */
  private final List<Set<String>> groups;

  /**
   * Constructor.
   *
   * @param protocol the protocol that the predicate applies to
   * @param groups the groups of marks, where every group must be satisfied by any one of its marks
   */
  public RequiredMarksRequesterPredicate(final @Nonnull AuthenticationProtocol protocol,
      final @Nonnull Collection<? extends Collection<String>> groups) {
    this.protocol = Objects.requireNonNull(protocol, "protocol must not be null");
    this.groups = Objects.requireNonNull(groups, "groups must not be null").stream()
        .map(g -> Collections.unmodifiableSet(new LinkedHashSet<>(g)))
        .toList();
    if (this.groups.stream().anyMatch(Set::isEmpty)) {
      throw new IllegalArgumentException("A group of required marks must not be empty");
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull AuthenticationProtocol getProtocol() {
    return this.protocol;
  }

  /**
   * Accepts the requester if every group is satisfied, asking the registry for missing marks first.
   */
  @Override
  public boolean test(final @Nonnull RequesterRecord record, final @Nonnull ClientRegistry registry)
      throws ClientRegistryException {
    RequesterRecord current = record;
    for (final Set<String> group : this.groups) {
      if (group.stream().anyMatch(current::hasMark)) {
        continue;
      }
      boolean satisfied = false;
      for (final String mark : group) {
        final RequesterRecord updated = registry.requestMark(current.requester(), mark);
        if (updated != null) {
          current = updated;
          if (current.hasMark(mark)) {
            satisfied = true;
            break;
          }
        }
      }
      if (!satisfied) {
        log.debug("Requester '{}' holds none of the required marks {}", record.getIdentifier(), group);
        return false;
      }
    }
    return true;
  }

  /**
   * Gets the groups of marks.
   *
   * @return the groups
   */
  public @Nonnull List<Set<String>> getGroups() {
    return this.groups;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "required-marks(%s)=%s".formatted(this.protocol, this.groups);
  }

}
