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

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * A {@link RequesterAcceptance} that holds a set of {@link RequesterPredicate}s.
 * <p>
 * Only the predicates of the requester's protocol are evaluated. Per protocol, the predicates are combined according
 * to a {@link Mode}: {@link Mode#ALL} (the default), where every predicate must accept, or {@link Mode#ANY}, where one
 * accepting predicate is enough. A protocol with no predicates accepts every requester.
 * </p>
 *
 * @author Martin Lindström
 */
public class ConfigurableRequesterAcceptance implements RequesterAcceptance {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ConfigurableRequesterAcceptance.class);

  /**
   * How the predicates of a protocol are combined.
   */
  public enum Mode {

    /** Every predicate must accept the requester. */
    ALL,

    /** One accepting predicate is enough. */
    ANY
  }

  /** The predicates. */
  private final List<RequesterPredicate> predicates = new CopyOnWriteArrayList<>();

  /** The combination modes, per protocol. */
  private final Map<AuthenticationProtocol, Mode> modes = new EnumMap<>(AuthenticationProtocol.class);

  /**
   * Adds a predicate.
   *
   * @param predicate the predicate
   * @return this object
   */
  public @Nonnull ConfigurableRequesterAcceptance addPredicate(final @Nonnull RequesterPredicate predicate) {
    this.predicates.add(Objects.requireNonNull(predicate, "predicate must not be null"));
    return this;
  }

  /**
   * Gets the predicates. The list may be modified.
   *
   * @return the predicates
   */
  public @Nonnull List<RequesterPredicate> getPredicates() {
    return this.predicates;
  }

  /**
   * Assigns how the predicates of a protocol are combined. The default is {@link Mode#ALL}.
   *
   * @param protocol the protocol
   * @param mode the combination mode
   * @return this object
   */
  public @Nonnull ConfigurableRequesterAcceptance mode(final @Nonnull AuthenticationProtocol protocol,
      final @Nonnull Mode mode) {
    this.modes.put(Objects.requireNonNull(protocol, "protocol must not be null"),
        Objects.requireNonNull(mode, "mode must not be null"));
    return this;
  }

  /**
   * Gets how the predicates of a protocol are combined.
   *
   * @param protocol the protocol
   * @return the combination mode
   */
  public @Nonnull Mode getMode(final @Nonnull AuthenticationProtocol protocol) {
    return this.modes.getOrDefault(protocol, Mode.ALL);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAccepted(final @Nonnull RequesterRecord record, final @Nonnull ClientRegistry registry)
      throws ClientRegistryException {

    final List<RequesterPredicate> applicable = new ArrayList<>();
    for (final RequesterPredicate predicate : this.predicates) {
      if (predicate.getProtocol() == record.getProtocol()) {
        applicable.add(predicate);
      }
    }
    if (applicable.isEmpty()) {
      return true;
    }
    final Mode mode = this.getMode(record.getProtocol());
    for (final RequesterPredicate predicate : applicable) {
      final boolean accepted = predicate.test(record, registry);
      log.debug("Predicate {} {} requester '{}'", predicate, accepted ? "accepted" : "rejected",
          record.getIdentifier());
      if (mode == Mode.ALL && !accepted) {
        return false;
      }
      if (mode == Mode.ANY && accepted) {
        return true;
      }
    }
    return mode == Mode.ALL;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "predicates=%s, modes=%s".formatted(this.predicates, this.modes);
  }

}
