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
package se.swedenconnect.spring.authnserver.attributes.release;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * The default {@link AttributeReleaseManager}.
 *
 * @author Martin Lindström
 */
public class DefaultAttributeReleaseManager implements AttributeReleaseManager {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(DefaultAttributeReleaseManager.class);

  /** The producers. */
  private final List<AttributeProducer> producers;

  /** The voters. */
  private final List<AttributeReleaseVoter> voters;

  /**
   * Constructor.
   *
   * @param producers the producers, at least one must be given
   * @param voters the voters, may be {@code null} or empty in which case an
   *     {@link IncludeAllAttributeReleaseVoter} is used
   */
  public DefaultAttributeReleaseManager(final @Nullable List<AttributeProducer> producers,
      final @Nullable List<AttributeReleaseVoter> voters) {
    if (producers == null || producers.isEmpty()) {
      throw new IllegalArgumentException("At least one attribute producer must be given");
    }
    this.producers = List.copyOf(producers);
    this.voters = voters != null && !voters.isEmpty()
        ? List.copyOf(voters)
        : List.of(new IncludeAllAttributeReleaseVoter());
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<GenericAttribute<? extends Serializable>> releaseAttributes(
      final @NonNull UserAuthentication userAuthentication) {

    final List<GenericAttribute<? extends Serializable>> released = new ArrayList<>();
    for (final AttributeProducer producer : this.producers) {
      for (final GenericAttribute<? extends Serializable> attribute : producer.releaseAttributes(userAuthentication)) {
        if (released.stream().anyMatch(a -> a.getIdentifier().equals(attribute.getIdentifier()))) {
          log.trace("Attribute '{}' has already been released [{}]",
              attribute.getIdentifier(), userAuthentication.getLogString());
          continue;
        }
        if (this.vote(userAuthentication, attribute) == AttributeReleaseVote.INCLUDE) {
          released.add(attribute);
        }
        else {
          log.debug("Attribute '{}' is not released [{}]",
              attribute.getIdentifier(), userAuthentication.getLogString());
        }
      }
    }
    log.debug("Released attributes: {} [{}]",
        released.stream().map(GenericAttribute::getIdentifier).toList(), userAuthentication.getLogString());

    return released;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<AttributeProducer> getAttributeProducers() {
    return Collections.unmodifiableList(this.producers);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<AttributeReleaseVoter> getAttributeReleaseVoters() {
    return Collections.unmodifiableList(this.voters);
  }

  /**
   * Asks the voters about an attribute.
   *
   * @param userAuthentication the authentication result
   * @param attribute the attribute to vote on
   * @return the outcome of the vote
   */
  private @NonNull AttributeReleaseVote vote(final @NonNull UserAuthentication userAuthentication,
      final @NonNull GenericAttribute<? extends Serializable> attribute) {

    AttributeReleaseVote outcome = AttributeReleaseVote.DONT_KNOW;
    for (final AttributeReleaseVoter voter : this.voters) {
      final AttributeReleaseVote vote = voter.vote(userAuthentication, attribute);
      if (vote == AttributeReleaseVote.DONT_INCLUDE) {
        return AttributeReleaseVote.DONT_INCLUDE;
      }
      if (vote == AttributeReleaseVote.INCLUDE) {
        outcome = AttributeReleaseVote.INCLUDE;
      }
    }
    return outcome;
  }

}
