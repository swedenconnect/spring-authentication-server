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

import java.util.List;

import org.jspecify.annotations.NonNull;

/**
 * Runs the {@link AttributeProducer}s and lets the {@link AttributeReleaseVoter}s decide what is kept. It is itself a
 * producer, and it is what the protocol modules ask for the attributes to put in a response.
 * <p>
 * The producers are run in order and the first one to release an attribute wins, so a later producer releasing the
 * same generic attribute is ignored.
 * </p>
 * <p>
 * Every released attribute is then put to the voters, in order:
 * </p>
 * <ul>
 * <li>A {@link AttributeReleaseVote#DONT_INCLUDE} ends the vote and the attribute is left out.</li>
 * <li>Otherwise at least one {@link AttributeReleaseVote#INCLUDE} is needed for the attribute to be released.</li>
 * <li>{@link AttributeReleaseVote#DONT_KNOW} leaves the decision to the other voters, so an attribute that every
 * voter is indifferent about is left out.</li>
 * </ul>
 *
 * @author Martin Lindström
 */
public interface AttributeReleaseManager extends AttributeProducer {

  /**
   * Gets the producers that this manager runs.
   *
   * @return the {@link AttributeProducer}s
   */
  @NonNull List<AttributeProducer> getAttributeProducers();

  /**
   * Gets the voters that this manager asks.
   *
   * @return the {@link AttributeReleaseVoter}s
   */
  @NonNull List<AttributeReleaseVoter> getAttributeReleaseVoters();

}
