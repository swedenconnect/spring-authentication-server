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
import java.util.function.BiFunction;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Checks whether an attribute that an {@link AttributeProducer} released is to be kept.
 * <p>
 * This is where an application puts a rule about what a given requester may receive. The library ships no list of the
 * attributes that a Service Provider or an OpenID Connect client is allowed to get; an application that needs one
 * writes a voter.
 * </p>
 *
 * @author Martin Lindström
 * @see AttributeReleaseManager
 */
@FunctionalInterface
public interface AttributeReleaseVoter
    extends BiFunction<UserAuthentication, GenericAttribute<? extends Serializable>, AttributeReleaseVote> {

  /**
   * Maps to {@link #vote(UserAuthentication, GenericAttribute)}.
   */
  @Override
  default @NonNull AttributeReleaseVote apply(final @NonNull UserAuthentication userAuthentication,
      final @NonNull GenericAttribute<? extends Serializable> attribute) {
    return this.vote(userAuthentication, attribute);
  }

  /**
   * Tells whether this voter thinks that the supplied attribute is to be released.
   *
   * @param userAuthentication the authentication result
   * @param attribute the attribute to vote on
   * @return an {@link AttributeReleaseVote}
   */
  @NonNull AttributeReleaseVote vote(final @NonNull UserAuthentication userAuthentication,
      final @NonNull GenericAttribute<? extends Serializable> attribute);

}
