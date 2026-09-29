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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.authentication;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.identifiers;
import static se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseTestSupport.producer;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Tests for {@link DefaultAttributeReleaseManager}.
 *
 * @author Martin Lindström
 */
class DefaultAttributeReleaseManagerTest {

  private static final GenericAttribute<String> SURNAME =
      GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson");

  private static final GenericAttribute<String> OTHER_SURNAME =
      GenericAttribute.of(AttributeIdentifiers.SURNAME, "Ek");

  private static final GenericAttribute<String> GIVEN_NAME =
      GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Agda");

  private static AttributeReleaseVoter voter(final AttributeReleaseVote vote) {
    return (authentication, attribute) -> vote;
  }

  @Test
  void atLeastOneProducerIsRequired() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new DefaultAttributeReleaseManager(null, null));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new DefaultAttributeReleaseManager(List.of(), null));
  }

  @Test
  void withoutVotersTheIncludeAllVoterIsUsed() {
    final DefaultAttributeReleaseManager manager =
        new DefaultAttributeReleaseManager(List.of(producer(SURNAME)), null);

    assertThat(manager.getAttributeReleaseVoters())
        .singleElement().isInstanceOf(IncludeAllAttributeReleaseVoter.class);
    assertThat(identifiers(manager.releaseAttributes(authentication())))
        .containsExactly(AttributeIdentifiers.SURNAME);

    assertThat(new DefaultAttributeReleaseManager(List.of(producer(SURNAME)), List.of())
        .getAttributeReleaseVoters()).singleElement().isInstanceOf(IncludeAllAttributeReleaseVoter.class);
  }

  @Test
  void theProducersAreRunInOrder() {
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME), producer(GIVEN_NAME)), null);

    assertThat(identifiers(manager.releaseAttributes(authentication())))
        .containsExactly(AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME);
  }

  @Test
  void theFirstProducerToReleaseAnAttributeWins() {
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME), producer(OTHER_SURNAME, GIVEN_NAME)), null);

    final List<GenericAttribute<? extends Serializable>> released = manager.releaseAttributes(authentication());

    assertThat(identifiers(released))
        .containsExactly(AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME);
    assertThat(released.getFirst()).isSameAs(SURNAME);
  }

  @Test
  void aDontIncludeVoteExcludesTheAttribute() {
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME, GIVEN_NAME)),
        List.of(voter(AttributeReleaseVote.INCLUDE),
            (authentication, attribute) -> AttributeIdentifiers.SURNAME.equals(attribute.getIdentifier())
                ? AttributeReleaseVote.DONT_INCLUDE
                : AttributeReleaseVote.DONT_KNOW));

    assertThat(identifiers(manager.releaseAttributes(authentication())))
        .containsExactly(AttributeIdentifiers.GIVEN_NAME);
  }

  @Test
  void aDontIncludeVoteEndsTheVote() {
    final List<String> asked = new ArrayList<>();
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME)),
        List.of(
            (authentication, attribute) -> {
              asked.add("first");
              return AttributeReleaseVote.DONT_INCLUDE;
            },
            (authentication, attribute) -> {
              asked.add("second");
              return AttributeReleaseVote.INCLUDE;
            }));

    assertThat(manager.releaseAttributes(authentication())).isEmpty();
    assertThat(asked).containsExactly("first");
  }

  @Test
  void atLeastOneIncludeVoteIsNeeded() {
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME)), List.of(voter(AttributeReleaseVote.DONT_KNOW)));

    assertThat(manager.releaseAttributes(authentication())).isEmpty();
  }

  @Test
  void aDontKnowVoteLeavesTheDecisionToTheOthers() {
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME)),
        List.of(voter(AttributeReleaseVote.DONT_KNOW), voter(AttributeReleaseVote.INCLUDE)));

    assertThat(identifiers(manager.releaseAttributes(authentication())))
        .containsExactly(AttributeIdentifiers.SURNAME);
  }

  @Test
  void theProducersAndVotersAreReachableAndImmutable() {
    final AttributeProducer producer = producer(SURNAME);
    final AttributeReleaseVoter voter = voter(AttributeReleaseVote.INCLUDE);
    final DefaultAttributeReleaseManager manager =
        new DefaultAttributeReleaseManager(List.of(producer), List.of(voter));

    assertThat(manager.getAttributeProducers()).containsExactly(producer);
    assertThat(manager.getAttributeReleaseVoters()).containsExactly(voter);
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> manager.getAttributeProducers().add(producer));
  }

  @Test
  void theVoterIsGivenTheAuthenticationAndTheAttribute() {
    final UserAuthentication authentication = authentication();
    final DefaultAttributeReleaseManager manager = new DefaultAttributeReleaseManager(
        List.of(producer(SURNAME)),
        List.of((token, attribute) -> token == authentication && attribute == SURNAME
            ? AttributeReleaseVote.INCLUDE
            : AttributeReleaseVote.DONT_INCLUDE));

    assertThat(manager.releaseAttributes(authentication)).containsExactly(SURNAME);
  }

  @Test
  void aVoterIsAlsoAFunction() {
    final AttributeReleaseVoter voter = new IncludeAllAttributeReleaseVoter();

    assertThat(voter.apply(authentication(), SURNAME)).isEqualTo(AttributeReleaseVote.INCLUDE);
  }

}
