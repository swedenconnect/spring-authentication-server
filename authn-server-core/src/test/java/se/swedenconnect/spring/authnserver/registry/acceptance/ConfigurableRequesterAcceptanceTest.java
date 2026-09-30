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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link ConfigurableRequesterAcceptance} and the built-in predicates.
 *
 * @author Martin Lindström
 */
class ConfigurableRequesterAcceptanceTest {

  private static final String SP = "https://sp.example.com";

  private static final String CLIENT = "https://client.example.com";

  /** A registry that gives the marks of a set when asked, and records what it was asked for. */
  static class MarkGivingRegistry implements ClientRegistry {

    private final Set<String> obtainable;

    final List<String> asked = new ArrayList<>();

    MarkGivingRegistry(final Set<String> obtainable) {
      this.obtainable = obtainable;
    }

    @Override
    public @Nullable RequesterRecord lookup(final @NonNull Requester requester) {
      return null;
    }

    @Override
    public @Nullable RequesterRecord requestMark(final @NonNull Requester requester, final @NonNull String mark) {
      this.asked.add(mark);
      return this.obtainable.contains(mark) ? record(requester, Set.of(mark)) : record(requester, Set.of());
    }
  }

  @Test
  void acceptAllAcceptsEveryRequester() throws Exception {
    assertThat(RequesterAcceptance.acceptAll().isAccepted(saml(Set.of()), new MarkGivingRegistry(Set.of())))
        .isTrue();
  }

  @Test
  void withoutPredicatesEveryRequesterIsAccepted() throws Exception {
    assertThat(new ConfigurableRequesterAcceptance().isAccepted(saml(Set.of()), new MarkGivingRegistry(Set.of())))
        .isTrue();
  }

  @Test
  void theWhitelistAcceptsListedRequesters() throws Exception {
    final ConfigurableRequesterAcceptance acceptance = new ConfigurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of(SP)));
    assertThat(acceptance.isAccepted(saml(Set.of()), new MarkGivingRegistry(Set.of()))).isTrue();
    assertThat(acceptance.isAccepted(record(new Requester(AuthenticationProtocol.SAML, "https://other"), Set.of()),
        new MarkGivingRegistry(Set.of()))).isFalse();
  }

  @Test
  void onlyThePredicatesOfTheRequestersProtocolAreEvaluated() throws Exception {
    final ConfigurableRequesterAcceptance acceptance = new ConfigurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.OIDC, List.of(CLIENT)));
    assertThat(acceptance.isAccepted(saml(Set.of()), new MarkGivingRegistry(Set.of()))).isTrue();
    assertThat(acceptance.isAccepted(record(new Requester(AuthenticationProtocol.OIDC, "other"), Set.of()),
        new MarkGivingRegistry(Set.of()))).isFalse();
  }

  @Test
  void everyGroupOfMarksMustBeSatisfiedByOneOfItsMarks() throws Exception {
    final RequiredMarksRequesterPredicate predicate = new RequiredMarksRequesterPredicate(AuthenticationProtocol.SAML,
        List.of(List.of("A", "B"), List.of("C")));
    final MarkGivingRegistry registry = new MarkGivingRegistry(Set.of());

    assertThat(predicate.test(saml(Set.of("A", "C")), registry)).isTrue();
    assertThat(predicate.test(saml(Set.of("B", "C")), registry)).isTrue();
    assertThat(registry.asked).isEmpty();

    assertThat(predicate.test(saml(Set.of("A")), registry)).isFalse();
    assertThat(predicate.test(saml(Set.of("C")), registry)).isFalse();
  }

  @Test
  void missingMarksAreAskedForBeforeRejecting() throws Exception {
    final RequiredMarksRequesterPredicate predicate = new RequiredMarksRequesterPredicate(AuthenticationProtocol.OIDC,
        List.of(List.of("A", "B")));
    final RequesterRecord record = record(new Requester(AuthenticationProtocol.OIDC, CLIENT), Set.of());

    final MarkGivingRegistry giving = new MarkGivingRegistry(Set.of("B"));
    assertThat(predicate.test(record, giving)).isTrue();
    assertThat(giving.asked).containsExactlyInAnyOrder("A", "B");

    final MarkGivingRegistry notGiving = new MarkGivingRegistry(Set.of());
    assertThat(predicate.test(record, notGiving)).isFalse();
    assertThat(notGiving.asked).containsExactlyInAnyOrder("A", "B");
  }

  @Test
  void aFailingRegistryIsPassedOn() {
    final RequiredMarksRequesterPredicate predicate = new RequiredMarksRequesterPredicate(AuthenticationProtocol.SAML,
        List.of(List.of("A")));
    final ClientRegistry failing = new MarkGivingRegistry(Set.of()) {
      @Override
      public @Nullable RequesterRecord requestMark(final @NonNull Requester requester, final @NonNull String mark)
          throws ClientRegistryException {
        throw new ClientRegistryException("down");
      }
    };
    assertThatThrownBy(() -> predicate.test(saml(Set.of()), failing)).isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void anEmptyGroupIsRejected() {
    assertThatIllegalArgumentException().isThrownBy(
        () -> new RequiredMarksRequesterPredicate(AuthenticationProtocol.SAML, List.of(List.of())));
  }

  @Test
  void allModeRequiresEveryPredicateAndAnyModeOne() throws Exception {
    final RequesterPredicate accepting = new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of(SP));
    final RequesterPredicate rejecting = new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of("x"));
    final MarkGivingRegistry registry = new MarkGivingRegistry(Set.of());

    final ConfigurableRequesterAcceptance acceptance =
        new ConfigurableRequesterAcceptance().addPredicate(accepting).addPredicate(rejecting);
    assertThat(acceptance.getMode(AuthenticationProtocol.SAML)).isEqualTo(ConfigurableRequesterAcceptance.Mode.ALL);
    assertThat(acceptance.isAccepted(saml(Set.of()), registry)).isFalse();

    acceptance.mode(AuthenticationProtocol.SAML, ConfigurableRequesterAcceptance.Mode.ANY);
    assertThat(acceptance.isAccepted(saml(Set.of()), registry)).isTrue();

    final ConfigurableRequesterAcceptance onlyRejecting = new ConfigurableRequesterAcceptance()
        .addPredicate(rejecting)
        .mode(AuthenticationProtocol.SAML, ConfigurableRequesterAcceptance.Mode.ANY);
    assertThat(onlyRejecting.isAccepted(saml(Set.of()), registry)).isFalse();
  }

  private static RequesterRecord saml(final Set<String> marks) {
    return record(new Requester(AuthenticationProtocol.SAML, SP), marks);
  }

  private static RequesterRecord record(final Requester requester, final Set<String> marks) {
    return new RequesterRecord(requester, List.of(), List.of(), marks, "metadata");
  }

}
