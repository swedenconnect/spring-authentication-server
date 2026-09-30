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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Tests for {@link DefaultClientRegistry}.
 *
 * @author Martin Lindström
 */
class DefaultClientRegistryTest {

  private static final Requester CLIENT = new Requester(AuthenticationProtocol.OIDC, "https://client.example.com");

  private static final Requester SP = new Requester(AuthenticationProtocol.SAML, "https://sp.example.com");

  @Test
  void theFirstBackendThatKnowsTheRequesterWins() {
    final TestBackend first = new TestBackend("first", AuthenticationProtocol.OIDC, CLIENT.identifier());
    final TestBackend second = new TestBackend("second", AuthenticationProtocol.OIDC, CLIENT.identifier());
    final ClientRegistry registry = new DefaultClientRegistry(List.of(first, second));

    final RequesterRecord record = registry.lookup(CLIENT);

    assertThat(record).isNotNull();
    assertThat(record.marks()).containsExactly("first");
    assertThat(second.asked).isEmpty();
  }

  @Test
  void theNextBackendIsAskedWhenTheFirstDoesNotKnowTheRequester() {
    final TestBackend first = new TestBackend("first", AuthenticationProtocol.OIDC);
    final TestBackend second = new TestBackend("second", AuthenticationProtocol.OIDC, CLIENT.identifier());
    final ClientRegistry registry = new DefaultClientRegistry(List.of(first, second));

    final RequesterRecord record = registry.lookup(AuthenticationProtocol.OIDC, CLIENT.identifier());

    assertThat(record).isNotNull();
    assertThat(record.marks()).containsExactly("second");
    assertThat(first.asked).containsExactly(CLIENT.identifier());
  }

  @Test
  void anUnknownRequesterGivesNoRecord() {
    final ClientRegistry registry = new DefaultClientRegistry(
        List.of(new TestBackend("only", AuthenticationProtocol.OIDC)));
    assertThat(registry.lookup(CLIENT)).isNull();
  }

  @Test
  void aBackendFailureIsNotAnUnknownRequester() {
    final ClientRegistryBackend failing = new TestBackend("failing", AuthenticationProtocol.OIDC) {

      @Override
      public @Nullable RequesterRecord lookup(final @NonNull String identifier) {
        throw new ClientRegistryException("the resolver could not be reached");
      }

    };
    final ClientRegistry registry = new DefaultClientRegistry(List.of(failing));

    assertThatThrownBy(() -> registry.lookup(CLIENT))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("could not be reached");
  }

  @Test
  void onlyTheBackendsOfTheRequestersProtocolAreAsked() {
    final TestBackend saml = new TestBackend("saml", AuthenticationProtocol.SAML, SP.identifier());
    final TestBackend oidc = new TestBackend("oidc", AuthenticationProtocol.OIDC, CLIENT.identifier());
    final ClientRegistry registry = new DefaultClientRegistry(List.of(saml, oidc));

    assertThat(registry.lookup(SP)).isNotNull();
    assertThat(oidc.asked).isEmpty();
    assertThat(registry.lookup(CLIENT)).isNotNull();
    assertThat(saml.asked).containsExactly(SP.identifier());
  }

  @Test
  void askingForAMarkGoesToTheBackendThatKnowsTheRequester() {
    final TestBackend first = new TestBackend("first", AuthenticationProtocol.OIDC);
    final TestBackend second = new TestBackend("second", AuthenticationProtocol.OIDC, CLIENT.identifier());
    final ClientRegistry registry = new DefaultClientRegistry(List.of(first, second));

    final RequesterRecord record = registry.requestMark(CLIENT, "https://example.com/mark");

    assertThat(record).isNotNull();
    assertThat(record.marks()).containsExactly("second");
    assertThat(registry.requestMark(new Requester(AuthenticationProtocol.OIDC, "other"), "mark")).isNull();
  }

  @Test
  void atLeastOneBackendIsRequired() {
    assertThatThrownBy(() -> new DefaultClientRegistry(List.of())).isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * A backend that knows a fixed set of requesters and records what it was asked for.
   */
  private static class TestBackend implements ClientRegistryBackend {

    /** The backend name, also used as the single mark of the records it hands out. */
    private final String name;

    /** The protocol that the backend answers for. */
    private final AuthenticationProtocol protocol;

    /** The requesters that the backend knows. */
    private final Set<String> known;

    /** What the backend has been asked for. */
    private final List<String> asked = new ArrayList<>();

    TestBackend(final String name, final AuthenticationProtocol protocol, final String... known) {
      this.name = name;
      this.protocol = protocol;
      this.known = Set.of(known);
    }

    @Override
    public @NonNull String getName() {
      return this.name;
    }

    @Override
    public @NonNull AuthenticationProtocol getProtocol() {
      return this.protocol;
    }

    @Override
    public @Nullable RequesterRecord lookup(final @NonNull String identifier) {
      this.asked.add(identifier);
      if (!this.known.contains(identifier)) {
        return null;
      }
      return new RequesterRecord(new Requester(this.protocol, identifier), List.of(), List.of(),
          Set.of(this.name), "metadata");
    }

  }

}
