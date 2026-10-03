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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link EntityConfigurationEndpoints}.
 *
 * @author Martin Lindström
 */
class EntityConfigurationEndpointsTest extends FederationTestSupport {

  private static final String RESOLVE_ENDPOINT = "https://resolver.example.com/resolve";

  private final ECKey key = key("resolver");

  private final TestClock clock = new TestClock();

  private final StubFederationClient client = new StubFederationClient();

  private final List<FederationCallEvent> events = new ArrayList<>();

  private EntityConfigurationEndpoints endpoints() {
    final EntityConfigurationEndpoints endpoints = new EntityConfigurationEndpoints(this.client, this.clock);
    endpoints.setEventPublisher(e -> this.events.add((FederationCallEvent) e));
    return endpoints;
  }

  private void publish(final Map<String, Object> federationEntity, final Duration lifetime) {
    this.client.entityConfigurations.put(RESOLVER,
        entityConfiguration(this.key, RESOLVER, federationEntity, this.clock.instant().plus(lifetime)));
  }

  @Test
  void anEndpointIsTakenFromTheEntityConfigurationAndKeptUntilItExpires() {
    this.publish(Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, RESOLVE_ENDPOINT), Duration.ofHours(1));
    final EntityConfigurationEndpoints endpoints = this.endpoints();

    assertThat(endpoints.getEndpoint(RESOLVER, publicKeys(this.key), HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isEqualTo(URI.create(RESOLVE_ENDPOINT));
    assertThat(endpoints.getEndpoint(RESOLVER, publicKeys(this.key), HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isEqualTo(URI.create(RESOLVE_ENDPOINT));
    assertThat(this.client.entityConfigurationRequests).containsExactly(RESOLVER);

    this.clock.advance(Duration.ofHours(1));
    endpoints.getEndpoint(RESOLVER, publicKeys(this.key), HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT);
    assertThat(this.client.entityConfigurationRequests).containsExactly(RESOLVER, RESOLVER);
    assertThat(this.events).isEmpty();
  }

  @Test
  void anEndpointThatIsNotPublishedIsAFailureAndIsLookedForAgain() {
    this.publish(Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, "https://resolver.example.com/tm"),
        Duration.ofHours(1));
    final EntityConfigurationEndpoints endpoints = this.endpoints();

    assertThat(endpoints.findEndpoint(RESOLVER, publicKeys(this.key),
        HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT)).isNull();
    assertThat(this.events).isEmpty();

    assertThatThrownBy(() -> endpoints.getEndpoint(RESOLVER, publicKeys(this.key),
        HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("does not publish federation_resolve_endpoint");
    assertThat(this.events).singleElement().satisfies(e -> {
      assertThat(e.getServiceType()).isEqualTo(FederationCallEvent.ServiceType.ENTITY_CONFIGURATION);
      assertThat(e.getServiceId()).isEqualTo(RESOLVER);
      assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.ERROR_RESPONSE);
    });
    assertThat(this.client.entityConfigurationRequests).containsExactly(RESOLVER, RESOLVER);

    // Once the entity publishes it, it is found
    this.publish(Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, RESOLVE_ENDPOINT), Duration.ofHours(1));
    assertThat(endpoints.getEndpoint(RESOLVER, publicKeys(this.key), HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isEqualTo(URI.create(RESOLVE_ENDPOINT));
  }

  @Test
  void anEntityThatCannotBeReachedIsTriedAgain() {
    final EntityConfigurationEndpoints endpoints = this.endpoints();
    assertThatThrownBy(() -> endpoints.getEndpoint(RESOLVER, publicKeys(this.key),
        HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("could not be reached");

    this.publish(Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, RESOLVE_ENDPOINT), Duration.ofHours(1));
    assertThat(endpoints.getEndpoint(RESOLVER, publicKeys(this.key), HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isEqualTo(URI.create(RESOLVE_ENDPOINT));
  }

  @Test
  void anEntityConfigurationThatDoesNotVerifyIsRejected() {
    this.publish(Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, RESOLVE_ENDPOINT), Duration.ofHours(1));
    final EntityConfigurationEndpoints endpoints = this.endpoints();
    assertThatThrownBy(() -> endpoints.getEndpoint(RESOLVER, publicKeys(key("other")),
        HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("Failed to verify");
    assertThat(this.events).singleElement()
        .satisfies(e -> assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.ERROR_RESPONSE));
  }

  @Test
  void anEntityConfigurationOfAnotherEntityIsRejected() {
    this.client.entityConfigurations.put(RESOLVER, entityConfiguration(this.key, TRUST_ANCHOR,
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, RESOLVE_ENDPOINT),
        this.clock.instant().plus(Duration.ofHours(1))));
    assertThatThrownBy(() -> this.endpoints().getEndpoint(RESOLVER, publicKeys(this.key),
        HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void anEndpointThatIsNotAUriIsRejected() {
    this.publish(Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "not a uri"), Duration.ofHours(1));
    assertThatThrownBy(() -> this.endpoints().getEndpoint(RESOLVER, publicKeys(this.key),
        HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("not a valid URI");
  }

  @Test
  void theLocationFollowsTheEntityIdentifier() {
    assertThat(EntityConfigurationEndpoints.location("https://ta.example.com"))
        .isEqualTo("https://ta.example.com/.well-known/openid-federation");
    assertThat(EntityConfigurationEndpoints.location("https://example.com/ta/"))
        .isEqualTo("https://example.com/ta/.well-known/openid-federation");
  }

}
