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

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Tests for {@link FederationServiceMonitor} and the stores of the state of the federation services.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class FederationServiceMonitorTest {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private static final String RESOLVE_ENDPOINT = "https://resolver.example.com/resolve";

  private static final String ISSUER = "https://tmi.example.com";

  private static LettuceConnectionFactory nodeA;

  private static LettuceConnectionFactory nodeB;

  @BeforeAll
  static void init() {
    nodeA = connect();
    nodeB = connect();
  }

  @AfterAll
  static void close() {
    nodeA.destroy();
    nodeB.destroy();
  }

  @BeforeEach
  void flush() {
    new StringRedisTemplate(nodeA).execute(c -> {
      c.serverCommands().flushAll();
      return null;
    }, true);
  }

  @Test
  void aFailureFollowedByASuccessIsStillShown() {
    this.aFailureFollowedByASuccessIsStillShown(new InMemoryFederationServiceStateStore());
  }

  @Test
  void aFailureFollowedByASuccessIsStillShownWithRedis() {
    this.aFailureFollowedByASuccessIsStillShown(new RedisFederationServiceStateStore(new StringRedisTemplate(nodeA),
        "test"));
  }

  @Test
  void theNodesSharingRedisReportTheSame() {
    final FederationServiceMonitor a =
        new FederationServiceMonitor(new RedisFederationServiceStateStore(new StringRedisTemplate(nodeA), "test"));
    final FederationServiceMonitor b =
        new FederationServiceMonitor(new RedisFederationServiceStateStore(new StringRedisTemplate(nodeB), "test"));

    a.onApplicationEvent(resolve(FederationCallEvent.Outcome.UNREACHABLE, "connection refused"));
    b.onApplicationEvent(resolve(FederationCallEvent.Outcome.ERROR_RESPONSE, "answered 500"));
    b.onApplicationEvent(new FederationCallEvent(FederationCallEvent.Call.TRUST_MARK_STATUS,
        "https://tmi.example.com/status", ISSUER, FederationCallEvent.Outcome.SUCCESS, null));

    assertThat(a.getStates()).isEqualTo(b.getStates());
    final FederationServiceState resolver = a.getStates().stream()
        .filter(s -> s.type() == FederationCallEvent.ServiceType.RESOLVER)
        .findFirst()
        .orElseThrow();
    assertThat(resolver.failuresSinceSuccess()).isEqualTo(2);
    assertThat(resolver.isFailing()).isTrue();
    assertThat(a.getStates()).filteredOn(s -> s.type() == FederationCallEvent.ServiceType.TRUST_MARK_ISSUER)
        .singleElement()
        .satisfies(s -> assertThat(s.id()).isEqualTo(ISSUER))
        .satisfies(s -> assertThat(s.isFailing()).isFalse())
        .satisfies(s -> assertThat(s.lastFailure()).isNull());

    new StringRedisTemplate(nodeA).opsForSet().add("test:oidc:federation-services", "test:oidc:gone", "test:bad");
    new StringRedisTemplate(nodeA).opsForHash().put("test:bad", "type", "NOT_A_TYPE");
    assertThat(a.getStates()).hasSize(2);
  }

  private void aFailureFollowedByASuccessIsStillShown(final FederationServiceStateStore store) {
    final FederationServiceMonitor monitor = new FederationServiceMonitor(store);
    assertThat(monitor.getStates()).isEmpty();

    monitor.onApplicationEvent(resolve(FederationCallEvent.Outcome.UNREACHABLE, "connection refused"));
    monitor.onApplicationEvent(resolve(FederationCallEvent.Outcome.ERROR_RESPONSE, "answered 500"));
    final FederationServiceState failing = monitor.getStates().getFirst();
    assertThat(failing.isFailing()).isTrue();
    assertThat(failing.failuresSinceSuccess()).isEqualTo(2);
    assertThat(failing.lastFailureOutcome()).isEqualTo(FederationCallEvent.Outcome.ERROR_RESPONSE);
    assertThat(failing.lastFailureError()).isEqualTo("answered 500");

    monitor.onApplicationEvent(resolve(FederationCallEvent.Outcome.SUCCESS, null));
    final List<FederationServiceState> states = monitor.getStates();
    assertThat(states).singleElement()
        .satisfies(s -> assertThat(s.isFailing()).isFalse())
        .satisfies(s -> assertThat(s.failuresSinceSuccess()).isZero())
        .satisfies(s -> assertThat(s.latestOutcome()).isEqualTo(FederationCallEvent.Outcome.SUCCESS))
        .satisfies(s -> assertThat(s.lastFailure()).isNotNull())
        .satisfies(s -> assertThat(s.lastFailureError()).isEqualTo("answered 500"))
        .satisfies(s -> assertThat(s.id()).isEqualTo(RESOLVE_ENDPOINT));
  }

  private static FederationCallEvent resolve(final FederationCallEvent.Outcome outcome, final String error) {
    return new FederationCallEvent(FederationCallEvent.Call.RESOLVE, RESOLVE_ENDPOINT, null, outcome, error);
  }

  private static LettuceConnectionFactory connect() {
    final LettuceConnectionFactory factory = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getFirstMappedPort()));
    factory.afterPropertiesSet();
    factory.start();
    return factory;
  }

}
