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
package se.swedenconnect.spring.authnserver.redis;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * Tests for {@link RedisKnownClientStore}, against a Redis container. Two nodes, each with its own connection and
 * tracker, share the record.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisKnownClientStoreTest {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private static final String SOURCE = "https://md.example.com/sp.xml";

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
  void eachChangeGivesOneEventForTheDeployment() {
    final List<ApplicationEvent> events = new ArrayList<>();
    final ClientChangeTracker a = tracker(nodeA, events);
    final ClientChangeTracker b = tracker(nodeB, events);

    a.sourceLoaded(AuthenticationProtocol.SAML, SOURCE, List.of(sp("one"), sp("two")));
    b.sourceLoaded(AuthenticationProtocol.SAML, SOURCE, List.of(sp("one"), sp("two")));
    assertThat(events).hasSize(2).allMatch(ClientAddedEvent.class::isInstance);
    events.clear();

    a.sourceLoaded(AuthenticationProtocol.SAML, SOURCE, List.of(sp("two"), sp("three")));
    b.sourceLoaded(AuthenticationProtocol.SAML, SOURCE, List.of(sp("two"), sp("three")));
    assertThat(events).hasSize(2);
    assertThat(events).filteredOn(ClientAddedEvent.class::isInstance)
        .extracting(e -> ((ClientAddedEvent) e).getClient().identifier())
        .containsExactly("three");
    assertThat(events).filteredOn(ClientRemovedEvent.class::isInstance)
        .extracting(e -> ((ClientRemovedEvent) e).getClient())
        .containsExactly(sp("one"));
  }

  @Test
  void addRemoveUpdateAndList() {
    final RedisKnownClientStore store = new RedisKnownClientStore(new StringRedisTemplate(nodeA), "test");
    assertThat(store.addAll(List.of())).isEmpty();
    assertThat(store.removeAll(List.of())).isEmpty();
    assertThat(store.addAll(List.of(sp("one"), sp("two")))).hasSize(2);
    assertThat(store.addAll(List.of(sp("one")))).isEmpty();
    store.update(sp("one").withSource("other"));
    assertThat(store.getAll()).hasSize(2).contains(sp("one").withSource("other"));
    assertThat(store.removeAll(List.of(new Requester(AuthenticationProtocol.SAML, "one"),
        new Requester(AuthenticationProtocol.SAML, "unknown")))).containsExactly(sp("one").withSource("other"));
    assertThat(store.getAll()).containsExactly(sp("two"));

    new StringRedisTemplate(nodeA).opsForHash().put("test:known-clients", "SAML|bad", "not json");
    assertThat(store.getAll()).containsExactly(sp("two"));
  }

  private static ClientChangeTracker tracker(final LettuceConnectionFactory node, final List<ApplicationEvent> events) {
    final ClientChangeTracker tracker =
        new ClientChangeTracker(new RedisKnownClientStore(new StringRedisTemplate(node), "test"));
    tracker.setApplicationEventPublisher(e -> events.add((ApplicationEvent) e));
    tracker.start();
    return tracker;
  }

  private static KnownClient sp(final String id) {
    return new KnownClient(new Requester(AuthenticationProtocol.SAML, id), null, SOURCE);
  }

  private static LettuceConnectionFactory connect() {
    final LettuceConnectionFactory factory = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getFirstMappedPort()));
    factory.afterPropertiesSet();
    factory.start();
    return factory;
  }

}
