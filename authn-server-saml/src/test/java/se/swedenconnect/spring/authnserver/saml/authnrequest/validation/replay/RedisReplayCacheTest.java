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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
 * Tests for {@link RedisReplayCache}, against a Redis container. Each cache has its own connection, as two nodes
 * would.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisReplayCacheTest {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

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
  void anIdIsAcceptedOnceAcrossNodes() {
    final RedisReplayCache a = new RedisReplayCache(new StringRedisTemplate(nodeA), "test");
    final RedisReplayCache b = new RedisReplayCache(new StringRedisTemplate(nodeB), "test");
    final Instant expires = Instant.now().plusSeconds(60);

    assertThat(a.check("ctx", "_id1", expires)).isTrue();
    assertThat(b.check("ctx", "_id1", expires)).isFalse();
    assertThat(a.check("ctx", "_id1", expires)).isFalse();
    assertThat(b.check("other", "_id1", expires)).isTrue();
    assertThat(b.check("ctx", "_id2", expires)).isTrue();
  }

  @Test
  void theEntryExpiresWithTheId() throws Exception {
    final StringRedisTemplate template = new StringRedisTemplate(nodeA);
    final RedisReplayCache cache = new RedisReplayCache(template, "test");

    assertThat(cache.check("ctx", "_id1", Instant.now().plusSeconds(60))).isTrue();
    assertThat(template.getExpire("test:saml:replay:ctx:_id1")).isPositive().isLessThanOrEqualTo(60);

    assertThat(cache.check("ctx", "_id2", Instant.now().plusMillis(300))).isTrue();
    Thread.sleep(400);
    assertThat(template.hasKey("test:saml:replay:ctx:_id2")).isFalse();
    assertThat(cache.check("ctx", "_id2", Instant.now().plusSeconds(60))).isTrue();
  }

  @Test
  void theDefaultPrefixIsUsed() {
    final StringRedisTemplate template = new StringRedisTemplate(nodeA);
    assertThat(new RedisReplayCache(template).check("ctx", "_id1", Instant.now().plusSeconds(60))).isTrue();
    assertThat(template.hasKey("authn-server:saml:replay:ctx:_id1")).isTrue();
  }

  @Test
  void concurrentChecksFromTwoNodesSucceedOnce() throws Exception {
    final List<RedisReplayCache> caches = List.of(
        new RedisReplayCache(new StringRedisTemplate(nodeA), "test"),
        new RedisReplayCache(new StringRedisTemplate(nodeB), "test"));
    final Instant expires = Instant.now().plusSeconds(60);
    final CountDownLatch start = new CountDownLatch(1);
    final List<Callable<Boolean>> tasks = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      final RedisReplayCache cache = caches.get(i % 2);
      tasks.add(() -> {
        start.await();
        return cache.check("ctx", "_same", expires);
      });
    }
    final ExecutorService executor = Executors.newFixedThreadPool(tasks.size());
    try {
      final List<Future<Boolean>> results = tasks.stream().map(executor::submit).toList();
      start.countDown();
      int accepted = 0;
      for (final Future<Boolean> result : results) {
        accepted += result.get() ? 1 : 0;
      }
      assertThat(accepted).isEqualTo(1);
    }
    finally {
      executor.shutdownNow();
    }
  }

  @Test
  void invalidArguments() {
    assertThatThrownBy(() -> new RedisReplayCache(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RedisReplayCache(new StringRedisTemplate(nodeA), ""))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static LettuceConnectionFactory connect() {
    final LettuceConnectionFactory factory = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getFirstMappedPort()));
    factory.afterPropertiesSet();
    factory.start();
    return factory;
  }

}
