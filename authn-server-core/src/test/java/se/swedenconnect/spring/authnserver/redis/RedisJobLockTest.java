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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
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
 * Tests for {@link RedisJobLock}, against a Redis container. Each lock has its own connection, as two nodes would.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisJobLockTest {

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
    template(nodeA).execute(c -> {
      c.serverCommands().flushAll();
      return null;
    }, true);
  }

  @Test
  void onlyOneNodeGetsTheLockAndTheHolderMayRenewIt() {
    final RedisJobLock a = new RedisJobLock(template(nodeA), "test");
    final RedisJobLock b = new RedisJobLock(template(nodeB), "test");

    assertThat(a.tryAcquire("job", Duration.ofMinutes(1))).isTrue();
    assertThat(b.tryAcquire("job", Duration.ofMinutes(1))).isFalse();
    assertThat(a.tryAcquire("job", Duration.ofMinutes(1))).isTrue();
    assertThat(b.tryAcquire("other-job", Duration.ofMinutes(1))).isTrue();

    assertThat(template(nodeA).hasKey("test:lock:job")).isTrue();
    assertThat(template(nodeA).getExpire("test:lock:job")).isPositive().isLessThanOrEqualTo(60);
  }

  @Test
  void aLockHeldByAStoppedNodeIsReleasedWhenItsLeaseHasPassed() throws Exception {
    final RedisJobLock stopped = new RedisJobLock(template(nodeA), "test");
    final RedisJobLock other = new RedisJobLock(template(nodeB), "test");

    assertThat(stopped.tryAcquire("job", Duration.ofMillis(300))).isTrue();
    assertThat(other.tryAcquire("job", Duration.ofMillis(300))).isFalse();
    Thread.sleep(400);
    assertThat(other.tryAcquire("job", Duration.ofMillis(300))).isTrue();
    assertThat(stopped.tryAcquire("job", Duration.ofMillis(300))).isFalse();
  }

  @Test
  void whenNodesAskAtTheSameTimeOnlyOneGetsTheLock() throws Exception {
    final List<RedisJobLock> locks = List.of(
        new RedisJobLock(template(nodeA), "test"), new RedisJobLock(template(nodeB), "test"),
        new RedisJobLock(template(nodeA), "test"), new RedisJobLock(template(nodeB), "test"));
    final CountDownLatch start = new CountDownLatch(1);
    final List<Callable<Boolean>> tasks = new ArrayList<>();
    for (final RedisJobLock lock : locks) {
      tasks.add(() -> {
        start.await();
        return lock.tryAcquire("job", Duration.ofMinutes(1));
      });
    }
    final ExecutorService executor = Executors.newFixedThreadPool(locks.size());
    try {
      final List<Future<Boolean>> results = tasks.stream().map(executor::submit).toList();
      start.countDown();
      int granted = 0;
      for (final Future<Boolean> result : results) {
        granted += result.get() ? 1 : 0;
      }
      assertThat(granted).isEqualTo(1);
    }
    finally {
      executor.shutdownNow();
    }
  }

  @Test
  void invalidArguments() {
    assertThatThrownBy(() -> new RedisJobLock(null, "test")).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RedisJobLock(template(nodeA), " ")).isInstanceOf(IllegalArgumentException.class);
    final RedisJobLock lock = new RedisJobLock(template(nodeA), "test");
    assertThatThrownBy(() -> lock.tryAcquire("job", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
  }

  private static LettuceConnectionFactory connect() {
    final LettuceConnectionFactory factory = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getFirstMappedPort()));
    factory.afterPropertiesSet();
    factory.start();
    return factory;
  }

  private static StringRedisTemplate template(final LettuceConnectionFactory factory) {
    return new StringRedisTemplate(factory);
  }

}
