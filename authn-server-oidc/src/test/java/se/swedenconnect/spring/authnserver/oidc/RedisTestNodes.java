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
package se.swedenconnect.spring.authnserver.oidc;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;

import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Support for the tests against a Redis container. Each node of a test has a connection of its own.
 *
 * @author Martin Lindström
 */
public final class RedisTestNodes {

  /**
   * Creates a Redis container.
   *
   * @return a {@link GenericContainer}
   */
  public static GenericContainer<?> container() {
    return new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);
  }

  /**
   * Connects to a Redis container.
   *
   * @param redis the container
   * @return a started {@link LettuceConnectionFactory}
   */
  public static LettuceConnectionFactory connect(final GenericContainer<?> redis) {
    final LettuceConnectionFactory factory = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(redis.getHost(), redis.getFirstMappedPort()));
    factory.afterPropertiesSet();
    factory.start();
    return factory;
  }

  /**
   * Removes everything from Redis.
   *
   * @param factory a connection factory
   */
  public static void flush(final LettuceConnectionFactory factory) {
    new StringRedisTemplate(factory).execute(c -> {
      c.serverCommands().flushAll();
      return null;
    }, true);
  }

  /**
   * Runs tasks at the same time, and counts the ones that give {@code true}.
   *
   * @param tasks the tasks
   * @return the number of tasks that gave {@code true}
   * @throws Exception for errors running the tasks
   */
  public static int countSuccesses(final List<Supplier<Boolean>> tasks) throws Exception {
    final CountDownLatch start = new CountDownLatch(1);
    final List<Callable<Boolean>> callables = new ArrayList<>();
    for (final Supplier<Boolean> task : tasks) {
      callables.add(() -> {
        start.await();
        return task.get();
      });
    }
    final ExecutorService executor = Executors.newFixedThreadPool(callables.size());
    try {
      final List<Future<Boolean>> results = callables.stream().map(executor::submit).toList();
      start.countDown();
      int successes = 0;
      for (final Future<Boolean> result : results) {
        successes += result.get() ? 1 : 0;
      }
      return successes;
    }
    finally {
      executor.shutdownNow();
    }
  }

  // Hidden constructor
  private RedisTestNodes() {
  }

}
