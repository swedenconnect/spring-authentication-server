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
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.job.JobLock;

/**
 * Tests for {@link RedisJson}, {@link RedisKeys} and {@link JobLock#LOCAL}.
 *
 * @author Martin Lindström
 */
class RedisSupportTest {

  record Sample(String name, Instant at, List<String> values, int count) {
  }

  record OlderSample(String name, Instant at) {
  }

  @Test
  void anEntryIsWrittenAndReadBack() {
    final Sample sample = new Sample("a", Instant.parse("2026-10-01T10:00:00Z"), List.of("x", "y"), 3);
    final String json = RedisJson.write(sample);
    assertThat(json).contains("\"name\":\"a\"");
    assertThat(RedisJson.read("key", json, Sample.class)).isEqualTo(sample);
  }

  @Test
  void anEntryWrittenByAnotherVersionIsRead() {
    // A property that the class does not know is ignored
    final Sample newer = new Sample("a", Instant.parse("2026-10-01T10:00:00Z"), List.of("x"), 3);
    assertThat(RedisJson.read("key", RedisJson.write(newer), OlderSample.class))
        .isEqualTo(new OlderSample("a", Instant.parse("2026-10-01T10:00:00Z")));

    // A property that is missing gets its default value
    final OlderSample older = new OlderSample("a", Instant.parse("2026-10-01T10:00:00Z"));
    assertThat(RedisJson.read("key", RedisJson.write(older), Sample.class))
        .isEqualTo(new Sample("a", Instant.parse("2026-10-01T10:00:00Z"), null, 0));
  }

  @Test
  void anEntryThatCannotBeReadIsMissing() {
    assertThat(RedisJson.read("key", null, Sample.class)).isNull();
    assertThat(RedisJson.read("key", "not json", Sample.class)).isNull();
    assertThat(RedisJson.read("key", "[1,2]", Sample.class)).isNull();
  }

  @Test
  void timeToLiveIsAtLeastOneMillisecond() {
    final Instant now = Instant.parse("2026-10-01T10:00:00Z");
    assertThat(RedisKeys.timeToLive(now.plusSeconds(60), now)).isEqualTo(Duration.ofSeconds(60));
    assertThat(RedisKeys.timeToLive(now, now)).isEqualTo(Duration.ofMillis(1));
    assertThat(RedisKeys.timeToLive(now.minusSeconds(60), now)).isEqualTo(Duration.ofMillis(1));
  }

  @Test
  void thePrefixMustBeSet() {
    assertThat(RedisKeys.checkPrefix("p")).isEqualTo("p");
    assertThatThrownBy(() -> RedisKeys.checkPrefix(null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> RedisKeys.checkPrefix("")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theLocalLockIsAlwaysGranted() {
    assertThat(JobLock.LOCAL.tryAcquire("job", Duration.ofMinutes(1))).isTrue();
    assertThat(JobLock.LOCAL.tryAcquire("job", Duration.ofMinutes(1))).isTrue();
  }

}
