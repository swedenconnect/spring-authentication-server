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

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link InMemoryLookupTracker}.
 *
 * @author Martin Lindström
 */
class InMemoryLookupTrackerTest extends FederationTestSupport {

  @Test
  void onlyClientsThatReachTheMinimumQualify() {
    final TestClock clock = new TestClock();
    final InMemoryLookupTracker tracker = new InMemoryLookupTracker(100, Duration.ofMinutes(10), clock);

    for (int i = 0; i < 5; i++) {
      tracker.record("frequent");
    }
    tracker.record("rare");

    assertThat(tracker.getFrequentClients(5, 10)).containsExactly("frequent");
    assertThat(tracker.getFrequentClients(6, 10)).isEmpty();
  }

  @Test
  void theMostAskedForClientComesFirstAndTheListIsCapped() {
    final InMemoryLookupTracker tracker = new InMemoryLookupTracker(100, Duration.ofMinutes(10), new TestClock());

    for (int i = 0; i < 10; i++) {
      tracker.record("one");
    }
    for (int i = 0; i < 5; i++) {
      tracker.record("two");
    }
    for (int i = 0; i < 3; i++) {
      tracker.record("three");
    }

    assertThat(tracker.getFrequentClients(3, 10)).containsExactly("one", "two", "three");
    assertThat(tracker.getFrequentClients(3, 2)).containsExactly("one", "two");
  }

  @Test
  void aClientThatGoesQuietForAWholePeriodStartsOver() {
    final TestClock clock = new TestClock();
    final InMemoryLookupTracker tracker = new InMemoryLookupTracker(100, Duration.ofMinutes(10), clock);

    for (int i = 0; i < 5; i++) {
      tracker.record("client");
    }
    assertThat(tracker.getFrequentClients(5, 10)).containsExactly("client");

    clock.advance(Duration.ofMinutes(11));
    assertThat(tracker.getFrequentClients(5, 10)).isEmpty();

    tracker.record("client");
    assertThat(tracker.getFrequentClients(1, 10)).containsExactly("client");
    assertThat(tracker.getFrequentClients(2, 10)).isEmpty();
  }

  @Test
  void theCountingDoesNotGrowWithoutLimit() {
    final InMemoryLookupTracker tracker = new InMemoryLookupTracker(10, Duration.ofMinutes(10), new TestClock());

    for (int i = 0; i < 1000; i++) {
      tracker.record("client-" + i);
    }

    assertThat(tracker.size()).isEqualTo(10);
    assertThat(tracker.getFrequentClients(1, 100)).contains("client-999").doesNotContain("client-0");
  }

  @Test
  void theLimitIsValidated() {
    assertThatThrownBy(() -> new InMemoryLookupTracker(0, Duration.ofMinutes(10)))
        .isInstanceOf(IllegalArgumentException.class);
  }

}
