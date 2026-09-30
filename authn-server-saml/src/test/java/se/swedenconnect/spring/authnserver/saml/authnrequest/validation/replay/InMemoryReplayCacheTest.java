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

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link InMemoryReplayCache}.
 *
 * @author Martin Lindström
 */
class InMemoryReplayCacheTest {

  @Test
  void aKeyIsOnlyAcceptedOnceUntilItExpires() {
    final InMemoryReplayCache cache = new InMemoryReplayCache();
    final Instant expires = Instant.now().plusSeconds(60);
    assertThat(cache.check("ctx", "id-1", expires)).isTrue();
    assertThat(cache.check("ctx", "id-1", expires)).isFalse();
    assertThat(cache.check("other", "id-1", expires)).isTrue();
    assertThat(cache.check("ctx", "id-2", expires)).isTrue();
  }

  @Test
  void anExpiredKeyIsAcceptedAgain() {
    final InMemoryReplayCache cache = new InMemoryReplayCache();
    assertThat(cache.check("ctx", "id-1", Instant.now().minusSeconds(10))).isTrue();
    assertThat(cache.check("ctx", "id-1", Instant.now().plusSeconds(60))).isTrue();
  }

}
