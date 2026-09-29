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
package se.swedenconnect.spring.authnserver.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SsoPolicy}.
 *
 * @author Martin Lindström
 */
class SsoPolicyTest {

  @Test
  void theDefaultPolicyIsSixtyMinutesForTheSameRequester() {
    final SsoPolicy policy = SsoPolicy.defaultPolicy();
    assertThat(policy.isEnabled()).isTrue();
    assertThat(policy.getTimeLimit()).isEqualTo(Duration.ofMinutes(60));
    assertThat(policy.isSameRequesterRequired()).isTrue();
    assertThat(new SsoPolicy()).usingRecursiveComparison().isEqualTo(policy);
    assertThat(policy.toString()).contains("enabled=true", "same-requester-required=true");
  }

  @Test
  void singleSignOnCanBeTurnedOffCompletely() {
    assertThat(SsoPolicy.none().isEnabled()).isFalse();
  }

  @Test
  void singleSignOnCanLastForTheSessionAndAcrossRequesters() {
    final SsoPolicy policy = SsoPolicy.forSessionLifetime();
    assertThat(policy.isEnabled()).isTrue();
    assertThat(policy.getTimeLimit()).isNull();
    assertThat(policy.isSameRequesterRequired()).isFalse();
    assertThat(policy.toString()).contains("time-limit=none");
  }

  @Test
  void theTimeLimitAndTheSameRequesterRuleAreConfigurable() {
    final SsoPolicy policy = new SsoPolicy();
    policy.setTimeLimit(Duration.ofMinutes(5));
    policy.setSameRequesterRequired(false);
    assertThat(policy.getTimeLimit()).isEqualTo(Duration.ofMinutes(5));
    assertThat(policy.isSameRequesterRequired()).isFalse();
  }

  @Test
  void aTimeLimitThatIsNotPositiveIsRejected() {
    final SsoPolicy policy = new SsoPolicy();
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> policy.setTimeLimit(Duration.ZERO))
        .withMessage("timeLimit must be positive");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> policy.setTimeLimit(Duration.ofSeconds(-1)))
        .withMessage("timeLimit must be positive");
  }

}
