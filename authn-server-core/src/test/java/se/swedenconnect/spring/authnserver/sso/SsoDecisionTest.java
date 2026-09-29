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

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SsoDecision}, {@link SsoDenialReason} and {@link SsoDenialKind}.
 *
 * @author Martin Lindström
 */
class SsoDecisionTest {

  @Test
  void theThreeOutcomesAreDistinct() {
    assertThat(SsoDecision.allow().isAllowed()).isTrue();
    assertThat(SsoDecision.allow().isDenied()).isFalse();
    assertThat(SsoDecision.allow().reason()).isNull();

    assertThat(SsoDecision.abstain().isAllowed()).isFalse();
    assertThat(SsoDecision.abstain().isDenied()).isFalse();

    final SsoDecision denied = SsoDecision.deny(SsoDenialReason.NOT_REUSABLE);
    assertThat(denied.isDenied()).isTrue();
    assertThat(denied.isAllowed()).isFalse();
    assertThat(denied.reason()).isEqualTo(SsoDenialReason.NOT_REUSABLE);
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void aDenialMustStateItsReasonAndNoOtherVoteMay() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new SsoDecision(SsoDecision.Vote.DENY, null))
        .withMessage("A denial must state its reason");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new SsoDecision(SsoDecision.Vote.ALLOW, SsoDenialReason.NOT_REUSABLE))
        .withMessage("Only a denial may state a reason");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new SsoDecision(null, null))
        .withMessage("vote must not be null");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> SsoDecision.deny(null))
        .withMessage("reason must not be null");
  }

  @Test
  void onlyADifferentSetOfRequestedAttributesNeedsInteraction() {
    for (final SsoDenialReason reason : SsoDenialReason.values()) {
      assertThat(reason.getDescription()).isNotEmpty();
      if (reason == SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES) {
        assertThat(reason.getKind()).isEqualTo(SsoDenialKind.INTERACTION_REQUIRED);
      }
      else {
        assertThat(reason.getKind()).isEqualTo(SsoDenialKind.LOGIN_REQUIRED);
      }
    }
  }

}
