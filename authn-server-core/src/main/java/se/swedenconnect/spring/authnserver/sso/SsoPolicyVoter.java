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

import jakarta.annotation.Nonnull;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationUse;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Applies the configured {@link SsoPolicy}: whether single sign-on is allowed at all, how old the previous
 * authentication may be, and whether it may be reused for another requester than the one it was made for.
 * <p>
 * The policy is read for every request, so a change to it takes effect immediately.
 * </p>
 *
 * @author Martin Lindström
 */
public class SsoPolicyVoter implements SsoVoter {

  /** Where the policy comes from. */
  private final Supplier<SsoPolicy> policySupplier;

  /**
   * Constructor.
   *
   * @param policySupplier where the policy comes from, asked for every request
   */
  public SsoPolicyVoter(final @Nonnull Supplier<SsoPolicy> policySupplier) {
    this.policySupplier = Objects.requireNonNull(policySupplier, "policySupplier must not be null");
  }

  /**
   * Constructor for a fixed policy.
   *
   * @param policy the policy
   */
  public SsoPolicyVoter(final @Nonnull SsoPolicy policy) {
    this(() -> Objects.requireNonNull(policy, "policy must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull SsoDecision vote(final @Nonnull UserAuthentication previousAuthentication,
      final @Nonnull AuthenticationRequirements requirements, final @Nonnull Requester requester,
      final @Nonnull List<String> allowedAuthnContexts) {

    final SsoPolicy policy = this.policySupplier.get();
    if (!policy.isEnabled()) {
      return SsoDecision.deny(SsoDenialReason.NOT_ALLOWED);
    }

    final AuthenticationUse original = previousAuthentication.getUsageTrack().getOriginalAuthentication();

    final Duration timeLimit = policy.getTimeLimit();
    if (timeLimit != null) {
      final Instant instant = original != null
          ? original.instant()
          : previousAuthentication.getAuthenticatedUser().getAuthnInstant();
      if (instant.plus(timeLimit).isBefore(Instant.now())) {
        return SsoDecision.deny(SsoDenialReason.TIME_LIMIT_EXCEEDED);
      }
    }

    // A result that has not been used yet says nothing about which requester it was made for, so the rule cannot
    // refuse it.
    if (policy.isSameRequesterRequired() && original != null && !requester.matches(original)) {
      return SsoDecision.deny(SsoDenialReason.OTHER_REQUESTER);
    }

    return SsoDecision.allow();
  }

}
