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

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationUse;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Refuses single sign-on when the requester asks for another set of attributes than the original authentication was
 * made for. The OpenID Connect Profile for Sweden Connect, Section 2.2.1, requires {@code interaction_required} in that
 * case, which is why this refusal is of the {@link SsoDenialKind#INTERACTION_REQUIRED} kind.
 *
 * @author Martin Lindström
 */
public class RequestedAttributesSsoVoter implements SsoVoter {

  /** {@inheritDoc} */
  @Override
  public @Nonnull SsoDecision vote(final @Nonnull UserAuthentication previousAuthentication,
      final @Nonnull AuthenticationRequirements requirements, final @Nonnull Requester requester,
      final @Nonnull List<String> allowedAuthnContexts) {

    final AuthenticationUse original = previousAuthentication.getUsageTrack().getOriginalAuthentication();
    if (original == null) {
      return SsoDecision.abstain();
    }
    final Set<String> requestedNow = requirements.getRequestedAttributes().stream()
        .map(GenericRequestedAttribute::getIdentifier)
        .collect(Collectors.toSet());
    final Set<String> requestedOriginally = new HashSet<>(original.requestedAttributes());

    return requestedNow.equals(requestedOriginally)
        ? SsoDecision.abstain()
        : SsoDecision.deny(SsoDenialReason.OTHER_REQUESTED_ATTRIBUTES);
  }

}
