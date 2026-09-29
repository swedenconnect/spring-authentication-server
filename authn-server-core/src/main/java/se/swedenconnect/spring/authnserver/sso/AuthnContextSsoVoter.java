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

import java.util.List;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Requires that the previous authentication was made under an authentication context that is acceptable for this
 * request. The Deployment Profile for the Swedish eID Framework, Section 5.4.5, forbids reusing an authentication that
 * was made at another level of assurance than the one now asked for.
 *
 * @author Martin Lindström
 */
public class AuthnContextSsoVoter implements SsoVoter {

  /** {@inheritDoc} */
  @Override
  public @Nonnull SsoDecision vote(final @Nonnull UserAuthentication previousAuthentication,
      final @Nonnull AuthenticationRequirements requirements, final @Nonnull Requester requester,
      final @Nonnull List<String> allowedAuthnContexts) {
    return allowedAuthnContexts.contains(previousAuthentication.getAuthenticatedUser().getAuthnContextUri())
        ? SsoDecision.allow()
        : SsoDecision.deny(SsoDenialReason.OTHER_AUTHN_CONTEXT);
  }

}
