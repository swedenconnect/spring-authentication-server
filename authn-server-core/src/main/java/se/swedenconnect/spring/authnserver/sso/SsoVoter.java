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
 * Decides whether a previous authentication may be reused for the request at hand.
 * <p>
 * The voters of a provider are asked in order. One denial ends it, and at least one {@link SsoDecision#allow()} is
 * needed, so a request where every voter abstains gets no single sign-on. A voter is only asked once the rules that
 * always apply have been checked, so it can count on there being a previous authentication that may be reused.
 * </p>
 * <p>
 * Applications add voters of their own to refuse single sign-on in cases the library knows nothing about.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface SsoVoter {

  /**
   * Votes on whether the previous authentication may be reused.
   *
   * @param previousAuthentication the authentication that may be reused
   * @param requirements what the requester asks for
   * @param requester who is asking
   * @param allowedAuthnContexts the authentication contexts that may be used for this request
   * @return an {@link SsoDecision}
   */
  @Nonnull
  SsoDecision vote(@Nonnull final UserAuthentication previousAuthentication,
      @Nonnull final AuthenticationRequirements requirements, @Nonnull final Requester requester,
      @Nonnull final List<String> allowedAuthnContexts);

}
