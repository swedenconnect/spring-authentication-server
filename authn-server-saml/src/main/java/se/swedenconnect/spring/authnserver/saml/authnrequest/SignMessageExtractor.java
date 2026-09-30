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
package se.swedenconnect.spring.authnserver.saml.authnrequest;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Extracts the {@code SignMessage} extension of an authentication request into a {@link GenericSignMessage}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface SignMessageExtractor {

  /**
   * Extracts the sign message.
   *
   * @param token the authentication request token
   * @return the sign message, or {@code null} if the request has none, or one that is to be ignored
   * @throws SamlErrorStatusException if the sign message is invalid or cannot be decrypted
   */
  @Nullable GenericSignMessage extract(final @NonNull Saml2AuthnRequestAuthenticationToken token)
      throws SamlErrorStatusException;

}
