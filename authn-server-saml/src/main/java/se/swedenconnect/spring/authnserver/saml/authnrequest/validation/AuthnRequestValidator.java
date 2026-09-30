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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Validates one aspect of a received authentication request.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface AuthnRequestValidator {

  /**
   * Validates the authentication request.
   *
   * @param token the authentication request token
   * @throws UnrecoverableErrorException for errors that cannot be reported to the Service Provider
   * @throws SamlErrorStatusException for errors that are reported to the Service Provider
   */
  void validate(final @NonNull Saml2AuthnRequestAuthenticationToken token)
      throws UnrecoverableErrorException, SamlErrorStatusException;

}
