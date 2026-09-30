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
package se.swedenconnect.spring.authnserver.authentication.provider;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Runs on an authentication result before it is turned into an assertion or a set of tokens, and asserts that the
 * authentication delivered what the request needed. A processor may also change the result, not only check it.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface PostAuthenticationProcessor {

  /**
   * Processes an authentication result.
   *
   * @param authentication the result to process
   * @throws AuthenticationErrorException if the result does not meet what the request needed
   */
  void process(final @NonNull UserAuthentication authentication) throws AuthenticationErrorException;

}
