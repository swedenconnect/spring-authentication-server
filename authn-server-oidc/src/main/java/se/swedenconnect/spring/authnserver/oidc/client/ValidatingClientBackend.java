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
package se.swedenconnect.spring.authnserver.oidc.client;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;

/**
 * A client registry backend whose clients are validated by a {@link ClientValidation} that the OpenID Provider
 * assigns when it is set up: the {@link ConfigurationClientBackend} and the {@link RepositoryClientBackend}. Until it
 * has been assigned, every client of the backend is marked as invalid, so that no client is served without
 * validation.
 *
 * @author Martin Lindström
 */
public interface ValidatingClientBackend extends ClientRegistryBackend, ClientKeyHolder {

  /**
   * The reason given for a client of a backend that has no {@link ClientValidation}.
   */
  String NOT_VALIDATED_REASON =
      "the client has not been validated, since the OpenID Provider has not set up its client source";

  /**
   * Assigns the validation of the clients, and validates the clients that the backend can list. The OpenID Provider
   * assigns it when it is set up. A fault in a client never makes this method fail.
   *
   * @param validation the validation
   */
  void setClientValidation(final @NonNull ClientValidation validation);

  /**
   * Gets the validation of the clients.
   *
   * @return the validation, or {@code null} if it has not been assigned
   */
  @Nullable ClientValidation getClientValidation();

  /**
   * Reads the keys of the validated clients again, and validates again the clients whose metadata has changed or whose
   * temporary mark has run out. It is called by the {@link ClientKeysRefresher}. Nothing is done when the validation
   * has not been assigned.
   */
  void refreshClients();

}
