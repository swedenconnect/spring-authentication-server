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
package se.swedenconnect.spring.authnserver.autoconfigure;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;

/**
 * Gives access to the authentication server as it has been configured, for management such as the Actuator support.
 * <p>
 * The server is configured when its security filter chain is built, and the autoconfiguration assigns the configurer
 * here once that is done. An application that builds the filter chain itself assigns it with
 * {@link #setConfigurer(AuthnServerConfigurer)}.
 * </p>
 *
 * @author Martin Lindström
 */
public class ConfiguredAuthnServer {

  /** The configurer, or {@code null} until the server has been configured. */
  private volatile AuthnServerConfigurer configurer;

  /**
   * Assigns the configurer of the server, after the security filter chain has been built.
   *
   * @param configurer the configurer
   */
  public void setConfigurer(final @Nullable AuthnServerConfigurer configurer) {
    this.configurer = configurer;
  }

  /**
   * Gets the configurer of the server.
   *
   * @return the configurer, or {@code null} if the server has not been configured
   */
  public @Nullable AuthnServerConfigurer getConfigurer() {
    return this.configurer;
  }

  /**
   * Gets the client registry of the server.
   *
   * @return the client registry, or {@code null} if the server has not been configured
   */
  public @Nullable ClientRegistry getClientRegistry() {
    final AuthnServerConfigurer current = this.configurer;
    return current != null ? current.getClientRegistry() : null;
  }

  /**
   * Gets the backends of the client registry of the server.
   *
   * @return the backends, empty if the server has not been configured
   */
  public @NonNull List<ClientRegistryBackend> getClientRegistryBackends() {
    final ClientRegistry registry = this.getClientRegistry();
    return registry != null ? registry.getBackends() : List.of();
  }

  /**
   * Gets the backends of the client registry of a given type.
   *
   * @param type the type
   * @param <T> the type
   * @return the backends of the type
   */
  public <T extends ClientRegistryBackend> @NonNull List<T> getClientRegistryBackends(final @NonNull Class<T> type) {
    return this.getClientRegistryBackends().stream()
        .filter(type::isInstance)
        .map(type::cast)
        .toList();
  }

}
