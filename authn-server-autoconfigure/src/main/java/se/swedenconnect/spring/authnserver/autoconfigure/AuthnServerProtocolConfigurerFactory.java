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

import jakarta.annotation.Nonnull;

import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;

/**
 * Creates the configurer of one protocol from its configuration properties. The autoconfiguration of each enabled
 * protocol declares one as a bean, and the configurers are registered with the {@link AuthnServerConfigurer} before any
 * {@link se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter AuthnServerConfigurerAdapter} is
 * invoked.
 * <p>
 * This is internal to the autoconfiguration. Applications adjust the configuration with adapters.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface AuthnServerProtocolConfigurerFactory {

  /**
   * Creates the protocol configurer.
   *
   * @param server the shared configurer, holding the values from the shared properties
   * @return the protocol configurer
   * @throws Exception for errors creating the configurer, for example loading credentials
   */
  @Nonnull
  AbstractProtocolConfigurer<?> createConfigurer(final @Nonnull AuthnServerConfigurer server) throws Exception;

}
