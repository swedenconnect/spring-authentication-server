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
package se.swedenconnect.spring.authnserver.config;

import org.jspecify.annotations.NonNull;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Adjusts the configuration of the authentication server. Declare any number of adapters as beans. They are invoked in
 * Spring's order, after the values from the configuration properties have been applied, and before the
 * {@link SecurityFilterChain} is built. An adapter may change any value, and its value is the one used.
 * <p>
 * The protocol configurers are reached from the shared configurer:
 * </p>
 *
 * <pre>{@code
 * @Bean
 * AuthnServerConfigurerAdapter adapter() {
 *   return (http, configurer) -> configurer
 *       .protocol(Saml2IdpConfigurer.class, saml -> saml.entityId("https://idp.example.com/saml"));
 * }
 * }</pre>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface AuthnServerConfigurerAdapter {

  /**
   * Adjusts the configuration.
   *
   * @param http the HTTP security object of the server's filter chain
   * @param configurer the shared configurer
   */
  void configure(final @NonNull HttpSecurity http, final @NonNull AuthnServerConfigurer configurer);

}
