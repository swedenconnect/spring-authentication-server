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

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.ClassUtils;

import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientStore;

/**
 * Autoconfiguration for the authentication server. It checks that at least one protocol has been enabled, and sets up
 * the one {@link SecurityFilterChain} of the server.
 * <p>
 * The chain is built from an {@link AuthnServerConfigurer} holding the values of the shared properties, the configurers
 * of the enabled protocols, and every {@link UserAuthenticationProvider} bean. After that, every
 * {@link AuthnServerConfigurerAdapter} bean is invoked in Spring's order.
 * </p>
 * <p>
 * A {@link ClientChangeTracker} is given to the configurer, so that clients that appear in or disappear from the
 * client registry are reported, and the configured server is made available in a {@link ConfiguredAuthnServer} bean.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration(
    afterName = { "se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration",
        "se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration" },
    beforeName = "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration")
@EnableConfigurationProperties(AuthnServerConfigurationProperties.class)
public class AuthnServerAutoConfiguration {

  /** The class that tells whether the SAML module is on the classpath. */
  static final String SAML_MODULE_CLASS = "se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer";

  /** The class that tells whether the OIDC module is on the classpath. */
  static final String OIDC_MODULE_CLASS = "se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry";

  /**
   * Constructor checking that at least one protocol is enabled, and that the module of each enabled protocol is on the
   * classpath.
   *
   * @param environment the environment
   * @param resourceLoader gives the class loader of the application
   * @throws IllegalStateException if the protocol configuration is invalid
   */
  public AuthnServerAutoConfiguration(final @NonNull Environment environment,
      final @NonNull ResourceLoader resourceLoader) {
    final Binder binder = Binder.get(environment);
    final boolean samlEnabled = binder.bind("authn-server.saml.enabled", Boolean.class).orElse(false);
    final boolean oidcEnabled = binder.bind("authn-server.oidc.enabled", Boolean.class).orElse(false);

    if (!samlEnabled && !oidcEnabled) {
      throw new IllegalStateException("No protocol is enabled for the authentication server - "
          + "set authn-server.saml.enabled and/or authn-server.oidc.enabled to true");
    }
    final ClassLoader classLoader = resourceLoader.getClassLoader();
    if (samlEnabled && !ClassUtils.isPresent(SAML_MODULE_CLASS, classLoader)) {
      throw new IllegalStateException(
          "authn-server.saml.enabled is true, but the authn-server-saml module is not on the classpath");
    }
    if (oidcEnabled && !ClassUtils.isPresent(OIDC_MODULE_CLASS, classLoader)) {
      throw new IllegalStateException(
          "authn-server.oidc.enabled is true, but the authn-server-oidc module is not on the classpath");
    }
  }

  /**
   * Creates the object that gives access to the configured server.
   *
   * @return a {@link ConfiguredAuthnServer}
   */
  @Bean
  @ConditionalOnMissingBean
  ConfiguredAuthnServer configuredAuthnServer() {
    return new ConfiguredAuthnServer();
  }

  /**
   * Creates the tracker of clients that appear in and disappear from the client registry.
   *
   * @param store the record of known clients, if declared as a bean
   * @return a {@link ClientChangeTracker}
   */
  @Bean
  @ConditionalOnMissingBean
  ClientChangeTracker authnServerClientChangeTracker(final ObjectProvider<KnownClientStore> store) {
    return new ClientChangeTracker(store.getIfUnique(InMemoryKnownClientStore::new));
  }

  /**
   * Sets up the security filter chain of the server.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @EnableWebSecurity
  public static class SecurityFilterChainConfiguration {

    /** The name of the security filter chain bean. */
    public static final String FILTER_CHAIN_BEAN_NAME = "authnServerSecurityFilterChain";

    /**
     * Creates the security filter chain of the server.
     *
     * @param http the HTTP security object
     * @param properties the shared properties
     * @param providers the authentication providers
     * @param protocolFactories the factories for the configurers of the enabled protocols
     * @param adapters the adapters
     * @param tracker the tracker of client changes, if declared as a bean
     * @param configuredServer gets the configured server, if declared as a bean
     * @return a {@link SecurityFilterChain}
     * @throws Exception for configuration errors
     */
    @Bean(FILTER_CHAIN_BEAN_NAME)
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @ConditionalOnMissingBean(name = FILTER_CHAIN_BEAN_NAME)
    SecurityFilterChain authnServerSecurityFilterChain(final HttpSecurity http,
        final AuthnServerConfigurationProperties properties,
        final ObjectProvider<UserAuthenticationProvider> providers,
        final ObjectProvider<AuthnServerProtocolConfigurerFactory> protocolFactories,
        final ObjectProvider<AuthnServerConfigurerAdapter> adapters,
        final ObjectProvider<ClientChangeTracker> tracker,
        final ObjectProvider<ConfiguredAuthnServer> configuredServer) throws Exception {

      final AuthnServerConfigurer configurer = new AuthnServerConfigurer();
      properties.applyTo(configurer);
      configurer.clientChangeTracker(tracker.getIfUnique());
      providers.orderedStream().forEach(configurer::authenticationProvider);
      for (final AuthnServerProtocolConfigurerFactory factory : protocolFactories.orderedStream().toList()) {
        configurer.protocol(factory.createConfigurer(configurer));
      }

      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);

      for (final AuthnServerConfigurerAdapter adapter : adapters.orderedStream().toList()) {
        adapter.configure(http, configurer);
      }
      final SecurityFilterChain chain = http.build();
      configuredServer.ifAvailable(c -> c.setConfigurer(configurer));
      return chain;
    }

  }

}
