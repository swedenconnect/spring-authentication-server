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
package se.swedenconnect.spring.authnserver.service.config;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.thymeleaf.spring6.SpringTemplateEngine;

import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.oidc.client.ConfigurationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;
import se.swedenconnect.spring.authnserver.service.authn.SimulatedAuthenticationProvider;
import se.swedenconnect.spring.authnserver.service.message.MessageHtmlConverter;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUser;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUsers;

/**
 * The configuration of the reference: the simulated authentication, its pages, the OpenID Connect clients, and the
 * security of everything that is not an endpoint of the server.
 *
 * @author Martin Lindström
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ AuthnProperties.class, UiProperties.class, ReferenceProperties.class,
    TomcatAjpProperties.class })
public class ReferenceConfiguration {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ReferenceConfiguration.class);

  /** The name of the cookie that remembers the last selected user and level of assurance. */
  public static final String SELECTED_USER_COOKIE = "selectedUser";

  /** The name of the cookie that holds the users that the tester has added. */
  public static final String SAVED_USERS_COOKIE = "savedUsers";

  /** How long the cookies of the user picker are kept. */
  private static final Duration COOKIE_MAX_AGE = Duration.ofDays(365);

  /** The settings of the simulated authentication. */
  private final AuthnProperties authn;

  /** The servlet context path. */
  private final String contextPath;

  /**
   * Constructor.
   *
   * @param authn the settings of the simulated authentication
   * @param contextPath the servlet context path
   */
  public ReferenceConfiguration(final @NonNull AuthnProperties authn,
      @Value("${server.servlet.context-path:}") final @NonNull String contextPath) {
    this.authn = Objects.requireNonNull(authn, "authn must not be null");
    this.contextPath = contextPath;
  }

  /**
   * Creates the simulated users from the {@code users} setting, which {@code users.yml} gives.
   *
   * @param environment the environment
   * @return the {@link SimulatedUsers}
   */
  @Bean
  SimulatedUsers simulatedUsers(final @NonNull Environment environment) {
    final List<SimulatedUser> users = Binder.get(environment)
        .bind("users", Bindable.listOf(SimulatedUser.class))
        .orElse(List.of());
    log.info("Loaded {} simulated users", users.size());
    return new SimulatedUsers(users);
  }

  /**
   * Creates the authentication provider of the simulated authentication.
   *
   * @return the {@link SimulatedAuthenticationProvider}
   */
  @Bean
  SimulatedAuthenticationProvider simulatedAuthenticationProvider() {
    return new SimulatedAuthenticationProvider(this.authn.getProviderName(), this.authn.getAuthnPath(),
        this.authn.getResumePath(), this.authn.getSupportedLoas(), this.authn.getEntityCategories());
  }

  /**
   * Creates the converter of sign messages and user messages into HTML.
   *
   * @return the {@link MessageHtmlConverter}
   */
  @Bean
  MessageHtmlConverter messageHtmlConverter() {
    return new MessageHtmlConverter();
  }

  /**
   * Creates the cookie that remembers the last selected user and level of assurance.
   *
   * @return a {@link CookieGenerator}
   */
  @Bean(SELECTED_USER_COOKIE)
  CookieGenerator selectedUserCookie() {
    return new CookieGenerator(SELECTED_USER_COOKIE, this.contextPath, COOKIE_MAX_AGE);
  }

  /**
   * Creates the cookie that holds the users that the tester has added.
   *
   * @return a {@link CookieGenerator}
   */
  @Bean(SAVED_USERS_COOKIE)
  CookieGenerator savedUsersCookie() {
    return new CookieGenerator(SAVED_USERS_COOKIE, this.contextPath, COOKIE_MAX_AGE);
  }

  /**
   * Creates the page that posts responses to the requesters.
   *
   * @param templateEngine the template engine
   * @return the {@link ThymeleafResponsePage}
   */
  @Bean
  ThymeleafResponsePage responsePage(final @NonNull SpringTemplateEngine templateEngine) {
    return new ThymeleafResponsePage(templateEngine, "post-response");
  }

  /**
   * Adjusts the server: the response page of both protocols, and the statically configured OpenID Connect clients.
   *
   * @param responsePage the response page
   * @param properties the settings of the reference
   * @return an {@link AuthnServerConfigurerAdapter}
   */
  @Bean
  AuthnServerConfigurerAdapter referenceAdapter(final @NonNull ThymeleafResponsePage responsePage,
      final @NonNull ReferenceProperties properties) {
    return (http, configurer) -> {
      final Saml2IdpConfigurer saml = configurer.getProtocolConfigurer(Saml2IdpConfigurer.class);
      if (saml != null) {
        saml.authnRequestProcessor(p -> p.responsePage(responsePage));
      }
      final OidcProviderConfigurer oidc = configurer.getProtocolConfigurer(OidcProviderConfigurer.class);
      if (oidc != null) {
        oidc.authnRequestProcessor(p -> p.responsePage(responsePage));
        final List<OidcClientRecord> clients = OidcClientLoader.load(properties.getOidc().getClients());
        configurer.clientRegistryBackend(new ConfigurationClientBackend(clients));
        log.info("Configured {} OpenID Connect client(s)", clients.size());
      }
    };
  }

  /**
   * Creates the view resolver for errors that cannot be reported back to the requester.
   *
   * @return an {@link UnrecoverableErrorViewResolver}
   */
  @Bean
  UnrecoverableErrorViewResolver unrecoverableErrorViewResolver() {
    return new UnrecoverableErrorViewResolver();
  }

  /**
   * Adds the Tomcat AJP connector, when {@code tomcat.ajp.enabled} is {@code true}.
   *
   * @param ajp the AJP settings
   * @return a {@link TomcatAjpCustomizer}
   */
  @Bean
  @ConditionalOnProperty(name = "tomcat.ajp.enabled", havingValue = "true")
  TomcatAjpCustomizer tomcatAjpCustomizer(final @NonNull TomcatAjpProperties ajp) {
    return new TomcatAjpCustomizer(ajp);
  }

  /**
   * The security of everything that the server's own filter chain does not cover: the user picker, the static
   * resources, the error page and the Actuator endpoints are open, and everything else is denied.
   *
   * @param http the HTTP security object
   * @return a {@link SecurityFilterChain}
   * @throws Exception for configuration errors
   */
  @Bean
  @Order(2)
  SecurityFilterChain referenceSecurityFilterChain(final @NonNull HttpSecurity http) throws Exception {
    final String authnPath = Objects.requireNonNull(this.authn.getAuthnPath(), "authn.authn-path must be set");
    http
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers(authnPath, authnPath + "/**").permitAll()
            .requestMatchers("/images/**", "/css/**", "/scripts/**", "/webjars/**", "/error").permitAll()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
            .anyRequest().denyAll());
    return http.build();
  }

}
