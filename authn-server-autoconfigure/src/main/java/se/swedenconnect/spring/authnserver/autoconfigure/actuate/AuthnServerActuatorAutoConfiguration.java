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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import java.util.Optional;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.autoconfigure.endpoint.condition.ConditionalOnAvailableEndpoint;
import org.springframework.boot.actuate.endpoint.EndpointId;
import org.springframework.boot.actuate.endpoint.web.PathMappedEndpoints;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceMonitor;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceStateStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;

/**
 * Spring Boot Actuator support for the authentication server. Active when Spring Boot Actuator is on the classpath.
 * <p>
 * It declares the {@link ClientsEndpoint}, the {@link AuthnServerInfoContributor} and, when the health support of
 * Spring Boot is on the classpath, the health indicators {@value #SAML_METADATA_HEALTH},
 * {@value #OIDC_TRUST_MARKS_HEALTH} and {@value #OIDC_FEDERATION_HEALTH}, each for an enabled protocol.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration(after = AuthnServerAutoConfiguration.class,
    afterName = { "se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration",
        "se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration",
        "se.swedenconnect.spring.authnserver.autoconfigure.storage.AuthnServerStorageAutoConfiguration" })
@ConditionalOnClass(name = AuthnServerActuatorAutoConfiguration.ACTUATOR_CLASS)
public class AuthnServerActuatorAutoConfiguration {

  /** The class that tells whether Spring Boot Actuator is on the classpath. */
  static final String ACTUATOR_CLASS =
      "org.springframework.boot.actuate.autoconfigure.endpoint.EndpointAutoConfiguration";

  /** The class that tells whether the health support of Spring Boot is on the classpath. */
  static final String HEALTH_CLASS = "org.springframework.boot.health.contributor.HealthIndicator";

  /** The name of the SAML metadata health indicator. */
  public static final String SAML_METADATA_HEALTH = "saml-metadata";

  /** The name of the health indicator of the OpenID Provider's own trust marks. */
  public static final String OIDC_TRUST_MARKS_HEALTH = "oidc-trust-marks";

  /** The name of the health indicator of the federation services. */
  public static final String OIDC_FEDERATION_HEALTH = "oidc-federation";

  /**
   * Creates the {@value ClientsEndpoint#ID} endpoint.
   *
   * @param server the configured server
   * @param endpoints gives the path of the endpoint, if available
   * @return a {@link ClientsEndpoint}
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnAvailableEndpoint
  ClientsEndpoint authnServerClientsEndpoint(final ConfiguredAuthnServer server,
      final ObjectProvider<PathMappedEndpoints> endpoints) {
    return new ClientsEndpoint(server, () -> Optional.ofNullable(endpoints.getIfAvailable())
        .map(e -> e.getPath(EndpointId.of(ClientsEndpoint.ID)))
        .orElse("/actuator/" + ClientsEndpoint.ID));
  }

  /**
   * Creates the info contributor.
   *
   * @param server the configured server
   * @return an {@link AuthnServerInfoContributor}
   */
  @Bean
  @ConditionalOnMissingBean
  AuthnServerInfoContributor authnServerInfoContributor(final ConfiguredAuthnServer server) {
    return new AuthnServerInfoContributor(server);
  }

  /**
   * The SAML health indicator.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = { HEALTH_CLASS, "se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer" })
  @ConditionalOnProperty(name = "authn-server.saml.enabled", havingValue = "true")
  static class SamlHealthConfiguration {

    /**
     * Creates the SAML metadata health indicator.
     *
     * @param server the configured server
     * @return a {@link SamlMetadataHealthIndicator}
     */
    @Bean(SAML_METADATA_HEALTH)
    @ConditionalOnMissingBean(name = SAML_METADATA_HEALTH)
    @ConditionalOnEnabledHealthIndicator(SAML_METADATA_HEALTH)
    SamlMetadataHealthIndicator samlMetadataHealthIndicator(final ConfiguredAuthnServer server) {
      return new SamlMetadataHealthIndicator(server);
    }

  }

  /**
   * The OIDC health indicators.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = { HEALTH_CLASS,
      "se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer" })
  @ConditionalOnProperty(name = "authn-server.oidc.enabled", havingValue = "true")
  static class OidcHealthConfiguration {

    /**
     * Creates the health indicator of the OpenID Provider's own trust marks, when OpenID Federation is enabled.
     *
     * @param trustMarks the trust marks of the OpenID Provider
     * @return an {@link OidcTrustMarksHealthIndicator}
     */
    @Bean(OIDC_TRUST_MARKS_HEALTH)
    @ConditionalOnBean(ProviderTrustMarks.class)
    @ConditionalOnMissingBean(name = OIDC_TRUST_MARKS_HEALTH)
    @ConditionalOnEnabledHealthIndicator(OIDC_TRUST_MARKS_HEALTH)
    OidcTrustMarksHealthIndicator oidcTrustMarksHealthIndicator(final ProviderTrustMarks trustMarks) {
      return new OidcTrustMarksHealthIndicator(trustMarks);
    }

    /**
     * Creates the monitor of the federation services, which records the outcome of every federation call.
     *
     * @param store where the state is kept
     * @return a {@link FederationServiceMonitor}
     */
    @Bean
    @ConditionalOnBean(FederationServiceStateStore.class)
    @ConditionalOnMissingBean
    FederationServiceMonitor oidcFederationServiceMonitor(final FederationServiceStateStore store) {
      return new FederationServiceMonitor(store);
    }

    /**
     * Creates the health indicator of the federation services.
     *
     * @param monitor the monitor of the federation services
     * @return an {@link OidcFederationHealthIndicator}
     */
    @Bean(OIDC_FEDERATION_HEALTH)
    @ConditionalOnBean(FederationServiceStateStore.class)
    @ConditionalOnMissingBean(name = OIDC_FEDERATION_HEALTH)
    @ConditionalOnEnabledHealthIndicator(OIDC_FEDERATION_HEALTH)
    OidcFederationHealthIndicator oidcFederationHealthIndicator(final FederationServiceMonitor monitor) {
      return new OidcFederationHealthIndicator(monitor);
    }

  }

}
