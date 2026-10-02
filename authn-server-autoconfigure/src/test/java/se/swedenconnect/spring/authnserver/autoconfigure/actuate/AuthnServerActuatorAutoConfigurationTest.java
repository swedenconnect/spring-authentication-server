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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.actuate.autoconfigure.endpoint.EndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.jackson.JacksonEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.info.InfoEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.contributor.HealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.servlet.autoconfigure.actuate.web.ServletManagementContextAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.DispatcherServletAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.http.MediaType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.storage.AuthnServerStorageAutoConfiguration;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCallEvent;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceMonitor;
import se.swedenconnect.spring.authnserver.saml.metadata.SamlMetadataBackend;

/**
 * Tests for {@link AuthnServerActuatorAutoConfiguration}: the clients endpoint, the info contribution and the health
 * indicators, through the Actuator web endpoints.
 *
 * @author Martin Lindström
 */
class AuthnServerActuatorAutoConfigurationTest {

  private static final String RESOLVER = "$.details.services[?(@.type == 'resolver')]";

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class, SamlAutoConfiguration.class,
          OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class, AuthnServerActuatorAutoConfiguration.class,
          JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class, WebMvcAutoConfiguration.class,
          DispatcherServletAutoConfiguration.class, EndpointAutoConfiguration.class,
          JacksonEndpointAutoConfiguration.class, WebEndpointAutoConfiguration.class,
          ManagementContextAutoConfiguration.class, ServletManagementContextAutoConfiguration.class,
          HealthContributorAutoConfiguration.class, HealthContributorRegistryAutoConfiguration.class,
          HealthEndpointAutoConfiguration.class,
          InfoEndpointAutoConfiguration.class))
      .withUserConfiguration(ActuatorTestSupport.OidcBackendsConfiguration.class)
      .withInitializer(c -> {
        c.getEnvironment().setConversionService(new ApplicationConversionService());
        new HealthStatusEnvironmentPostProcessor().postProcessEnvironment(c.getEnvironment(), null);
      })
      .withPropertyValues("management.endpoints.web.exposure.include=*",
          "management.endpoint.health.show-details=always");

  @TempDir
  Path directory;

  @AfterEach
  void clear() {
    ActuatorTestSupport.RESOLVED.clear();
  }

  @Test
  void theClientsEndpointListsAndShowsTheClients() throws Exception {
    this.run(context -> {
      final MockMvc mvc = mvc(context);
      resolveFederationClient(context);

      mvc.perform(get("/actuator/clients"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.clients[*].id", Matchers.containsInAnyOrder(ActuatorTestSupport.SP_ONE,
              ActuatorTestSupport.SP_TWO, ActuatorTestSupport.PROPERTIES_CLIENT, ActuatorTestSupport.CONFIGURED_CLIENT,
              ActuatorTestSupport.FEDERATION_CLIENT)))
          .andExpect(jsonPath("$.clients[?(@.id == '%s')].source".formatted(ActuatorTestSupport.PROPERTIES_CLIENT))
              .value("properties"))
          .andExpect(jsonPath("$.clients[?(@.id == '%s')].source".formatted(ActuatorTestSupport.FEDERATION_CLIENT))
              .value("federation"))
          .andExpect(jsonPath("$.clients[?(@.id == '%s')].expires-at".formatted(ActuatorTestSupport.FEDERATION_CLIENT))
              .exists());

      mvc.perform(get("/actuator/clients/saml").param("id", ActuatorTestSupport.SP_ONE))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.protocol").value("saml"))
          .andExpect(jsonPath("$.id").value(ActuatorTestSupport.SP_ONE))
          .andExpect(jsonPath("$.marks").isArray())
          .andExpect(jsonPath("$.source").value(Matchers.endsWith(".xml")))
          .andExpect(jsonPath("$.metadata").value(
              "/actuator/clients/saml/metadata?id=https%3A%2F%2Fsp-one.example.com"));

      mvc.perform(get("/actuator/clients/saml/metadata").param("id", ActuatorTestSupport.SP_ONE))
          .andExpect(status().isOk())
          .andExpect(header().string("Content-Type", Matchers.startsWith(ClientsEndpoint.SAML_METADATA_MEDIA_TYPE)))
          .andExpect(content().string(Matchers.containsString("entityID=\"https://sp-one.example.com\"")));

      mvc.perform(get("/actuator/clients/oidc").param("id", ActuatorTestSupport.CONFIGURED_CLIENT))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.source").value("configuration"));

      mvc.perform(get("/actuator/clients/oidc").param("id", ActuatorTestSupport.PROPERTIES_CLIENT))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.source").value("properties"))
          .andExpect(jsonPath("$.marks[0]").value("https://tm.example.com/approved"));

      mvc.perform(get("/actuator/clients/oidc/metadata").param("id", ActuatorTestSupport.CONFIGURED_CLIENT))
          .andExpect(status().isOk())
          .andExpect(header().string("Content-Type", Matchers.startsWith("application/json")))
          .andExpect(jsonPath("$.client_name").value("Configured Client"))
          .andExpect(jsonPath("$.client_secret").doesNotExist());

      mvc.perform(get("/actuator/clients/oidc/metadata").param("id", ActuatorTestSupport.FEDERATION_CLIENT))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.client_name").value("Federation Client"));

      mvc.perform(get("/actuator/clients/saml").param("id", "https://unknown.example.com"))
          .andExpect(status().isNotFound());
      mvc.perform(get("/actuator/clients/oidc/metadata").param("id", "https://unknown.example.com"))
          .andExpect(status().isNotFound());
      mvc.perform(get("/actuator/clients/cas").param("id", ActuatorTestSupport.SP_ONE))
          .andExpect(status().isNotFound());
      mvc.perform(get("/actuator/clients/saml/other").param("id", ActuatorTestSupport.SP_ONE))
          .andExpect(status().isNotFound());
    });
  }

  @Test
  void theUpdateOperationsAreRefusedUntilAccessIsGranted() throws Exception {
    this.run(context -> {
      final MockMvc mvc = mvc(context);
      resolveFederationClient(context);

      mvc.perform(post("/actuator/clients/saml").contentType(MediaType.APPLICATION_JSON))
          .andExpect(status().is4xxClientError());
      mvc.perform(oidcUpdate().param("id", ActuatorTestSupport.FEDERATION_CLIENT))
          .andExpect(status().is4xxClientError());
      assertThat(ActuatorTestSupport.RESOLVED).hasSize(1);
    });
  }

  @Test
  void theUpdateOperationsWorkWhenAccessIsGranted() throws Exception {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.SP_TWO);
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata))
        .withPropertyValues("management.endpoint.clients.access=unrestricted")
        .withUserConfiguration(ActuatorTestSupport.EventsConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final MockMvc mvc = mvc(context);
          final ActuatorTestSupport.EventCollector events = context.getBean(ActuatorTestSupport.EventCollector.class);
          resolveFederationClient(context);
          events.events.clear();

          Files.writeString(metadata,
              ActuatorTestSupport.metadata(ActuatorTestSupport.SP_TWO, ActuatorTestSupport.SP_THREE));
          Files.setLastModifiedTime(metadata,
              java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 5000));
          mvc.perform(post("/actuator/clients/saml").contentType(MediaType.APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.outcome").value("updated"));
          assertThat(events.added()).containsExactly(ActuatorTestSupport.SP_THREE);
          assertThat(events.removed()).containsExactly(ActuatorTestSupport.SP_ONE);
          mvc.perform(get("/actuator/clients/saml").param("id", ActuatorTestSupport.SP_THREE))
              .andExpect(status().isOk());

          ActuatorTestSupport.RESOLVED.put(ActuatorTestSupport.FEDERATION_CLIENT,
              ActuatorTestSupport.resolved(ActuatorTestSupport.FEDERATION_CLIENT));
          mvc.perform(oidcUpdate().param("id", ActuatorTestSupport.FEDERATION_CLIENT))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.id").value(ActuatorTestSupport.FEDERATION_CLIENT))
              .andExpect(jsonPath("$.outcome").value("updated"));

          mvc.perform(oidcUpdate().param("id", ActuatorTestSupport.CONFIGURED_CLIENT))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.outcome").value("nothing-to-update"));
          mvc.perform(oidcUpdate())
              .andExpect(status().isBadRequest());
          mvc.perform(oidcUpdate().param("id", "https://unknown.example.com"))
              .andExpect(status().isNotFound());
          mvc.perform(post("/actuator/clients/cas").contentType(MediaType.APPLICATION_JSON))
              .andExpect(status().isNotFound());

          ActuatorTestSupport.RESOLVED.clear();
          mvc.perform(oidcUpdate().param("id", ActuatorTestSupport.FEDERATION_CLIENT))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.outcome").value("removed"));
          assertThat(events.removed()).contains(ActuatorTestSupport.FEDERATION_CLIENT);

          Files.writeString(metadata, "not xml");
          Files.setLastModifiedTime(metadata,
              java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 10000));
          mvc.perform(post("/actuator/clients/saml").contentType(MediaType.APPLICATION_JSON))
              .andExpect(status().is(502))
              .andExpect(jsonPath("$.outcome").value("failed"));
        });
  }

  @Test
  void theInfoEndpointShowsTheServerAndTheSources() throws Exception {
    this.run(context -> {
      resolveFederationClient(context);
      mvc(context).perform(get("/actuator/info"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.authn-server.protocols", Matchers.containsInAnyOrder("saml", "oidc")))
          .andExpect(jsonPath("$.authn-server.saml.entity-id").value(ActuatorTestSupport.BASE_URL))
          .andExpect(jsonPath("$.authn-server.oidc.issuer").value(ActuatorTestSupport.BASE_URL))
          .andExpect(jsonPath("$.authn-server.oidc.federation.authority-hints[0]").value("https://ia.example.com"))
          .andExpect(jsonPath("$.authn-server.oidc.federation.trust-marks[0].type")
              .value("https://id.swedenconnect.se/loa/loa3"))
          .andExpect(jsonPath("$.authn-server.oidc.federation.trust-marks[0].published").value(false))
          .andExpect(jsonPath("$.authn-server.authentication-providers").isArray())
          .andExpect(jsonPath("$.client-registry.sources[?(@.protocol == 'saml')].clients").value(2))
          .andExpect(jsonPath("$.client-registry.sources[?(@.backend == 'configuration')].clients").value(1))
          .andExpect(jsonPath("$.client-registry.sources[?(@.backend == 'properties')].clients").value(1))
          .andExpect(jsonPath("$.client-registry.sources[?(@.backend == 'federation')].clients").value(1))
          .andExpect(jsonPath("$.client-registry.sources[?(@.backend == 'federation')].last-update").exists());
    });
  }

  @Test
  void theHealthIndicatorsReportWarningWithHttp200() throws Exception {
    this.run(context -> {
      final MockMvc mvc = mvc(context);
      mvc.perform(get("/actuator/health"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.status").value("WARNING"))
          .andExpect(jsonPath("$.components.saml-metadata.status").value("UP"))
          .andExpect(jsonPath("$.components.saml-metadata.details.sources[0].service-providers").value(2))
          .andExpect(jsonPath("$.components.oidc-trust-marks.status").value("WARNING"))
          .andExpect(jsonPath("$.components.oidc-trust-marks.details.trust-marks[0].published").value(false))
          .andExpect(jsonPath("$.components.oidc-federation").exists());

      context.publishEvent(new FederationCallEvent(FederationCallEvent.Call.RESOLVE, "https://r.example.com/resolve",
          null, FederationCallEvent.Outcome.UNREACHABLE, "connection refused"));
      mvc.perform(get("/actuator/health/oidc-federation"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.status").value("WARNING"))
          .andExpect(jsonPath(RESOLVER + ".latest-outcome").value("unreachable"));

      context.publishEvent(new FederationCallEvent(FederationCallEvent.Call.RESOLVE, "https://r.example.com/resolve",
          null, FederationCallEvent.Outcome.SUCCESS, null));
      mvc.perform(get("/actuator/health/oidc-federation"))
          .andExpect(jsonPath(RESOLVER + ".latest-outcome").value("success"))
          .andExpect(jsonPath(RESOLVER + ".failures-since-success").value(0))
          .andExpect(jsonPath(RESOLVER + ".last-failure.kind").value("unreachable"))
          .andExpect(jsonPath(RESOLVER + ".last-failure.error").value("connection refused"));
      assertThat(context.getBean(FederationServiceMonitor.class).getStates())
          .anyMatch(s -> s.type() == FederationCallEvent.ServiceType.RESOLVER && !s.isFailing());

      // The trust mark issuer of the OP's own trust mark cannot be reached
      Thread.sleep(200);
      mvc.perform(get("/actuator/health/oidc-federation"))
          .andExpect(jsonPath("$.status").value("WARNING"))
          .andExpect(jsonPath("$.details.services[?(@.type == 'trust-mark-issuer')].id")
              .value("https://tmi.example.com"));
    });
  }

  @Test
  void aFailedMetadataUpdateIsAWarning() throws Exception {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.SP_TWO);
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata)).run(context -> {
      Files.writeString(metadata, "not xml");
      Files.setLastModifiedTime(metadata,
          java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 5000));
      context.getBean(ConfiguredAuthnServer.class).getClientRegistryBackends(SamlMetadataBackend.class)
          .forEach(SamlMetadataBackend::update);

      mvc(context).perform(get("/actuator/health/saml-metadata"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.status").value("WARNING"))
          .andExpect(jsonPath("$.details.sources[0].last-download-successful").value(false))
          .andExpect(jsonPath("$.details.sources[0].error").exists())
          .andExpect(jsonPath("$.details.sources[0].service-providers").value(2));
    });
  }

  @Test
  void noServiceProviderAtAllIsOutOfService() throws Exception {
    final Path metadata = this.metadataFile();
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata)).run(context ->
        mvc(context).perform(get("/actuator/health/saml-metadata"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.status").value("OUT_OF_SERVICE")));
  }

  @Test
  void theHttpMappingOfWarningCanBeChanged() throws Exception {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE);
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata))
        .withPropertyValues("management.endpoint.health.status.http-mapping.down=503",
            "management.endpoint.health.status.http-mapping.out-of-service=503",
            "management.endpoint.health.status.http-mapping.warning=503")
        .run(context -> mvc(context).perform(get("/actuator/health"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.status").value("WARNING")));
  }

  @Test
  void theStatusOrderCanBeChanged() throws Exception {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE);
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata))
        .withPropertyValues("management.endpoint.health.status.order=DOWN,OUT_OF_SERVICE,UP,WARNING,UNKNOWN")
        .run(context -> mvc(context).perform(get("/actuator/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP")));
  }

  @Test
  void theServerStartsWithoutActuator() {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE);
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class, SamlAutoConfiguration.class,
            OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class,
            AuthnServerActuatorAutoConfiguration.class))
        .withClassLoader(new FilteredClassLoader("org.springframework.boot.actuate.autoconfigure",
            "org.springframework.boot.health"))
        .withPropertyValues(ActuatorTestSupport.server(metadata))
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityFilterChain.class);
          assertThat(context).doesNotHaveBean(ClientsEndpoint.class);
          assertThat(context).doesNotHaveBean(AuthnServerInfoContributor.class);
          assertThat(context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
              .lookup(AuthenticationProtocol.SAML, ActuatorTestSupport.SP_ONE)).isNotNull();
        });
  }

  @Test
  void anEndpointThatIsNotConfiguredGivesNothing() {
    final ConfiguredAuthnServer server = new ConfiguredAuthnServer();
    final ClientsEndpoint endpoint = new ClientsEndpoint(server, () -> "/actuator/clients");
    assertThat(endpoint.clients()).containsEntry("clients", java.util.List.of());
    assertThat(endpoint.client("saml", "x").getStatus()).isEqualTo(404);
    assertThat(endpoint.update("saml", null).getStatus()).isEqualTo(404);
    assertThat(server.getClientRegistry()).isNull();

    final org.springframework.boot.actuate.info.Info.Builder builder =
        new org.springframework.boot.actuate.info.Info.Builder();
    new AuthnServerInfoContributor(server).contribute(builder);
    assertThat(builder.build().getDetails()).isEmpty();
    assertThat(new SamlMetadataHealthIndicator(server).health().getStatus().getCode()).isEqualTo("UNKNOWN");
  }

  private void run(final org.springframework.boot.test.context.runner.ContextConsumer<
      AssertableWebApplicationContext> consumer) {
    final Path metadata = this.metadataFile(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.SP_TWO);
    this.runner.withPropertyValues(ActuatorTestSupport.server(metadata)).run(context -> {
      assertThat(context).hasNotFailed();
      consumer.accept(context);
    });
  }

  private Path metadataFile(final String... entityIds) {
    try {
      final Path file = Files.createTempFile(this.directory, "metadata", ".xml");
      Files.writeString(file, ActuatorTestSupport.metadata(entityIds));
      return file;
    }
    catch (final java.io.IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void resolveFederationClient(final AssertableWebApplicationContext context) {
    ActuatorTestSupport.RESOLVED.put(ActuatorTestSupport.FEDERATION_CLIENT,
        ActuatorTestSupport.resolved(ActuatorTestSupport.FEDERATION_CLIENT));
    assertThat(context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
        .lookup(AuthenticationProtocol.OIDC, ActuatorTestSupport.FEDERATION_CLIENT)).isNotNull();
  }

  private static MockHttpServletRequestBuilder oidcUpdate() {
    return post("/actuator/clients/oidc").contentType(MediaType.APPLICATION_JSON);
  }

  private static MockMvc mvc(final AssertableWebApplicationContext context) {
    return MockMvcBuilders.webAppContextSetup((WebApplicationContext) context.getSourceApplicationContext()).build();
  }

}
