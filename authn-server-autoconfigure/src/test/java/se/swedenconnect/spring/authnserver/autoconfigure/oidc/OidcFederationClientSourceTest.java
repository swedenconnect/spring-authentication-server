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
package se.swedenconnect.spring.authnserver.autoconfigure.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.autoconfigure.storage.AuthnServerStorageAutoConfiguration;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.oidc.client.InMemoryClientRepository;
import se.swedenconnect.spring.authnserver.oidc.client.RepositoryClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCacheSettings;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCallEvent;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceMonitor;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceState;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationServiceStateStore;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link OidcFederationClientSource}, set up from the properties, against a local HTTP server that plays
 * the trust anchor, a standalone resolver and a trust mark issuer.
 *
 * @author Martin Lindström
 */
class OidcFederationClientSourceTest {

  private static final String CLIENT_ID = "https://rp.example.com";

  private static final String MARK = "https://tm.example.com/approved";

  private final ECKey trustAnchorKey = key("ta");

  private final ECKey resolverKey = key("resolver");

  private final ECKey issuerKey = key("tmi");

  /** The paths that the server was asked for. */
  private final List<String> paths = Collections.synchronizedList(new ArrayList<>());

  /** What the server answers, by path. A missing path gives 404. */
  private final Map<String, Function<String, Answer>> answers = new HashMap<>();

  /** Whether the server answers 503 to everything. */
  private volatile boolean down = false;

  @TempDir
  Path directory;

  private HttpServer server;

  private String base;

  private String trustAnchor;

  private String resolver;

  private String issuer;

  @BeforeEach
  void startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", this::handle);
    this.server.start();
    this.base = "http://localhost:" + this.server.getAddress().getPort();
    this.trustAnchor = this.base + "/ta";
    this.resolver = this.base + "/resolver";
    this.issuer = this.base + "/tmi";

    this.publish("/ta", this.trustAnchorKey, this.trustAnchor, Map.of(
        "federation_resolve_endpoint", this.trustAnchor + "/resolve",
        "federation_trust_mark_endpoint", this.trustAnchor + "/trust_mark"));
    this.answers.put("/ta/resolve", query -> Answer.ok(this.resolveResponse(this.trustAnchorKey, this.trustAnchor,
        "Resolved by the trust anchor")));
    this.answers.put("/ta/trust_mark", query -> Answer.ok(this.trustMark(this.trustAnchorKey, this.trustAnchor)));
    this.publish("/resolver", this.resolverKey, this.resolver,
        Map.of("federation_resolve_endpoint", this.resolver + "/resolve-here"));
    this.answers.put("/resolver/resolve-here", query -> Answer.ok(this.resolveResponse(this.resolverKey,
        this.resolver, "Resolved by the resolver")));
    this.answers.put("/resolver/configured", query -> Answer.ok(this.resolveResponse(this.resolverKey,
        this.resolver, "Resolved at the configured endpoint")));
    this.publish("/tmi", this.issuerKey, this.issuer, Map.of("federation_trust_mark_endpoint",
        this.issuer + "/trust_mark"));
    this.answers.put("/tmi/trust_mark", query -> Answer.ok(this.trustMark(this.issuerKey, this.issuer)));
  }

  @AfterEach
  void stopServer() {
    this.server.stop(0);
  }

  private WebApplicationContextRunner runner() throws IOException {
    return new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class, OidcAutoConfiguration.class,
            AuthnServerAutoConfiguration.class))
        .withUserConfiguration(MonitorConfiguration.class)
        .withPropertyValues(
            "authn-server.base-url=https://op.example.com",
            "authn-server.oidc.enabled=true",
            "authn-server.oidc.keys.signing[0].credential.jks.store.location=classpath:credentials/oidc-keys.p12",
            "authn-server.oidc.keys.signing[0].credential.jks.store.password=secret",
            "authn-server.oidc.keys.signing[0].credential.jks.store.type=PKCS12",
            "authn-server.oidc.keys.signing[0].credential.jks.key.alias=rsa-sign",
            "authn-server.oidc.keys.signing[0].credential.jks.key.key-password=secret",
            "authn-server.oidc.federation.enabled=true",
            "authn-server.oidc.federation.authority-hints[0]=" + this.trustAnchor,
            "authn-server.oidc.federation.keys[0].credential.jks.store.location=classpath:credentials/oidc-keys.p12",
            "authn-server.oidc.federation.keys[0].credential.jks.store.password=secret",
            "authn-server.oidc.federation.keys[0].credential.jks.store.type=PKCS12",
            "authn-server.oidc.federation.keys[0].credential.jks.key.alias=rsa-sign",
            "authn-server.oidc.federation.keys[0].credential.jks.key.key-password=secret",
            "authn-server.entity-information.ui-info.display-names.sv=Exempel-OP",
            "authn-server.entity-information.ui-info.logotypes[0].url=https://cdn.example.com/logo.svg",
            "authn-server.entity-information.organization.names.sv=Exempel AB",
            "authn-server.entity-information.organization.number=5561234567",
            "authn-server.entity-information.contact-persons.technical.email-addresses[0]=ops@example.com",
            "authn-server.oidc.federation.trust-anchor.entity-id=" + this.trustAnchor,
            "authn-server.oidc.federation.trust-anchor.jwks=" + this.jwks("ta", this.trustAnchorKey));
  }

  @Test
  void aClientIsResolvedThroughAResolverAtTheTrustAnchor() throws Exception {
    this.runner().run(context -> {
      assertThat(context).hasNotFailed();
      // Nothing is fetched at startup
      assertThat(this.paths).isEmpty();

      final ConfiguredAuthnServer server = context.getBean(ConfiguredAuthnServer.class);
      final RequesterRecord record = server.getClientRegistry().lookup(AuthenticationProtocol.OIDC, CLIENT_ID);
      assertThat(record).isNotNull();
      assertThat(record.getDisplayName("en")).isEqualTo("Resolved by the trust anchor");
      assertThat(this.paths).containsExactly("/ta/.well-known/openid-federation", "/ta/resolve");
      assertThat(server.getClientRegistryBackends(FederationClientBackend.class))
          .singleElement()
          .satisfies(b -> assertThat(b.getName()).isEqualTo(OidcFederationClientSource.NAME));
    });
  }

  @Test
  void aClientIsResolvedThroughAStandaloneResolverWithItsOwnKeys() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.federation.clients.resolver.entity-id=" + this.resolver,
            "authn-server.oidc.federation.clients.resolver.jwks=" + this.jwks("resolver", this.resolverKey))
        .run(context -> {
          assertThat(context).hasNotFailed();
          final RequesterRecord record = context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
              .lookup(AuthenticationProtocol.OIDC, CLIENT_ID);
          assertThat(record).isNotNull();
          assertThat(record.getDisplayName("en")).isEqualTo("Resolved by the resolver");
          assertThat(this.paths).containsExactly("/resolver/.well-known/openid-federation", "/resolver/resolve-here");
        });
  }

  @Test
  void aConfiguredEndpointIsUsedWithoutFetchingAnything() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.federation.clients.resolver.entity-id=" + this.resolver,
            "authn-server.oidc.federation.clients.resolver.endpoint=" + this.resolver + "/configured",
            "authn-server.oidc.federation.clients.resolver.jwks=" + this.jwks("resolver", this.resolverKey))
        .run(context -> {
          assertThat(context).hasNotFailed();
          final RequesterRecord record = context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
              .lookup(AuthenticationProtocol.OIDC, CLIENT_ID);
          assertThat(record.getDisplayName("en")).isEqualTo("Resolved at the configured endpoint");
          assertThat(this.paths).containsExactly("/resolver/configured");
        });
  }

  @Test
  void anUnreachableFederationDoesNotStopTheServerAndShowsInTheHealthUntilItAnswers() throws Exception {
    this.down = true;
    this.runner().run(context -> {
      assertThat(context).hasNotFailed();
      final ClientRegistry registry = context.getBean(ConfiguredAuthnServer.class).getClientRegistry();
      final FederationServiceMonitor monitor = context.getBean(FederationServiceMonitor.class);

      assertThatThrownBy(() -> registry.lookup(AuthenticationProtocol.OIDC, CLIENT_ID))
          .isInstanceOf(ClientRegistryException.class);
      assertThat(monitor.getStates()).singleElement().satisfies(state -> {
        assertThat(state.type()).isEqualTo(FederationCallEvent.ServiceType.ENTITY_CONFIGURATION);
        assertThat(state.id()).isEqualTo(this.trustAnchor);
        assertThat(state.isFailing()).isTrue();
      });

      this.down = false;
      assertThat(registry.lookup(AuthenticationProtocol.OIDC, CLIENT_ID)).isNotNull();
      assertThat(monitor.getStates()).noneMatch(FederationServiceState::isFailing);
    });
  }

  @Test
  void aResolverThatDoesNotPublishItsEndpointShowsInTheHealth() throws Exception {
    this.publish("/ta", this.trustAnchorKey, this.trustAnchor, Map.of());
    this.runner().run(context -> {
      assertThat(context).hasNotFailed();
      assertThatThrownBy(() -> context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
          .lookup(AuthenticationProtocol.OIDC, CLIENT_ID))
          .isInstanceOf(ClientRegistryException.class)
          .hasMessageContaining("does not publish federation_resolve_endpoint");
      assertThat(context.getBean(FederationServiceMonitor.class).getStates())
          .anySatisfy(state -> assertThat(state.isFailing()).isTrue());
    });
  }

  @Test
  void aClientKnownToBothSourcesIsServedFromTheConfiguredClients() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.clients[0].client-id=" + CLIENT_ID,
            "authn-server.oidc.clients[0].metadata={\"client_name\":\"Configured\","
                + "\"redirect_uris\":[\"https://rp.example.com/cb\"]}")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final RequesterRecord record = context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
              .lookup(AuthenticationProtocol.OIDC, CLIENT_ID);
          assertThat(record.getDisplayName("en")).isEqualTo("Configured");
          assertThat(this.paths).isEmpty();
        });
  }

  @Test
  void theSourcesAreAskedInOrderPropertiesCodeFederation() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.clients[0].client-id=https://configured.example.com",
            "authn-server.oidc.clients[0].metadata={}")
        .withUserConfiguration(CodeSourceConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context.getBean(ConfiguredAuthnServer.class).getClientRegistryBackends())
              .extracting(ClientRegistryBackend::getName)
              .containsExactly("properties", "repository", "federation");
        });
  }

  @Test
  void aTrustMarkIsObtainedFromAnIssuerAtItsPublishedEndpoint() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].type=" + MARK,
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].issuer=" + this.issuer,
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].jwks=" + this.jwks("tmi", this.issuerKey),
            "authn-server.oidc.requester-acceptance.required-marks[0][0]=" + MARK)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final ConfiguredAuthnServer server = context.getBean(ConfiguredAuthnServer.class);
          final RequesterRecord record = server.getClientRegistry().lookup(AuthenticationProtocol.OIDC, CLIENT_ID);
          assertThat(record.hasMark(MARK)).isFalse();
          assertThat(server.getConfigurer().getRequesterAcceptance().isAccepted(record, server.getClientRegistry()))
              .isTrue();
          assertThat(this.paths).contains("/tmi/.well-known/openid-federation", "/tmi/trust_mark");
        });
  }

  @Test
  void theTrustAnchorAsIssuerNeedsNoKeys() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].type=" + MARK,
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].issuer=" + this.trustAnchor)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final ClientRegistry registry = context.getBean(ConfiguredAuthnServer.class).getClientRegistry();
          final RequesterRecord record =
              registry.requestMark(new Requester(AuthenticationProtocol.OIDC, CLIENT_ID), MARK);
          assertThat(record.hasMark(MARK)).isTrue();
        });
  }

  @Test
  void aMissingTrustAnchorFailsStartup() throws Exception {
    this.runner()
        .withPropertyValues("authn-server.oidc.federation.trust-anchor.entity-id=")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("Missing trust anchor")
            .hasMessageContaining("authn-server.oidc.federation.trust-anchor.entity-id")
            .hasMessageContaining("authn-server.oidc.federation.clients.enabled=false"));
  }

  @Test
  void aStandaloneResolverWithoutKeysFailsStartup() throws Exception {
    this.runner()
        .withPropertyValues("authn-server.oidc.federation.clients.resolver.entity-id=" + this.resolver)
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("Missing authn-server.oidc.federation.clients.resolver.jwks"));
  }

  @Test
  void anIssuerThatIsNotTheTrustAnchorWithoutKeysFailsStartup() throws Exception {
    this.runner()
        .withPropertyValues(
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].type=" + MARK,
            "authn-server.oidc.federation.clients.trust-mark-issuers[0].issuer=" + this.issuer)
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("Missing authn-server.oidc.federation.clients.trust-mark-issuers[0].jwks"));
  }

  @Test
  void theClientSourceCanBeTurnedOff() throws Exception {
    this.runner()
        .withPropertyValues("authn-server.oidc.federation.trust-anchor.entity-id=",
            "authn-server.oidc.federation.clients.enabled=false",
            "authn-server.oidc.clients[0].client-id=https://configured.example.com",
            "authn-server.oidc.clients[0].metadata={}")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context.getBean(ConfiguredAuthnServer.class)
              .getClientRegistryBackends(FederationClientBackend.class)).isEmpty();
        });
  }

  @Test
  void aFederationSourceAddedInCodeReplacesTheOneOfTheProperties() throws Exception {
    this.runner()
        .withPropertyValues("authn-server.oidc.federation.trust-anchor.entity-id=")
        .withUserConfiguration(CodeFederationConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context.getBean(ConfiguredAuthnServer.class)
              .getClientRegistryBackends(FederationClientBackend.class))
              .singleElement().isSameAs(CodeFederationConfiguration.BACKEND);
        });
  }

  @Test
  void theCacheSettingsFollowThePropertiesWithTheDefaultsOfTheLibrary() {
    final OidcConfigurationProperties.FederationCacheProperties properties =
        new OidcConfigurationProperties.FederationCacheProperties();
    assertThat(OidcFederationClientSource.createCacheSettings(properties))
        .isEqualTo(FederationCacheSettings.defaults());

    properties.setMaximumAge(Duration.ofHours(12));
    properties.setNotFoundTimeToLive(Duration.ofMinutes(2));
    properties.getRefresh().setEnabled(true);
    properties.getRefresh().setMinimumLookups(3);
    final FederationCacheSettings settings = OidcFederationClientSource.createCacheSettings(properties);
    assertThat(settings.maximumAge()).isEqualTo(Duration.ofHours(12));
    assertThat(settings.notFoundTimeToLive()).isEqualTo(Duration.ofMinutes(2));
    assertThat(settings.refresh().enabled()).isTrue();
    assertThat(settings.refresh().minimumLookups()).isEqualTo(3);
    assertThat(settings.refresh().interval())
        .isEqualTo(FederationCacheSettings.RefreshSettings.DEFAULT_INTERVAL);
  }

  @Test
  void invalidSettingsAreRejected() throws Exception {
    final OidcConfigurationProperties.FederationProperties properties =
        new OidcConfigurationProperties.FederationProperties();
    properties.getTrustAnchor().setEntityId(this.trustAnchor);
    properties.getTrustAnchor().setJwks(new FileSystemResource(this.jwks("ta", this.trustAnchorKey).substring(5)));

    final OidcConfigurationProperties.TrustMarkIssuerProperties noIssuer =
        new OidcConfigurationProperties.TrustMarkIssuerProperties();
    noIssuer.setType(MARK);
    properties.getClients().setTrustMarkIssuers(List.of(noIssuer));
    assertThatIllegalArgumentException().isThrownBy(() -> OidcFederationClientSource.createSettings(properties))
        .withMessageContaining("trust-mark-issuers[0] must have type and issuer");

    final OidcConfigurationProperties.TrustMarkIssuerProperties one =
        new OidcConfigurationProperties.TrustMarkIssuerProperties();
    one.setType(MARK);
    one.setIssuer(this.trustAnchor);
    properties.getClients().setTrustMarkIssuers(List.of(one, one));
    assertThatIllegalArgumentException().isThrownBy(() -> OidcFederationClientSource.createSettings(properties))
        .withMessageContaining("has more than one issuer");

    properties.getClients().setTrustMarkIssuers(null);
    final Path empty = this.directory.resolve("empty.json");
    Files.writeString(empty, "{\"keys\":[]}");
    properties.getTrustAnchor().setJwks(new FileSystemResource(empty));
    assertThatIllegalArgumentException().isThrownBy(() -> OidcFederationClientSource.createSettings(properties))
        .withMessageContaining("holds no keys");
  }

  @Test
  void theTrustMarkEndpointOfTheProvidersOwnTrustMarksIsOptional() throws Exception {
    final OidcConfigurationProperties.TrustMarkProperties withoutEndpoint =
        new OidcConfigurationProperties.TrustMarkProperties();
    withoutEndpoint.setType(MARK);
    withoutEndpoint.setIssuer(this.issuer);
    withoutEndpoint.setJwks(new FileSystemResource(this.jwks("tmi", this.issuerKey).substring(5)));
    assertThat(OidcAutoConfiguration.loadTrustMarkSources(List.of(withoutEndpoint)))
        .singleElement()
        .satisfies(source -> assertThat(source.endpoint()).isNull());

    withoutEndpoint.setJwks(null);
    assertThatIllegalArgumentException()
        .isThrownBy(() -> OidcAutoConfiguration.loadTrustMarkSources(List.of(withoutEndpoint)))
        .withMessageContaining("must have type, issuer and jwks");
  }

  /** Records the federation calls, as the Actuator support does. */
  @Configuration
  static class MonitorConfiguration {

    @Bean
    FederationServiceMonitor testFederationServiceMonitor() {
      return new FederationServiceMonitor(new InMemoryFederationServiceStateStore());
    }
  }

  /** Adds a client source in code. */
  @Configuration
  static class CodeSourceConfiguration {

    @Bean
    AuthnServerConfigurerAdapter codeSource() {
      return (http, configurer) -> configurer.clientRegistryBackend(
          new RepositoryClientBackend(new InMemoryClientRepository()));
    }
  }

  /** Adds a federation client source in code. */
  @Configuration
  static class CodeFederationConfiguration {

    static final FederationClientBackend BACKEND = new FederationClientBackend(clientId -> null,
        (clientId, type) -> null, new InMemoryFederationCache(), FederationCacheSettings.defaults());

    @Bean
    AuthnServerConfigurerAdapter codeFederation() {
      return (http, configurer) -> configurer.clientRegistryBackend(BACKEND);
    }
  }

  /**
   * An answer of the server.
   *
   * @param status the HTTP status
   * @param body the body
   */
  private record Answer(int status, String body) {

    static Answer ok(final String body) {
      return new Answer(200, body);
    }
  }

  private void handle(final HttpExchange exchange) throws IOException {
    final String path = exchange.getRequestURI().getPath();
    this.paths.add(path);
    final Function<String, Answer> answer = this.answers.get(path);
    final Answer a = this.down ? new Answer(503, "down")
        : answer != null ? answer.apply(exchange.getRequestURI().getRawQuery()) : new Answer(404, "not found");
    final byte[] bytes = a.body().getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(a.status(), bytes.length);
    try (final OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private void publish(final String path, final ECKey key, final String entityId,
      final Map<String, Object> federationEntity) {
    this.answers.put(path + "/.well-known/openid-federation", query -> Answer.ok(sign(key, "entity-statement+jwt",
        new JWTClaimsSet.Builder()
            .issuer(entityId)
            .subject(entityId)
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plus(Duration.ofHours(1))))
            .claim("metadata", Map.of("federation_entity", federationEntity))
            .build())));
  }

  private String resolveResponse(final ECKey key, final String issuer, final String name) {
    return sign(key, "resolve-response+jwt", new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(CLIENT_ID)
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plus(Duration.ofHours(1))))
        .claim("metadata", Map.of("openid_relying_party", Map.of(
            "client_name", name,
            "redirect_uris", List.of("https://rp.example.com/cb"))))
        .build());
  }

  private String trustMark(final ECKey key, final String issuer) {
    return sign(key, "trust-mark+jwt", new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(CLIENT_ID)
        .issueTime(new Date())
        .claim("trust_mark_type", MARK)
        .build());
  }

  private String jwks(final String name, final ECKey key) throws IOException {
    final Path file = this.directory.resolve(name + ".jwks");
    Files.writeString(file, new JWKSet(key.toPublicJWK()).toString());
    return "file:" + file;
  }

  private static String sign(final ECKey key, final String type, final JWTClaimsSet claims) {
    try {
      final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
          .type(new JOSEObjectType(type)).keyID(key.getKeyID()).build(), claims);
      jwt.sign(new ECDSASigner(key));
      return jwt.serialize();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static ECKey key(final String keyId) {
    try {
      return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
