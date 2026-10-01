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
package se.swedenconnect.spring.authnserver.saml.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;

import com.sun.net.httpserver.HttpServer;
import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;

/**
 * Tests for {@link ManagedMetadataSource} and the management methods of {@link SamlMetadataBackend}.
 *
 * @author Martin Lindström
 */
class ManagedMetadataSourceTest extends OpenSamlTestBase {

  private static final String SP_ONE = "https://sp-one.example.com";

  private static final String SP_TWO = "https://sp-two.example.com";

  private static final String SP_THREE = "https://sp-three.example.com";

  private final List<ApplicationEvent> events = new ArrayList<>();

  /** The HTTP server of the test, stopped when the test is done. */
  private HttpServer server;

  @AfterEach
  void cleanUp() {
    if (this.server != null) {
      this.server.stop(0);
      this.server = null;
    }
  }

  @Test
  void theBackendListsAndShowsItsServiceProviders() throws Exception {
    final SamlMetadataBackend backend = new SamlMetadataBackend(MetadataProviderFactory.createManagedSources(List.of(
        MetadataSource.builder(new ClassPathResource("metadata/sp-metadata.xml")).build(),
        MetadataSource.builder(new ClassPathResource("metadata/sp-three.xml")).build()), null));

    assertThat(backend.getClients()).extracting(c -> c.requester().identifier())
        .containsExactlyInAnyOrder(SP_ONE, SP_TWO, SP_THREE);
    final RegisteredClient one = backend.getClient(SP_ONE);
    assertThat(one).isNotNull();
    assertThat(one.source()).isEqualTo("classpath:metadata/sp-metadata.xml");
    assertThat(one.marks()).contains("http://id.elegnamnden.se/sprop/1.0/mobile-auth");
    assertThat(backend.getClient("https://unknown.example.com")).isNull();
    assertThat(backend.getMetadata("https://unknown.example.com")).isNull();

    final String xml = backend.getMetadata(SP_THREE);
    assertThat(xml).isNotNull();
    final EntityDescriptor parsed = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(),
        new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    assertThat(parsed.getEntityID()).isEqualTo(SP_THREE);

    assertThat(backend.getSources()).extracting(ClientSource::name, ClientSource::clients)
        .containsExactly(tuple("classpath:metadata/sp-metadata.xml", 2),
            tuple("classpath:metadata/sp-three.xml", 1));
    assertThat(backend.getSources()).allMatch(s -> s.protocol() == AuthenticationProtocol.SAML);
    assertThat(backend.getMetadataSources()).noneMatch(ManagedMetadataSource::isRefreshable);

    assertThat(backend.update().outcome()).isEqualTo(ClientUpdateResult.Outcome.NOTHING_TO_UPDATE);
    assertThat(backend.update(SP_ONE).outcome()).isEqualTo(ClientUpdateResult.Outcome.NOTHING_TO_UPDATE);
  }

  @Test
  void anUpdatedFileWithOneAddedAndOneRemovedGivesOneEventOfEach(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("metadata.xml");
    Files.writeString(file, metadata(SP_ONE, SP_TWO));
    final SamlMetadataBackend backend = new SamlMetadataBackend(MetadataProviderFactory.createManagedSources(
        List.of(MetadataSource.builder(new FileSystemResource(file)).build()), null));
    backend.setClientChangeTracker(this.tracker());
    assertThat(this.added()).containsExactlyInAnyOrder(SP_ONE, SP_TWO);
    this.events.clear();

    Files.writeString(file, metadata(SP_TWO, SP_THREE));
    Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 5000));
    final ClientUpdateResult result = backend.update();

    assertThat(result.outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);
    assertThat(this.added()).containsExactly(SP_THREE);
    assertThat(this.removed()).containsExactly(SP_ONE);
    assertThat(backend.getClient(SP_THREE)).isNotNull();
    assertThat(backend.getClient(SP_ONE)).isNull();
  }

  @Test
  void aDownloadedSourceIsUpdatedAndReportsItsState(@TempDir final Path directory) throws Exception {
    final AtomicReference<String> content = new AtomicReference<>(metadata(SP_ONE, SP_TWO));
    final AtomicInteger status = new AtomicInteger(200);
    final int port = this.startServer(content, status);
    final List<ManagedMetadataSource> sources = MetadataProviderFactory.createManagedSources(List.of(
        MetadataSource.builder(new UrlResource("http://localhost:%d/metadata".formatted(port)))
            .backupLocation(directory.resolve("backup.xml").toFile())
            .build()), null);
    final SamlMetadataBackend backend = new SamlMetadataBackend(sources);
    backend.setClientChangeTracker(this.tracker());
    this.events.clear();

    final ManagedMetadataSource source = sources.get(0);
    assertThat(source.isRefreshable()).isTrue();
    assertThat(source.isListable()).isTrue();
    assertThat(source.wasLastRefreshSuccessful()).isTrue();
    assertThat(source.getLastRefresh()).isNotNull();
    assertThat(source.getLastSuccessfulRefresh()).isNotNull();
    assertThat(source.getLastUpdate()).isNotNull();
    assertThat(source.getProvider()).isNotNull();
    assertThat(source.toString()).isEqualTo("http://localhost:%d/metadata".formatted(port));

    content.set(metadata(SP_TWO, SP_THREE));
    assertThat(backend.update().outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);
    assertThat(this.added()).containsExactly(SP_THREE);
    assertThat(this.removed()).containsExactly(SP_ONE);
    this.events.clear();

    status.set(500);
    final ClientUpdateResult failed = backend.update();
    assertThat(failed.outcome()).isEqualTo(ClientUpdateResult.Outcome.FAILED);
    assertThat(source.wasLastRefreshSuccessful()).isFalse();
    assertThat(source.getLastFailure()).contains("500");
    assertThat(this.events).isEmpty();
    assertThat(backend.getClient(SP_THREE)).isNotNull();
  }

  @Test
  void anMdqSourceCannotListItsServiceProviders() throws Exception {
    final AtomicReference<String> content = new AtomicReference<>(metadata(SP_ONE));
    final int port = this.startServer(content, new AtomicInteger(404));
    final List<ManagedMetadataSource> sources = MetadataProviderFactory.createManagedSources(List.of(
        MetadataSource.builder(new UrlResource("http://localhost:%d/mdq".formatted(port))).mdq(true).build()), null);
    final SamlMetadataBackend backend = new SamlMetadataBackend(sources);
    backend.setClientChangeTracker(this.tracker());

    assertThat(sources.get(0).isListable()).isFalse();
    assertThat(sources.get(0).isRefreshable()).isFalse();
    assertThat(backend.getSources()).singleElement().extracting(ClientSource::clients).isNull();
    assertThat(this.events).isEmpty();
  }

  @Test
  void aResolverGivenByTheApplicationIsOneSource() {
    final SamlMetadataBackend backend = new SamlMetadataBackend(MetadataProviderFactory.createMetadataResolver(
        List.of(MetadataSource.builder(new ClassPathResource("metadata/sp-metadata.xml")).build()), null));
    backend.setClientChangeTracker(this.tracker());

    assertThat(backend.getMetadataSources()).singleElement()
        .satisfies(s -> assertThat(s.getProvider()).isNull())
        .satisfies(s -> assertThat(s.isListable()).isTrue());
    assertThat(backend.getClients()).hasSize(2);
    assertThat(this.added()).containsExactlyInAnyOrder(SP_ONE, SP_TWO);

    backend.setClientChangeTracker(null);
  }

  private ClientChangeTracker tracker() {
    final ClientChangeTracker tracker = new ClientChangeTracker(new InMemoryKnownClientStore());
    tracker.setApplicationEventPublisher(e -> this.events.add((ApplicationEvent) e));
    tracker.start();
    return tracker;
  }

  private List<String> added() {
    return this.events.stream()
        .filter(ClientAddedEvent.class::isInstance)
        .map(e -> ((ClientAddedEvent) e).getClient().identifier())
        .toList();
  }

  private List<String> removed() {
    return this.events.stream()
        .filter(ClientRemovedEvent.class::isInstance)
        .map(e -> ((ClientRemovedEvent) e).getClient().identifier())
        .toList();
  }

  /**
   * Creates a metadata document holding Service Providers.
   *
   * @param entityIds the entityIDs
   * @return the metadata
   */
  static String metadata(final String... entityIds) {
    final StringBuilder sb = new StringBuilder("""
        <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
        """);
    for (final String entityId : entityIds) {
      sb.append("""
            <md:EntityDescriptor entityID="%s">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="%s/acs" index="0"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
          """.formatted(entityId, entityId));
    }
    return sb.append("</md:EntitiesDescriptor>\n").toString();
  }

  /**
   * Starts an HTTP server that answers with the given content, or with the given status if it is not 200.
   *
   * @param content the content
   * @param status the status
   * @return the port
   * @throws IOException if the server cannot be started
   */
  private int startServer(final AtomicReference<String> content, final AtomicInteger status) throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", exchange -> {
      if (status.get() != 200) {
        exchange.sendResponseHeaders(status.get(), -1);
        exchange.close();
        return;
      }
      final byte[] body = content.get().getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/samlmetadata+xml");
      exchange.sendResponseHeaders(200, body.length);
      try (final OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    this.server.start();
    return this.server.getAddress().getPort();
  }

}
