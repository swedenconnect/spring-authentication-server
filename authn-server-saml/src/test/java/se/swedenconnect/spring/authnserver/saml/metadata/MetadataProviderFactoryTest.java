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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;

/**
 * Tests that a Service Provider is found through each kind of metadata source.
 *
 * @author Martin Lindström
 */
class MetadataProviderFactoryTest extends OpenSamlTestBase {

  private static final String SP_ONE = "https://sp-one.example.com";

  private static final String SP_TWO = "https://sp-two.example.com";

  private static final String SP_THREE = "https://sp-three.example.com";

  private static final String METADATA_CONTENT_TYPE = "application/samlmetadata+xml";

  /** The provider of the test, destroyed when the test is done. */
  private MetadataProvider provider;

  /** The HTTP server of the test, stopped when the test is done. */
  private HttpServer server;

  @AfterEach
  void cleanUp() {
    if (this.provider != null) {
      this.provider.destroy();
      this.provider = null;
    }
    if (this.server != null) {
      this.server.stop(0);
      this.server = null;
    }
  }

  @Test
  void aServiceProviderIsFoundInAFile(@TempDir final Path directory) throws Exception {
    final File file = directory.resolve("sp-metadata.xml").toFile();
    Files.copy(new ClassPathResource("metadata/sp-metadata.xml").getInputStream(), file.toPath());

    final SamlMetadataBackend backend = this.backend(
        MetadataSource.builder(new FileSystemResource(file)).build());

    assertThat(backend.lookup(SP_ONE)).isNotNull();
    assertThat(backend.lookup(SP_TWO)).isNotNull();
    assertThat(backend.lookup(SP_THREE)).isNull();
  }

  @Test
  void aServiceProviderIsFoundInAStaticResource() {
    final SamlMetadataBackend backend = this.backend(
        MetadataSource.builder(new ClassPathResource("metadata/sp-metadata.xml")).build());

    final RequesterRecord record = backend.lookup(SP_ONE);

    assertThat(record).isNotNull();
    assertThat(record.getDisplayName("en")).isEqualTo("Service One");
    assertThat(record.marks()).containsExactlyInAnyOrder(
        "http://id.elegnamnden.se/ec/1.0/loa3-pnr", "http://id.elegnamnden.se/sprop/1.0/mobile-auth");
    assertThat(record.getLogo("sv").url()).isEqualTo("https://sp-one.example.com/logo-sv.svg");

    final RequesterRecord two = backend.lookup(SP_TWO);
    assertThat(two).isNotNull();
    assertThat(two.getDisplayName("sv")).isEqualTo("Org Två");
    assertThat(two.getDisplayName("en")).isEqualTo("Organisation Two");
    assertThat(two.marks()).isEmpty();
  }

  @Test
  void severalSourcesAreCombinedIntoOne() {
    final SamlMetadataBackend backend = this.backend(
        MetadataSource.builder(new ClassPathResource("metadata/sp-metadata.xml")).build(),
        MetadataSource.builder(new ClassPathResource("metadata/sp-three.xml")).build());

    assertThat(backend.lookup(SP_ONE)).isNotNull();
    assertThat(backend.lookup(SP_TWO)).isNotNull();
    assertThat(backend.lookup(SP_THREE)).isNotNull();
    assertThat(backend.lookup("https://sp-four.example.com")).isNull();
  }

  @Test
  void aServiceProviderIsFoundInDownloadedFederationMetadata(@TempDir final Path directory) throws Exception {
    final byte[] metadata = new ClassPathResource("metadata/sp-metadata.xml").getContentAsByteArray();
    final int port = this.startServer(exchange -> respond(exchange, metadata));
    final File backup = directory.resolve("backup/federation.xml").toFile();

    final SamlMetadataBackend backend = this.backend(
        MetadataSource.builder(new UrlResource("http://localhost:%d/metadata".formatted(port)))
            .backupLocation(backup)
            .build());

    assertThat(backend.lookup(SP_ONE)).isNotNull();
    assertThat(backend.lookup(SP_TWO)).isNotNull();
    assertThat(backup).exists();
  }

  @Test
  void aServiceProviderIsFoundThroughMdq(@TempDir final Path directory) throws Exception {
    final byte[] metadata = new ClassPathResource("metadata/sp-three.xml").getContentAsByteArray();
    final String path = "/mdq/entities/" + URLEncoder.encode(SP_THREE, StandardCharsets.UTF_8);
    final int port = this.startServer(exchange -> {
      if (path.equals(exchange.getRequestURI().getRawPath())) {
        respond(exchange, metadata);
      }
      else {
        exchange.sendResponseHeaders(404, -1);
        exchange.close();
      }
    });

    final SamlMetadataBackend backend = this.backend(
        MetadataSource.builder(new UrlResource("http://localhost:%d/mdq".formatted(port)))
            .mdq(true)
            .backupLocation(directory.resolve("mdq-backup").toFile())
            .build());

    final RequesterRecord record = backend.lookup(SP_THREE);

    assertThat(record).isNotNull();
    assertThat(record.getDisplayName("en")).isEqualTo("Service Three");
    assertThat(backend.lookup("https://sp-unknown.example.com")).isNull();
    assertThat(directory.resolve("mdq-backup")).exists();
  }

  @Test
  void aDownloadingSourceWithoutBackupLocationAndValidationCertificateIsWarnedAbout() throws Exception {
    final byte[] metadata = new ClassPathResource("metadata/sp-metadata.xml").getContentAsByteArray();
    final int port = this.startServer(exchange -> respond(exchange, metadata));

    final Logger logger = (Logger) LoggerFactory.getLogger(MetadataProviderFactory.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      this.backend(MetadataSource.builder(new UrlResource("http://localhost:%d/metadata".formatted(port))).build());
    }
    finally {
      logger.detachAppender(appender);
    }

    assertThat(appender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .anySatisfy(message -> assertThat(message).contains("No backup location"))
        .anySatisfy(message -> assertThat(message).contains("No validation certificate"));
  }

  @Test
  void atLeastOneSourceIsRequired() {
    assertThatThrownBy(() -> MetadataProviderFactory.createMetadataResolver(List.of(), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aSourceThatCannotBeReadIsAnError() {
    assertThatThrownBy(() -> MetadataProviderFactory.createMetadataResolver(
        List.of(MetadataSource.builder(new ClassPathResource("metadata/does-not-exist.xml")).build()), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void anSslBundleThatDoesNotExistIsAnError() throws Exception {
    final MetadataSource source = MetadataSource.builder(new UrlResource("https://localhost:1/metadata"))
        .httpsTrustBundle("no-such-bundle")
        .build();
    assertThatThrownBy(() -> MetadataProviderFactory.createMetadataResolver(List.of(source), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("no-such-bundle");
  }

  /**
   * Creates the backend for the supplied sources.
   *
   * @param sources the metadata sources
   * @return a {@link SamlMetadataBackend}
   */
  private SamlMetadataBackend backend(final MetadataSource... sources) {
    this.provider = MetadataProviderFactory.createMetadataProvider(List.of(sources), null);
    final MetadataResolver resolver = this.provider.getMetadataResolver();
    return new SamlMetadataBackend(resolver);
  }

  /**
   * Starts an HTTP server on a free port.
   *
   * @param handler what the server does with a request
   * @return the port that the server listens on
   * @throws IOException if the server cannot be started
   */
  private int startServer(final Handler handler) throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", exchange -> {
      try {
        handler.handle(exchange);
      }
      catch (final IOException e) {
        exchange.close();
      }
    });
    this.server.start();
    return this.server.getAddress().getPort();
  }

  /**
   * Answers with the supplied metadata.
   *
   * @param exchange the request
   * @param metadata the metadata to answer with
   * @throws IOException for write errors
   */
  private static void respond(final HttpExchange exchange, final byte[] metadata) throws IOException {
    exchange.getResponseHeaders().add("Content-Type", METADATA_CONTENT_TYPE);
    exchange.sendResponseHeaders(200, metadata.length);
    try (final OutputStream out = exchange.getResponseBody()) {
      out.write(metadata);
    }
  }

  /**
   * What the test server does with a request.
   */
  private interface Handler {

    /**
     * Handles a request.
     *
     * @param exchange the request
     * @throws IOException for read and write errors
     */
    void handle(HttpExchange exchange) throws IOException;

  }

}
