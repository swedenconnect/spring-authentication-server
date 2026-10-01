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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.httpclient.HttpClientSupport;
import net.shibboleth.shared.httpclient.TLSSocketFactoryBuilder;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MDQMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;

/**
 * Creates the OpenSAML {@link MetadataProvider} that serves the configured {@link MetadataSource}s. Several sources
 * are combined into one provider where the sources are searched in the order they were given.
 *
 * @author Martin Lindström
 */
public class MetadataProviderFactory {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(MetadataProviderFactory.class);

  /**
   * Creates an initialized {@link MetadataProvider} for the supplied sources.
   * <p>
   * The caller owns the provider and is responsible for destroying it.
   * </p>
   *
   * @param sources the metadata sources
   * @param sslBundles the SSL bundles of the application, needed if a source names one, otherwise {@code null}
   * @return an initialized {@link MetadataProvider}
   */
  public static @NonNull MetadataProvider createMetadataProvider(
      final @NonNull List<MetadataSource> sources, final @Nullable SslBundles sslBundles) {
    return combine(createManagedSources(sources, sslBundles));
  }

  /**
   * Creates a {@link MetadataResolver} for the supplied sources.
   *
   * @param sources the metadata sources
   * @param sslBundles the SSL bundles of the application, needed if a source names one, otherwise {@code null}
   * @return a {@link MetadataResolver}
   */
  public static @NonNull MetadataResolver createMetadataResolver(
      final @NonNull List<MetadataSource> sources, final @Nullable SslBundles sslBundles) {
    return createMetadataProvider(sources, sslBundles).getMetadataResolver();
  }

  /**
   * Creates one initialized {@link ManagedMetadataSource} for each of the supplied sources, in the same order. Each
   * source tells its listener when it has read new metadata, except an MDQ source.
   *
   * @param sources the metadata sources
   * @param sslBundles the SSL bundles of the application, needed if a source names one, otherwise {@code null}
   * @return the managed sources
   */
  public static @NonNull List<ManagedMetadataSource> createManagedSources(
      final @NonNull List<MetadataSource> sources, final @Nullable SslBundles sslBundles) {

    Objects.requireNonNull(sources, "sources must not be null");
    if (sources.isEmpty()) {
      throw new IllegalArgumentException("At least one metadata source must be given");
    }
    try {
      final List<ManagedMetadataSource> managed = new ArrayList<>();
      for (final MetadataSource source : sources) {
        final AtomicReference<ManagedMetadataSource> reference = new AtomicReference<>();
        final DownloadRecordingHttpClient.DownloadRecord downloads = new DownloadRecordingHttpClient.DownloadRecord();
        final AbstractMetadataProvider provider = createProvider(source, sslBundles, downloads, m -> {
          final ManagedMetadataSource s = reference.get();
          if (s != null) {
            s.metadataLoaded(m);
          }
        });
        provider.setPerformSchemaValidation(false);
        provider.initialize();
        final ManagedMetadataSource s = new ManagedMetadataSource(getName(source.location()), provider,
            provider instanceof MDQMetadataProvider,
            provider instanceof HTTPMetadataProvider || provider instanceof MDQMetadataProvider ? downloads : null);
        reference.set(s);
        managed.add(s);
      }
      return managed;
    }
    catch (final ResolverException | ComponentInitializationException | IOException | XMLParserException e) {
      throw new IllegalArgumentException("Failed to initialize metadata provider - " + e.getMessage(), e);
    }
  }

  /**
   * Combines the providers of several managed sources into one, where the sources are searched in the order they are
   * given. A single source gives its own provider.
   *
   * @param sources the managed sources, each with a provider
   * @return an initialized {@link MetadataProvider}
   * @throws IllegalArgumentException if a source has no provider, or the providers cannot be combined
   */
  public static @NonNull MetadataProvider combine(final @NonNull List<ManagedMetadataSource> sources) {
    final List<MetadataProvider> providers = new ArrayList<>();
    for (final ManagedMetadataSource source : sources) {
      if (source.getProvider() == null) {
        throw new IllegalArgumentException("The metadata source '%s' has no provider".formatted(source.getName()));
      }
      providers.add(source.getProvider());
    }
    if (providers.size() == 1) {
      return providers.get(0);
    }
    try {
      final CompositeMetadataProvider composite = new CompositeMetadataProvider("composite-provider", providers);
      composite.initialize();
      return composite;
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize metadata provider - " + e.getMessage(), e);
    }
  }

  /**
   * Gets the name of a source from its location: the URL, the file path or the classpath resource.
   *
   * @param location the location
   * @return the name
   */
  static @NonNull String getName(final @NonNull Resource location) {
    if (location instanceof final FileSystemResource file) {
      return file.getPath();
    }
    if (location instanceof final ClassPathResource classPath) {
      return "classpath:" + classPath.getPath();
    }
    try {
      if (location instanceof final UrlResource url) {
        return url.isFile() ? url.getFile().getPath() : url.getURL().toString();
      }
    }
    catch (final IOException e) {
      // The description is used instead
    }
    return location.getDescription();
  }

  /**
   * Creates the provider for one source.
   *
   * @param source the metadata source
   * @param sslBundles the SSL bundles of the application
   * @param downloads where the outcome of the downloads of the source is recorded
   * @param listener told every time the provider has read new metadata
   * @return an uninitialized {@link AbstractMetadataProvider}
   * @throws ResolverException for provider errors
   * @throws IOException if the location cannot be read
   * @throws XMLParserException if the metadata cannot be parsed
   */
  private static @NonNull AbstractMetadataProvider createProvider(
      final @NonNull MetadataSource source, final @Nullable SslBundles sslBundles,
      final DownloadRecordingHttpClient.@NonNull DownloadRecord downloads, final @NonNull Consumer<XMLObject> listener)
      throws ResolverException, IOException, XMLParserException {

    if (source.location() instanceof final UrlResource urlResource && !urlResource.isFile()) {
      if (source.backupLocation() == null) {
        log.warn("No backup location for metadata source {} - using a backup location is strongly recommended",
            source.location());
      }
      final AbstractMetadataProvider provider;
      if (source.mdq()) {
        provider = new MDQMetadataProvider(urlResource.getURL().toString(),
            new DownloadRecordingHttpClient(createHttpClient(source, sslBundles), downloads, true),
            preProcessBackupDirectory(source.backupLocation()));
      }
      else {
        provider = new HTTPMetadataProvider(urlResource.getURL().toString(),
            preProcessBackupFile(source.backupLocation()),
            new DownloadRecordingHttpClient(createHttpClient(source, sslBundles), downloads, false)) {
          @Override
          protected synchronized void setMetadata(final XMLObject metadata) {
            super.setMetadata(metadata);
            listener.accept(metadata);
          }
        };
      }
      if (source.validationCertificate() != null) {
        provider.setSignatureVerificationCertificate(source.validationCertificate());
      }
      else {
        log.warn("No validation certificate assigned for metadata source {} - downloaded metadata can not be trusted",
            source.location());
      }
      return provider;
    }
    if (source.location() instanceof FileSystemResource
        || source.location() instanceof final UrlResource fileUrl && fileUrl.isFile()) {
      return new FilesystemMetadataProvider(source.location().getFile()) {
        @Override
        protected synchronized void setMetadata(final XMLObject metadata) {
          super.setMetadata(metadata);
          listener.accept(metadata);
        }
      };
    }
    final Document document = Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool())
        .parse(source.location().getInputStream());
    return new StaticMetadataProvider(document.getDocumentElement()) {
      @Override
      protected synchronized void setMetadata(final XMLObject metadata) {
        super.setMetadata(metadata);
        listener.accept(metadata);
      }
    };
  }

  /**
   * Creates the HTTP client that a downloading provider uses.
   *
   * @param source the metadata source
   * @param sslBundles the SSL bundles of the application
   * @return an {@link HttpClient}
   */
  private static @NonNull HttpClient createHttpClient(
      final @NonNull MetadataSource source, final @Nullable SslBundles sslBundles) {
    try {
      final List<TrustManager> managers;
      if (source.httpsTrustBundle() != null) {
        if (sslBundles == null) {
          throw new IllegalArgumentException("SSL bundle %s could not be found".formatted(source.httpsTrustBundle()));
        }
        try {
          managers = Arrays.asList(
              sslBundles.getBundle(source.httpsTrustBundle()).getManagers().getTrustManagers());
        }
        catch (final NoSuchSslBundleException e) {
          throw new IllegalArgumentException("SSL bundle %s could not be found".formatted(source.httpsTrustBundle()));
        }
      }
      else {
        managers = List.of(HttpClientSupport.buildNoTrustX509TrustManager());
      }
      final HostnameVerifier hostnameVerifier = source.skipHostnameVerification()
          ? new NoopHostnameVerifier()
          : new DefaultHostnameVerifier();

      final HttpClientBuilder builder = new HttpClientBuilder();
      builder.setUseSystemProperties(true);
      final MetadataSource.HttpProxy proxy = source.httpProxy();
      if (proxy != null) {
        builder.setConnectionProxyHost(proxy.host());
        builder.setConnectionProxyPort(proxy.port());
        if (StringUtils.hasText(proxy.userName())) {
          builder.setConnectionProxyUsername(proxy.userName());
        }
        if (StringUtils.hasText(proxy.password())) {
          builder.setConnectionProxyPassword(proxy.password());
        }
      }
      builder.setTLSSocketFactory(new TLSSocketFactoryBuilder()
          .setHostnameVerifier(hostnameVerifier)
          .setTrustManagers(managers)
          .build());

      return builder.buildClient();
    }
    catch (final IllegalArgumentException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }

  /**
   * Makes sure that the directories above the backup file exist.
   *
   * @param backupFile the backup file, or {@code null}
   * @return the absolute path of the backup file, or {@code null}
   */
  private static @Nullable String preProcessBackupFile(final @Nullable File backupFile) {
    if (backupFile == null) {
      return null;
    }
    preProcessBackupDirectory(backupFile.getParentFile());
    return backupFile.getAbsolutePath();
  }

  /**
   * Makes sure that the backup directory exists.
   *
   * @param backupDirectory the backup directory, or {@code null}
   * @return the absolute path of the backup directory, or {@code null}
   */
  private static @Nullable String preProcessBackupDirectory(final @Nullable File backupDirectory) {
    if (backupDirectory == null) {
      return null;
    }
    try {
      final Path path = backupDirectory.toPath();
      Files.createDirectories(path);
      return path.toFile().getAbsolutePath();
    }
    catch (final IOException e) {
      throw new IllegalArgumentException("Invalid backup location: " + backupDirectory, e);
    }
  }

  // Hidden constructor
  private MetadataProviderFactory() {
  }

}
