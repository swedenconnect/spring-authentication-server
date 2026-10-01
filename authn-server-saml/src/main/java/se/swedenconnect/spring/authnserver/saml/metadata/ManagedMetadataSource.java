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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.RefreshableMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;

/**
 * One source of SAML metadata as the server runs it: its name, the OpenSAML resolver that reads it and the state of
 * its latest download.
 * <p>
 * A source created by {@link MetadataProviderFactory#createManagedSources} tells its listener every time it has read
 * new metadata, see {@link #setListener(Consumer)}. A source that wraps a resolver given by the application cannot;
 * its clients are only compared after an update through {@link SamlMetadataBackend#update()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class ManagedMetadataSource {

  /** The name of the source. */
  private final String name;

  /** The provider, or {@code null} if the source wraps a resolver given by the application. */
  private final MetadataProvider provider;

  /** The resolver. */
  private final MetadataResolver resolver;

  /** Whether the source is queried entity by entity, so that it cannot list its Service Providers. */
  private final boolean mdq;

  /** The outcome of the downloads of the source, or {@code null} if it is not downloaded. */
  private final DownloadRecordingHttpClient.DownloadRecord downloads;

  /** Told when the source has read new metadata, or {@code null}. */
  private volatile Consumer<List<EntityDescriptor>> listener;

  /**
   * Constructor.
   *
   * @param name the name of the source
   * @param provider the provider
   * @param mdq whether the source is queried with the MDQ protocol
   */
  public ManagedMetadataSource(final @NonNull String name, final @NonNull MetadataProvider provider,
      final boolean mdq) {
    this(name, provider, mdq, null);
  }

  /**
   * Constructor.
   *
   * @param name the name of the source
   * @param provider the provider
   * @param mdq whether the source is queried with the MDQ protocol
   * @param downloads the outcome of the downloads of the source, or {@code null} if it is not downloaded
   */
  ManagedMetadataSource(final @NonNull String name, final @NonNull MetadataProvider provider, final boolean mdq,
      final DownloadRecordingHttpClient.@Nullable DownloadRecord downloads) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.provider = Objects.requireNonNull(provider, "provider must not be null");
    this.resolver = provider.getMetadataResolver();
    this.mdq = mdq;
    this.downloads = downloads;
  }

  /**
   * Constructor for a source that wraps a resolver given by the application.
   *
   * @param name the name of the source
   * @param resolver the resolver
   */
  public ManagedMetadataSource(final @NonNull String name, final @NonNull MetadataResolver resolver) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.provider = null;
    this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
    this.mdq = false;
    this.downloads = null;
  }

  /**
   * Gets the name of the source: its URL, file or resource.
   *
   * @return the name
   */
  public @NonNull String getName() {
    return this.name;
  }

  /**
   * Gets the provider of the source.
   *
   * @return the provider, or {@code null} if the source wraps a resolver given by the application
   */
  public @Nullable MetadataProvider getProvider() {
    return this.provider;
  }

  /**
   * Gets the resolver of the source.
   *
   * @return the resolver
   */
  public @NonNull MetadataResolver getResolver() {
    return this.resolver;
  }

  /**
   * Tells whether the source can list every Service Provider it holds. An MDQ source holds only those it has been
   * asked for, and a resolver that cannot be iterated holds none that can be listed.
   *
   * @return {@code true} if the source can list its Service Providers
   */
  public boolean isListable() {
    return !this.mdq && (this.provider != null || this.resolver instanceof IterableMetadataSource);
  }

  /**
   * Gets the Service Providers that the source holds now. An MDQ source gives those it has read.
   *
   * @return the Service Provider metadata
   */
  public @NonNull List<EntityDescriptor> getServiceProviders() {
    final List<EntityDescriptor> result = new ArrayList<>();
    final Iterable<EntityDescriptor> entities;
    if (this.provider != null) {
      entities = this.provider.iterator(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }
    else if (this.resolver instanceof final IterableMetadataSource iterable) {
      entities = iterable;
    }
    else {
      return result;
    }
    for (final EntityDescriptor entity : entities) {
      if (isServiceProvider(entity)) {
        result.add(entity);
      }
    }
    return result;
  }

  /**
   * Tells whether the source can be updated on request.
   *
   * @return {@code true} if the source can be updated
   */
  public boolean isRefreshable() {
    return this.resolver instanceof RefreshableMetadataResolver;
  }

  /**
   * Updates the source: downloads or reads the metadata again.
   *
   * @throws ResolverException if the update fails
   * @throws IllegalStateException if the source cannot be updated
   */
  public void refresh() throws ResolverException {
    if (!(this.resolver instanceof final RefreshableMetadataResolver refreshable)) {
      throw new IllegalStateException("The metadata source '%s' cannot be updated".formatted(this.name));
    }
    refreshable.refresh();
    if (Boolean.FALSE.equals(this.wasLastRefreshSuccessful())) {
      final String failure = this.getLastFailure();
      throw new ResolverException("Failed to update the metadata source '%s'%s".formatted(this.name,
          failure != null ? " - " + failure : ""));
    }
  }

  /**
   * Gets when the metadata of the source last changed.
   *
   * @return the time, or {@code null} if not known
   */
  public @Nullable Instant getLastUpdate() {
    if (this.resolver instanceof final RefreshableMetadataResolver refreshable) {
      return refreshable.getLastUpdate();
    }
    return this.provider != null ? this.provider.getLastUpdate() : null;
  }

  /**
   * Gets when the source was last downloaded or read, successfully or not.
   *
   * @return the time, or {@code null} if the source is not refreshed
   */
  public @Nullable Instant getLastRefresh() {
    if (this.downloads != null && this.downloads.getLastAttempt() != null) {
      return this.downloads.getLastAttempt();
    }
    return this.resolver instanceof final RefreshableMetadataResolver refreshable ? refreshable.getLastRefresh() : null;
  }

  /**
   * Gets when the source was last downloaded or read successfully.
   *
   * @return the time, or {@code null} if the source is not refreshed or never succeeded
   */
  public @Nullable Instant getLastSuccessfulRefresh() {
    if (this.downloads != null && this.downloads.getLastAttempt() != null) {
      return this.downloads.getLastSuccess();
    }
    return this.resolver instanceof final RefreshableMetadataResolver refreshable
        ? refreshable.getLastSuccessfulRefresh()
        : null;
  }

  /**
   * Tells whether the latest download or read succeeded. For a downloaded source it is the download itself that
   * counts, also when the resolver falls back to the metadata it holds or to its backup file.
   *
   * @return {@code true} or {@code false}, or {@code null} if the source is not refreshed or has not been yet
   */
  public @Nullable Boolean wasLastRefreshSuccessful() {
    if (this.downloads != null && this.downloads.getLastAttempt() != null) {
      return this.downloads.getLastError() == null;
    }
    return this.resolver instanceof final RefreshableMetadataResolver refreshable
        ? refreshable.wasLastRefreshSuccess()
        : null;
  }

  /**
   * Gets why the latest download or read failed.
   *
   * @return a description of the failure, or {@code null} if the latest one succeeded
   */
  public @Nullable String getLastFailure() {
    if (this.downloads != null && this.downloads.getLastAttempt() != null) {
      return this.downloads.getLastError();
    }
    if (this.resolver instanceof final RefreshableMetadataResolver refreshable
        && Boolean.FALSE.equals(refreshable.wasLastRefreshSuccess())) {
      final Throwable cause = refreshable.getLastFailureCause();
      return cause != null ? cause.getMessage() : "The latest update failed";
    }
    return null;
  }

  /**
   * Gets when the metadata held by the source expires, according to its {@code validUntil} and
   * {@code cacheDuration}.
   *
   * @return the time, or {@code null} if not known
   */
  public @Nullable Instant getExpirationTime() {
    return this.resolver instanceof final AbstractReloadingMetadataResolver reloading
        ? reloading.getExpirationTime()
        : null;
  }

  /**
   * Assigns the listener that is told, with the Service Providers of the new metadata, every time the source has read
   * new metadata. Only a listable source created by {@link MetadataProviderFactory} tells its listener.
   *
   * @param listener the listener, or {@code null}
   */
  public void setListener(final @Nullable Consumer<List<EntityDescriptor>> listener) {
    this.listener = listener;
  }

  /**
   * Invoked by the provider when it has read new metadata.
   *
   * @param metadata the metadata, after the filters of the provider have been applied
   */
  void metadataLoaded(final @Nullable XMLObject metadata) {
    final Consumer<List<EntityDescriptor>> current = this.listener;
    if (current == null || metadata == null || this.mdq) {
      return;
    }
    final List<EntityDescriptor> serviceProviders = new ArrayList<>();
    collect(metadata, serviceProviders);
    current.accept(serviceProviders);
  }

  /**
   * Collects the Service Providers of a metadata document.
   *
   * @param metadata an {@code EntitiesDescriptor} or an {@code EntityDescriptor}
   * @param result where they are collected
   */
  private static void collect(final @NonNull XMLObject metadata, final @NonNull List<EntityDescriptor> result) {
    if (metadata instanceof final EntityDescriptor entity) {
      if (isServiceProvider(entity)) {
        result.add(entity);
      }
    }
    else if (metadata instanceof final EntitiesDescriptor entities) {
      entities.getEntityDescriptors().forEach(e -> collect(e, result));
      entities.getEntitiesDescriptors().forEach(e -> collect(e, result));
    }
  }

  /**
   * Tells whether an entity is a Service Provider.
   *
   * @param entity the entity
   * @return {@code true} if it has an {@code SPSSODescriptor}
   */
  private static boolean isServiceProvider(final @NonNull EntityDescriptor entity) {
    return !entity.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).isEmpty();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return this.name;
  }

}
