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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.SerializeSupport;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.metadata.ext.OrganizationNumber;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.ClientSource;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * The client registry backend that serves SAML Service Providers from the Identity Provider's metadata sources.
 * <p>
 * The protocol metadata of the record is the Service Provider's {@link EntityDescriptor}. Display names are taken
 * from the {@code mdui:UIInfo} extension, then from {@code Organization/OrganizationDisplayName} and finally from
 * {@code Organization/OrganizationName}, and logotypes from {@code mdui:UIInfo}. The marks of the record are the
 * entity category URIs that the Service Provider declares.
 * </p>
 * <p>
 * Created from {@link ManagedMetadataSource}s, the backend can show what each source holds, update the sources on
 * request, and report every Service Provider that appears in or disappears from a source to the
 * {@link ClientChangeTracker}. Created from a {@link MetadataResolver}, the resolver is treated as one source.
 * </p>
 *
 * @author Martin Lindström
 */
public class SamlMetadataBackend implements ClientRegistryBackend {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SamlMetadataBackend.class);

  /** The default backend name. */
  public static final String DEFAULT_NAME = "saml-metadata";

  /** Where Service Provider metadata is found. */
  private final MetadataResolver metadataResolver;

  /** The sources, in the order they are searched. */
  private final List<ManagedMetadataSource> sources;

  /** The backend name. */
  private final String name;

  /** Told when a Service Provider appears or disappears, or {@code null}. */
  private volatile ClientChangeTracker tracker;

  /**
   * Constructor.
   *
   * @param metadataResolver where Service Provider metadata is found
   */
  public SamlMetadataBackend(final @NonNull MetadataResolver metadataResolver) {
    this(metadataResolver, DEFAULT_NAME);
  }

  /**
   * Constructor.
   *
   * @param metadataResolver where Service Provider metadata is found
   * @param name the backend name
   */
  public SamlMetadataBackend(final @NonNull MetadataResolver metadataResolver, final @NonNull String name) {
    this.metadataResolver = Objects.requireNonNull(metadataResolver, "metadataResolver must not be null");
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.sources = List.of(new ManagedMetadataSource(
        Optional.ofNullable(metadataResolver.getId()).orElse(name), metadataResolver));
  }

  /**
   * Constructor.
   *
   * @param sources the metadata sources, in the order they are searched, see
   *     {@link MetadataProviderFactory#createManagedSources(List, org.springframework.boot.ssl.SslBundles)}
   */
  public SamlMetadataBackend(final @NonNull List<ManagedMetadataSource> sources) {
    this(sources, DEFAULT_NAME);
  }

  /**
   * Constructor.
   *
   * @param sources the metadata sources, in the order they are searched
   * @param name the backend name
   */
  public SamlMetadataBackend(final @NonNull List<ManagedMetadataSource> sources, final @NonNull String name) {
    this.sources = List.copyOf(Objects.requireNonNull(sources, "sources must not be null"));
    if (this.sources.isEmpty()) {
      throw new IllegalArgumentException("At least one metadata source must be given");
    }
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.metadataResolver = this.sources.size() == 1
        ? this.sources.get(0).getResolver()
        : MetadataProviderFactory.combine(this.sources).getMetadataResolver();
  }

  /**
   * Gets the metadata sources, in the order they are searched.
   *
   * @return the sources
   */
  public @NonNull List<ManagedMetadataSource> getMetadataSources() {
    return this.sources;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.SAML;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull String identifier) throws ClientRegistryException {
    Objects.requireNonNull(identifier, "identifier must not be null");
    final EntityDescriptor metadata;
    try {
      metadata = this.metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(identifier)));
    }
    catch (final ResolverException e) {
      throw new ClientRegistryException(
          "Failed to read metadata for '%s' - %s".formatted(identifier, e.getMessage()), e);
    }
    if (metadata == null) {
      log.debug("No metadata found for '{}'", identifier);
      return null;
    }
    return toRecord(metadata);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<RegisteredClient> getClients() {
    final Map<String, RegisteredClient> clients = new LinkedHashMap<>();
    for (final ManagedMetadataSource source : this.sources) {
      for (final EntityDescriptor metadata : source.getServiceProviders()) {
        clients.putIfAbsent(metadata.getEntityID(), toRegisteredClient(metadata, source));
      }
    }
    return List.copyOf(clients.values());
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RegisteredClient getClient(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    for (final ManagedMetadataSource source : this.sources) {
      final EntityDescriptor metadata = find(source, identifier);
      if (metadata != null) {
        return toRegisteredClient(metadata, source);
      }
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable String getMetadata(final @NonNull String identifier) {
    Objects.requireNonNull(identifier, "identifier must not be null");
    for (final ManagedMetadataSource source : this.sources) {
      final EntityDescriptor metadata = find(source, identifier);
      if (metadata != null) {
        try {
          return SerializeSupport.nodeToString(XMLObjectSupport.marshall(metadata));
        }
        catch (final MarshallingException e) {
          throw new IllegalStateException(
              "Failed to serialize the metadata of '%s' - %s".formatted(identifier, e.getMessage()), e);
        }
      }
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<ClientSource> getSources() {
    return this.sources.stream()
        .map(s -> new ClientSource(AuthenticationProtocol.SAML, s.getName(),
            s.isListable() ? s.getServiceProviders().size() : null, s.getLastUpdate()))
        .toList();
  }

  /**
   * Updates every source that can be updated, that is, every source that is downloaded or read from a file. The
   * Service Providers of each updated source are compared with those known before, so that changes are reported.
   */
  @Override
  public @NonNull ClientUpdateResult update() {
    final List<String> updated = new ArrayList<>();
    final List<String> failed = new ArrayList<>();
    for (final ManagedMetadataSource source : this.sources) {
      if (!source.isRefreshable()) {
        continue;
      }
      try {
        source.refresh();
        updated.add(source.getName());
        log.info("The SAML metadata source '{}' was updated on request", source.getName());
      }
      catch (final ResolverException | RuntimeException e) {
        failed.add("%s (%s)".formatted(source.getName(), e.getMessage()));
        log.info("Failed to update the SAML metadata source '{}' on request: {}", source.getName(), e.getMessage());
      }
      this.report(source);
    }
    if (!failed.isEmpty()) {
      return ClientUpdateResult.failed("Failed to update %s%s".formatted(String.join(", ", failed),
          updated.isEmpty() ? "" : " - updated " + String.join(", ", updated)));
    }
    if (updated.isEmpty()) {
      return ClientUpdateResult.nothingToUpdate("No SAML metadata source can be updated");
    }
    return ClientUpdateResult.updated("Updated " + String.join(", ", updated));
  }

  /**
   * Updating a single Service Provider is not supported; use {@link #update()}.
   */
  @Override
  public @NonNull ClientUpdateResult update(final @NonNull String identifier) {
    return ClientUpdateResult.nothingToUpdate(
        "A single Service Provider cannot be updated - update the SAML metadata sources instead");
  }

  /**
   * Reports the Service Providers of every listable source to the tracker, and every change after that.
   */
  @Override
  public void setClientChangeTracker(final @Nullable ClientChangeTracker tracker) {
    this.tracker = tracker;
    for (final ManagedMetadataSource source : this.sources) {
      if (!source.isListable()) {
        source.setListener(null);
        continue;
      }
      if (tracker == null) {
        source.setListener(null);
      }
      else {
        source.setListener(serviceProviders -> this.report(source, serviceProviders));
        this.report(source);
      }
    }
  }

  /**
   * Reports the Service Providers that a source holds now to the tracker.
   *
   * @param source the source
   */
  private void report(final @NonNull ManagedMetadataSource source) {
    if (this.tracker != null && source.isListable()) {
      this.report(source, source.getServiceProviders());
    }
  }

  /**
   * Reports the Service Providers of a source to the tracker.
   *
   * @param source the source
   * @param serviceProviders the Service Providers that the source holds
   */
  private void report(final @NonNull ManagedMetadataSource source,
      final @NonNull List<EntityDescriptor> serviceProviders) {
    final ClientChangeTracker current = this.tracker;
    if (current == null) {
      return;
    }
    try {
      current.sourceLoaded(AuthenticationProtocol.SAML, source.getName(), serviceProviders.stream()
          .filter(e -> e.getEntityID() != null)
          .map(e -> new KnownClient(new Requester(AuthenticationProtocol.SAML, e.getEntityID()),
              getOrganizationNumber(e), source.getName()))
          .toList());
    }
    catch (final RuntimeException e) {
      log.error("Failed to compare the Service Providers of '{}' with those known before: {}", source.getName(),
          e.getMessage(), e);
    }
  }

  /**
   * Finds a Service Provider among those that a source holds now, without reading anything new.
   *
   * @param source the source
   * @param identifier the entityID
   * @return the metadata, or {@code null}
   */
  private static @Nullable EntityDescriptor find(final @NonNull ManagedMetadataSource source,
      final @NonNull String identifier) {
    return source.getServiceProviders().stream()
        .filter(e -> identifier.equals(e.getEntityID()))
        .findFirst()
        .orElse(null);
  }

  /**
   * Creates the entry of a Service Provider. The data expires at the {@code validUntil} of the entity, or else when
   * the metadata of the source expires.
   *
   * @param metadata the metadata
   * @param source the source
   * @return a {@link RegisteredClient}
   */
  private static @NonNull RegisteredClient toRegisteredClient(final @NonNull EntityDescriptor metadata,
      final @NonNull ManagedMetadataSource source) {
    final Instant expiresAt = metadata.getValidUntil() != null ? metadata.getValidUntil() : source.getExpirationTime();
    return RegisteredClient.of(toRecord(metadata), source.getName(), expiresAt);
  }

  /**
   * Creates the record for a Service Provider from its metadata. The organisation number is taken from the
   * {@code mdorgext:OrganizationNumber} extension of {@code md:Organization}, as given.
   *
   * @param metadata the Service Provider metadata
   * @return a {@link RequesterRecord}
   */
  public static @NonNull RequesterRecord toRecord(final @NonNull EntityDescriptor metadata) {
    Objects.requireNonNull(metadata, "metadata must not be null");
    final UIInfo uiInfo = getUiInfo(metadata);
    return new RequesterRecord(
        new Requester(AuthenticationProtocol.SAML, metadata.getEntityID()),
        getDisplayNames(metadata, uiInfo),
        getLogos(uiInfo),
        new LinkedHashSet<>(EntityDescriptorUtils.getEntityCategories(metadata)),
        getOrganizationNumber(metadata),
        metadata);
  }

  /**
   * Gets the organisation number from the {@code mdorgext:OrganizationNumber} extension of {@code md:Organization},
   * exactly as given.
   *
   * @param metadata the Service Provider metadata
   * @return the organisation number, or {@code null} if the metadata has none
   */
  private static @Nullable String getOrganizationNumber(final @NonNull EntityDescriptor metadata) {
    return Optional.ofNullable(metadata.getOrganization())
        .map(Organization::getExtensions)
        .flatMap(e -> e.getUnknownXMLObjects(OrganizationNumber.DEFAULT_ELEMENT_NAME).stream()
            .filter(OrganizationNumber.class::isInstance)
            .map(OrganizationNumber.class::cast)
            .findFirst())
        .map(OrganizationNumber::getValue)
        .filter(StringUtils::hasText)
        .orElse(null);
  }

  /**
   * Gets the {@code mdui:UIInfo} extension of the Service Provider role descriptor.
   *
   * @param metadata the Service Provider metadata
   * @return the {@link UIInfo} element, or {@code null} if the metadata has none
   */
  private static @Nullable UIInfo getUiInfo(final @NonNull EntityDescriptor metadata) {
    return Optional.ofNullable(metadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS))
        .map(SPSSODescriptor::getExtensions)
        .map(e -> e.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
        .filter(l -> !l.isEmpty())
        .map(l -> l.get(0))
        .map(UIInfo.class::cast)
        .orElse(null);
  }

  /**
   * Gets the display names of the Service Provider. The names of the {@code mdui:UIInfo} extension come first, then
   * the organization display names and finally the organization names. For every language the first name found is
   * used.
   *
   * @param metadata the Service Provider metadata
   * @param uiInfo the UI information of the metadata, or {@code null}
   * @return a list of display names
   */
  private static @NonNull List<DisplayName> getDisplayNames(
      final @NonNull EntityDescriptor metadata, final @Nullable UIInfo uiInfo) {

    final Map<String, DisplayName> names = new LinkedHashMap<>();
    if (uiInfo != null) {
      uiInfo.getDisplayNames().forEach(d -> addName(names, d.getXMLLang(), d.getValue()));
    }
    final Organization organization = metadata.getOrganization();
    if (organization != null) {
      organization.getDisplayNames().forEach(d -> addName(names, d.getXMLLang(), d.getValue()));
      organization.getOrganizationNames().forEach(n -> addName(names, n.getXMLLang(), n.getValue()));
    }
    return List.copyOf(names.values());
  }

  /**
   * Adds a display name unless a name for the same language has already been added.
   *
   * @param names the names collected so far, keyed by language
   * @param language the language of the name, or {@code null}
   * @param value the name, as given in the metadata
   */
  private static void addName(
      final @NonNull Map<String, DisplayName> names, final @Nullable String language, final @Nullable String value) {
    if (value == null || value.isBlank()) {
      return;
    }
    names.computeIfAbsent(Optional.ofNullable(language).orElse(""), l -> new DisplayName(language, value));
  }

  /**
   * Gets the logotypes of the {@code mdui:UIInfo} extension. A logotype without a URL is left out.
   *
   * @param uiInfo the UI information of the metadata, or {@code null}
   * @return a list of logotypes
   */
  private static @NonNull List<se.swedenconnect.spring.authnserver.registry.Logo> getLogos(
      final @Nullable UIInfo uiInfo) {
    if (uiInfo == null) {
      return List.of();
    }
    final List<se.swedenconnect.spring.authnserver.registry.Logo> logos = new ArrayList<>();
    for (final Logo logo : uiInfo.getLogos()) {
      if (logo.getURI() == null || logo.getURI().isBlank()) {
        continue;
      }
      logos.add(new se.swedenconnect.spring.authnserver.registry.Logo(
          logo.getXMLLang(), logo.getURI(), logo.getHeight(), logo.getWidth()));
    }
    return List.copyOf(logos);
  }

}
