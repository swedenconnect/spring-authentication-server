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
package se.swedenconnect.spring.authnserver.saml.attributes.requested;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.FromProtocolAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeMapping;

/**
 * Works out everything a SAML authentication request asks for, and gives it in the protocol-neutral form.
 * <p>
 * A Service Provider states what it needs in more than one place: the {@code AttributeConsumingService} element of its
 * metadata, the service entity categories it declares, the {@code RequestedAttributes} extensions of the request and
 * the {@code PrincipalSelection} extension. Each place has a {@link RequestedAttributeProcessor} of its own, and the
 * result of them all is mapped into generic requested attributes by {@link SamlAttributeMapping}.
 * </p>
 * <p>
 * An attribute that more than one source asks for appears once in the result, and is essential if any source said so.
 * The rule for several service entity categories is applied within that source, see
 * {@link EntityCategoryRequestedAttributeProcessor}.
 * </p>
 * <p>
 * An eIDAS Proxy Service works with the eIDAS attribute names rather than the names of the Swedish eID Framework, and
 * therefore passes the mapping of {@link EidasAttributeMapping} to the constructor.
 * </p>
 *
 * @author Martin Lindström
 */
public class SamlRequestedAttributeResolver {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SamlRequestedAttributeResolver.class);

  /** The mapping from SAML requested attributes into the generic form. */
  private final FromProtocolAttributeMapping<SamlRequestedAttribute> attributeMapping;

  /** The processors, one per source. */
  private final List<RequestedAttributeProcessor> processors;

  /**
   * Constructor using the built-in attribute mapping and the default processors.
   *
   * @param idpDeclaredEntityCategories the entity categories that the Identity Provider declares
   */
  public SamlRequestedAttributeResolver(final @NonNull Collection<String> idpDeclaredEntityCategories) {
    this(new SamlAttributeMapping(), getDefaultProcessors(idpDeclaredEntityCategories));
  }

  /**
   * Constructor.
   *
   * @param attributeMapping the mapping between SAML attributes and the generic attribute model
   * @param processors the processors, one per source
   */
  public SamlRequestedAttributeResolver(final @NonNull SamlAttributeMapping attributeMapping,
      final @NonNull List<RequestedAttributeProcessor> processors) {
    this(Objects.requireNonNull(attributeMapping, "attributeMapping must not be null").getFromProtocolMapping(),
        processors);
  }

  /**
   * Constructor taking the mapping from SAML requested attributes into the generic form, which is what an eIDAS Proxy
   * Service needs since it hands in the mapping of {@link EidasAttributeMapping}.
   *
   * @param attributeMapping the mapping from SAML requested attributes into the generic form
   * @param processors the processors, one per source
   */
  public SamlRequestedAttributeResolver(
      final @NonNull FromProtocolAttributeMapping<SamlRequestedAttribute> attributeMapping,
      final @NonNull List<RequestedAttributeProcessor> processors) {
    this.attributeMapping = Objects.requireNonNull(attributeMapping, "attributeMapping must not be null");
    this.processors = List.copyOf(Objects.requireNonNull(processors, "processors must not be null"));
  }

  /**
   * Gets the default processors: the metadata, the {@code RequestedAttributes} extension of the SAML protocol
   * extension for requesting attributes, the eIDAS {@code RequestedAttributes} extension, the declared service entity
   * categories and the {@code PrincipalSelection} extension.
   *
   * @param idpDeclaredEntityCategories the entity categories that the Identity Provider declares
   * @return the default processors
   */
  public static @NonNull List<RequestedAttributeProcessor> getDefaultProcessors(
      final @NonNull Collection<String> idpDeclaredEntityCategories) {
    return List.of(
        new MetadataRequestedAttributeProcessor(),
        new OasisExtensionRequestedAttributeProcessor(),
        new EidasRequestedAttributeProcessor(),
        new EntityCategoryRequestedAttributeProcessor(idpDeclaredEntityCategories),
        new PrincipalSelectionRequestedAttributeProcessor());
  }

  /**
   * Works out what the request asks for.
   *
   * @param context the authentication request and the metadata of the Service Provider that sent it
   * @return the generic requested attributes, possibly empty
   */
  public @NonNull List<GenericRequestedAttribute> resolve(final @NonNull RequestedAttributeContext context) {
    final List<GenericRequestedAttribute> attributes =
        this.attributeMapping.map(this.getRequestedAttributes(context));

    log.debug("Requested attributes: {} [{}]", attributes, context.getLogString());

    return attributes;
  }

  /**
   * Works out which SAML attributes the request asks for, before they are mapped into the generic form. An attribute
   * that more than one source asks for appears once per source.
   *
   * @param context the authentication request and the metadata of the Service Provider that sent it
   * @return the SAML requested attributes, possibly empty
   */
  public @NonNull List<SamlRequestedAttribute> getRequestedAttributes(
      final @NonNull RequestedAttributeContext context) {
    Objects.requireNonNull(context, "context must not be null");
    final List<SamlRequestedAttribute> attributes = new ArrayList<>();
    for (final RequestedAttributeProcessor processor : this.processors) {
      attributes.addAll(processor.extractRequestedAttributes(context));
    }
    return attributes;
  }

  /**
   * Gets the processors that this resolver runs.
   *
   * @return the processors
   */
  public @NonNull List<RequestedAttributeProcessor> getProcessors() {
    return this.processors;
  }

  /**
   * Gets the mapping from SAML requested attributes into the generic form. Use it to register mappers of your own.
   *
   * @return a {@link FromProtocolAttributeMapping}
   */
  public @NonNull FromProtocolAttributeMapping<SamlRequestedAttribute> getAttributeMapping() {
    return this.attributeMapping;
  }

}
