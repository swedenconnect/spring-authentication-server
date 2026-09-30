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

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes that the Service Provider asks for in the {@code AttributeConsumingService} element of its
 * metadata.
 * <p>
 * The {@code AttributeConsumingServiceIndex} of the request picks the element to use. Without it the element marked
 * as the default is used, and failing that the one with the lowest index.
 * </p>
 *
 * @author Martin Lindström
 */
public class MetadataRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(MetadataRequestedAttributeProcessor.class);

  /** {@inheritDoc} */
  @Override
  public @NonNull List<SamlRequestedAttribute> extractRequestedAttributes(
      final @NonNull RequestedAttributeContext context) {

    final SPSSODescriptor descriptor = context.spMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (descriptor == null) {
      return List.of();
    }
    final AttributeConsumingService service =
        findAttributeConsumingService(descriptor, context.authnRequest().getAttributeConsumingServiceIndex());
    if (service == null) {
      log.debug("No matching AttributeConsumingService to take requested attributes from [{}]",
          context.getLogString());
      return List.of();
    }
    final List<SamlRequestedAttribute> attributes = service.getRequestedAttributes().stream()
        .map(SamlRequestedAttribute::of)
        .toList();

    log.debug("Requested attributes from AttributeConsumingService with index {}: {} [{}]",
        service.getIndex(), attributes, context.getLogString());

    return attributes;
  }

  /**
   * Finds the {@code AttributeConsumingService} element to use.
   *
   * @param descriptor the SP SSO descriptor
   * @param index the index that the request asked for, may be {@code null}
   * @return an {@link AttributeConsumingService}, or {@code null} if the metadata holds none
   */
  private static @Nullable AttributeConsumingService findAttributeConsumingService(
      final @NonNull SPSSODescriptor descriptor, final @Nullable Integer index) {

    AttributeConsumingService found = null;
    for (final AttributeConsumingService service : descriptor.getAttributeConsumingServices()) {
      if (index != null) {
        if (index == service.getIndex()) {
          return service;
        }
      }
      else if (Boolean.TRUE.equals(service.isDefault())) {
        return service;
      }
      else if (found == null || service.getIndex() < found.getIndex()) {
        found = service;
      }
    }
    return index != null ? null : found;
  }

}
