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

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;

import se.swedenconnect.opensaml.saml2.core.build.AuthnRequestBuilder;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Support for the tests of the requested attribute processors.
 *
 * @author Martin Lindström
 */
abstract class RequestedAttributeTestSupport extends OpenSamlTestBase {

  /** The entity ID used for the Service Provider metadata of the tests. */
  static final String SP_ENTITY_ID = "https://sp.example.com";

  /**
   * Creates an authentication request.
   *
   * @param attributeConsumingServiceIndex the AttributeConsumingServiceIndex, may be {@code null}
   * @param extensions the extensions of the request
   * @return an {@link AuthnRequest}
   */
  static AuthnRequest authnRequest(final Integer attributeConsumingServiceIndex, final XMLObject... extensions) {
    final AuthnRequestBuilder builder = AuthnRequestBuilder.builder()
        .id("_request-id")
        .attributeConsumerServiceIndex(attributeConsumingServiceIndex);
    if (extensions.length > 0) {
      builder.extensions(ExtensionsBuilder.builder().extensions(extensions).build());
    }
    return builder.build();
  }

  /**
   * Creates Service Provider metadata holding the supplied entity categories and no requested attributes.
   *
   * @param entityCategories the entity categories to declare
   * @return an {@link EntityDescriptor}
   */
  static EntityDescriptor metadataWithEntityCategories(final String... entityCategories) {
    return EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .extensions(se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(entityCategories)
                .build())
            .build())
        .roleDescriptors(SPSSODescriptorBuilder.builder().build())
        .build();
  }

  /**
   * Creates Service Provider metadata holding one {@code AttributeConsumingService} element with index 0.
   *
   * @param requestedAttributes the requested attributes of the element
   * @return an {@link EntityDescriptor}
   */
  static EntityDescriptor metadataWithRequestedAttributes(final RequestedAttribute... requestedAttributes) {
    return EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(AttributeConsumingServiceBuilder.builder()
                .index(0)
                .isDefault(true)
                .requestedAttributes(requestedAttributes)
                .build())
            .build())
        .build();
  }

  /**
   * Creates a requested attribute for Service Provider metadata.
   *
   * @param name the attribute name
   * @param required whether the attribute is required
   * @return a {@link RequestedAttribute}
   */
  static RequestedAttribute requestedAttribute(final String name, final boolean required) {
    return RequestedAttributeBuilder.builder(name)
        .isRequired(required)
        .build();
  }

  /**
   * Creates an eIDAS requested attribute.
   *
   * @param name the attribute name
   * @param required whether the attribute is required
   * @return a {@link se.swedenconnect.opensaml.eidas.ext.RequestedAttribute}
   */
  static se.swedenconnect.opensaml.eidas.ext.RequestedAttribute eidasRequestedAttribute(final String name,
      final boolean required) {
    final se.swedenconnect.opensaml.eidas.ext.RequestedAttribute attribute =
        (se.swedenconnect.opensaml.eidas.ext.RequestedAttribute) XMLObjectSupport.buildXMLObject(
            se.swedenconnect.opensaml.eidas.ext.RequestedAttribute.DEFAULT_ELEMENT_NAME);
    attribute.setName(name);
    attribute.setIsRequired(required);
    return attribute;
  }

  /**
   * Gets the names of the supplied requested attributes.
   *
   * @param attributes the requested attributes
   * @return the attribute names
   */
  static List<String> names(final List<SamlRequestedAttribute> attributes) {
    return attributes.stream()
        .map(SamlRequestedAttribute::name)
        .toList();
  }

}
