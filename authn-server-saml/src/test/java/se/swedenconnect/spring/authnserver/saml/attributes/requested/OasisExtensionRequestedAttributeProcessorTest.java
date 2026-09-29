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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Tests for {@link OasisExtensionRequestedAttributeProcessor}.
 *
 * @author Martin Lindström
 */
class OasisExtensionRequestedAttributeProcessorTest extends RequestedAttributeTestSupport {

  private final OasisExtensionRequestedAttributeProcessor processor =
      new OasisExtensionRequestedAttributeProcessor();

  @Test
  void aRequestWithoutTheExtensionGivesNothing() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null), metadataWithRequestedAttributes());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void theRequestedAttributesAreTakenFromTheExtension() {
    final RequestedAttributes extension =
        (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    extension.getRequestedAttributes().add(
        requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_SN, true));

    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null, extension), metadataWithRequestedAttributes());

    final List<SamlRequestedAttribute> result = this.processor.extractRequestedAttributes(context);

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.name()).isEqualTo(AttributeConstants.ATTRIBUTE_NAME_SN);
      assertThat(a.required()).isTrue();
    });
  }

}
