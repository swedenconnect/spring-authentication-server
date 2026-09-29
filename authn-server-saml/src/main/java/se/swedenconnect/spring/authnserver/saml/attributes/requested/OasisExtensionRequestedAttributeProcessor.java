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

import jakarta.annotation.Nonnull;

import java.util.List;

import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes that the request asks for in its {@code RequestedAttributes} extension, see
 * <a href="https://docs.oasis-open.org/security/saml-protoc-req-attr-req/v1.0/saml-protoc-req-attr-req-v1.0.html">SAML
 * V2.0 Protocol Extension for Requesting Attributes per Request Version 1.0</a>.
 *
 * @author Martin Lindström
 */
public class OasisExtensionRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OasisExtensionRequestedAttributeProcessor.class);

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<SamlRequestedAttribute> extractRequestedAttributes(
      final @Nonnull RequestedAttributeContext context) {

    final RequestedAttributes extension = RequestExtensions.getExtension(
        context.authnRequest(), RequestedAttributes.DEFAULT_ELEMENT_NAME, RequestedAttributes.class);
    if (extension == null) {
      return List.of();
    }
    final List<SamlRequestedAttribute> attributes = extension.getRequestedAttributes().stream()
        .map(SamlRequestedAttribute::of)
        .toList();

    log.debug("Requested attributes from the RequestedAttributes extension: {} [{}]",
        attributes, context.getLogString());

    return attributes;
  }

}
