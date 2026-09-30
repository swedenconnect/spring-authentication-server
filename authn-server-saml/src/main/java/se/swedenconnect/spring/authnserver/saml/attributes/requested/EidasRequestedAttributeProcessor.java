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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.eidas.ext.RequestedAttributes;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes that the request asks for in the eIDAS {@code RequestedAttributes} extension, which an eIDAS
 * node sends.
 *
 * @author Martin Lindström
 */
public class EidasRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(EidasRequestedAttributeProcessor.class);

  /** {@inheritDoc} */
  @Override
  public @NonNull List<SamlRequestedAttribute> extractRequestedAttributes(
      final @NonNull RequestedAttributeContext context) {

    final RequestedAttributes extension = RequestExtensions.getExtension(
        context.authnRequest(), RequestedAttributes.DEFAULT_ELEMENT_NAME, RequestedAttributes.class);
    if (extension == null) {
      return List.of();
    }
    final List<SamlRequestedAttribute> attributes = extension.getRequestedAttributes().stream()
        .map(SamlRequestedAttribute::of)
        .toList();

    log.debug("Requested attributes from the eIDAS RequestedAttributes extension: {} [{}]",
        attributes, context.getLogString());

    return attributes;
  }

}
