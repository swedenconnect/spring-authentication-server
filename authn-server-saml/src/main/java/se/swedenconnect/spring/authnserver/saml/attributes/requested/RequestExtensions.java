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
import jakarta.annotation.Nullable;

import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;

/**
 * Support for reading the extensions of an authentication request.
 *
 * @author Martin Lindström
 */
class RequestExtensions {

  /**
   * Gets the first extension of the authentication request having the supplied element name.
   *
   * @param <T> the extension type
   * @param authnRequest the authentication request
   * @param elementName the element name of the extension
   * @param type the extension type
   * @return the extension, or {@code null} if the request does not carry one
   */
  static <T extends XMLObject> @Nullable T getExtension(final @Nonnull AuthnRequest authnRequest,
      final @Nonnull QName elementName, final @Nonnull Class<T> type) {

    final Extensions extensions = authnRequest.getExtensions();
    if (extensions == null) {
      return null;
    }
    final List<XMLObject> objects = extensions.getUnknownXMLObjects(elementName);
    return objects.stream()
        .filter(type::isInstance)
        .map(type::cast)
        .findFirst()
        .orElse(null);
  }

  // Hidden constructor
  private RequestExtensions() {
  }

}
