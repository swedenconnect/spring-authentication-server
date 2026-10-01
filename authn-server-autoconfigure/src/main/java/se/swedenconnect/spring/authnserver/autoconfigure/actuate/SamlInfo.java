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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;

/**
 * The SAML part of the server summary of the {@link AuthnServerInfoContributor}. Only used when the SAML module is on
 * the classpath.
 *
 * @author Martin Lindström
 */
final class SamlInfo {

  /**
   * Describes the SAML Identity Provider.
   *
   * @param configurer the SAML configurer
   * @return the description
   */
  static @NonNull Map<String, Object> describe(final @NonNull AbstractProtocolConfigurer<?> configurer) {
    final Map<String, Object> info = new LinkedHashMap<>();
    if (configurer instanceof final Saml2IdpConfigurer saml) {
      info.put("entity-id", saml.getEntityId());
    }
    return info;
  }

  // Hidden constructor
  private SamlInfo() {
  }

}
