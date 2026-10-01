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
import se.swedenconnect.spring.authnserver.oidc.config.OidcFederationConfigurer;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkState;

/**
 * The OpenID Connect part of the server summary of the {@link AuthnServerInfoContributor}. Only used when the OIDC
 * module is on the classpath.
 *
 * @author Martin Lindström
 */
final class OidcInfo {

  /**
   * Describes the OpenID Provider. The issuer is also the federation entity identifier, so it is given once.
   *
   * @param configurer the OIDC configurer
   * @return the description
   */
  static @NonNull Map<String, Object> describe(final @NonNull AbstractProtocolConfigurer<?> configurer) {
    final Map<String, Object> info = new LinkedHashMap<>();
    if (configurer instanceof final OidcProviderConfigurer oidc) {
      info.put("issuer", oidc.getIssuer());
      final OidcFederationConfigurer federation = oidc.getFederation();
      if (federation.isEnabled()) {
        final Map<String, Object> f = new LinkedHashMap<>();
        f.put("authority-hints", federation.getAuthorityHints());
        f.put("trust-marks", federation.getProviderTrustMarks().getStates().stream()
            .map(OidcInfo::trustMark)
            .toList());
        info.put("federation", f);
      }
    }
    return info;
  }

  /**
   * Describes one of the OpenID Provider's own trust marks.
   *
   * @param state the state of the trust mark
   * @return the description
   */
  private static @NonNull Map<String, Object> trustMark(final @NonNull TrustMarkState state) {
    final Map<String, Object> mark = new LinkedHashMap<>();
    mark.put("type", state.trustMarkType());
    mark.put("published", state.published());
    if (state.expiresAt() != null) {
      mark.put("expires-at", state.expiresAt().toString());
    }
    return mark;
  }

  // Hidden constructor
  private OidcInfo() {
  }

}
