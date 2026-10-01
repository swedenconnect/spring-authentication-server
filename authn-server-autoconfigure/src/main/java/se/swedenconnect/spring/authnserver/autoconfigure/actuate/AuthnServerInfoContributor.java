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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.util.ClassUtils;

import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientSource;

/**
 * Adds the authentication server to the {@code info} endpoint:
 * <ul>
 * <li>{@value #SERVER}: the enabled protocols, the SAML entityID, the OpenID Connect issuer, the authentication
 * providers with their supported {@code acr} values, and with OpenID Federation the authority hints and the OpenID
 * Provider's own trust marks.</li>
 * <li>{@value #CLIENT_REGISTRY}: each source of the client registry with its number of clients and the time of its last
 * update.</li>
 * </ul>
 *
 * @author Martin Lindström
 */
public class AuthnServerInfoContributor implements InfoContributor {

  /** The key of the server summary. */
  public static final String SERVER = "authn-server";

  /** The key of the client registry sources. */
  public static final String CLIENT_REGISTRY = "client-registry";

  /** The class that tells whether the SAML module is on the classpath. */
  private static final String SAML_CLASS = "se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer";

  /** The class that tells whether the OIDC module is on the classpath. */
  private static final String OIDC_CLASS = "se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer";

  /** The configured server. */
  private final ConfiguredAuthnServer server;

  /**
   * Constructor.
   *
   * @param server the configured server
   */
  public AuthnServerInfoContributor(final @NonNull ConfiguredAuthnServer server) {
    this.server = Objects.requireNonNull(server, "server must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void contribute(final Info.@NonNull Builder builder) {
    final AuthnServerConfigurer configurer = this.server.getConfigurer();
    if (configurer == null) {
      return;
    }
    builder.withDetail(SERVER, this.summary(configurer));
    builder.withDetail(CLIENT_REGISTRY, Map.of("sources", this.sources()));
  }

  /**
   * Creates the server summary.
   *
   * @param configurer the configurer of the server
   * @return the summary
   */
  private @NonNull Map<String, Object> summary(final @NonNull AuthnServerConfigurer configurer) {
    final Map<String, Object> summary = new LinkedHashMap<>();
    final ClassLoader classLoader = this.getClass().getClassLoader();
    summary.put("protocols", configurer.getProtocolConfigurers().stream()
        .map(c -> c.getProtocol().name().toLowerCase(Locale.ROOT))
        .toList());
    for (final AbstractProtocolConfigurer<?> protocol : configurer.getProtocolConfigurers()) {
      switch (protocol.getProtocol()) {
      case SAML -> {
        if (ClassUtils.isPresent(SAML_CLASS, classLoader)) {
          summary.put("saml", SamlInfo.describe(protocol));
        }
      }
      case OIDC -> {
        if (ClassUtils.isPresent(OIDC_CLASS, classLoader)) {
          summary.put("oidc", OidcInfo.describe(protocol));
        }
      }
      }
    }
    final List<Map<String, Object>> providers = new ArrayList<>();
    for (final UserAuthenticationProvider provider : configurer.getAuthenticationProviders()) {
      final Map<String, Object> p = new LinkedHashMap<>();
      p.put("name", provider.getName());
      p.put("acr-values", provider.getSupportedAuthnContextUris());
      providers.add(p);
    }
    summary.put("authentication-providers", providers);
    return summary;
  }

  /**
   * Lists the sources of the client registry.
   *
   * @return the sources
   */
  private @NonNull List<Map<String, Object>> sources() {
    final List<Map<String, Object>> sources = new ArrayList<>();
    for (final ClientRegistryBackend backend : this.server.getClientRegistryBackends()) {
      for (final ClientSource source : backend.getSources()) {
        final Map<String, Object> s = new LinkedHashMap<>();
        s.put("protocol", source.protocol().name().toLowerCase(Locale.ROOT));
        s.put("backend", backend.getName());
        s.put("name", source.name());
        if (source.clients() != null) {
          s.put("clients", source.clients());
        }
        if (source.lastUpdate() != null) {
          s.put("last-update", source.lastUpdate().toString());
        }
        sources.add(s);
      }
    }
    return sources;
  }

}
