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
package se.swedenconnect.spring.authnserver.service.config;

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.ConfigurationPropertyState;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.util.StringUtils;

/**
 * Checks, before anything else is set up, that the deployment has supplied the settings that the reference has no
 * defaults for: the base URL, the SAML entity ID, the OpenID Connect issuer, the keys, the SAML metadata and the TLS
 * key store. When any of them is missing, startup fails with a {@link MissingDeploymentSettingsException} that names
 * all of them.
 * <p>
 * The settings of a protocol are only required when the protocol is enabled. The OpenID Connect clients are not
 * checked here, since the server itself stops startup when the OpenID Provider has no client source.
 * </p>
 *
 * @author Martin Lindström
 */
public class DeploymentSettingsCheck implements EnvironmentPostProcessor, Ordered {

  /**
   * A setting that the deployment must supply.
   *
   * @param setting the name of the setting
   * @param description what the setting is
   */
  public record MissingSetting(@NonNull String setting, @NonNull String description) {
  }

  /** {@inheritDoc} */
  @Override
  public void postProcessEnvironment(final @NonNull ConfigurableEnvironment environment,
      final @NonNull SpringApplication application) {
    final List<MissingSetting> missing = check(environment);
    if (!missing.isEmpty()) {
      throw new MissingDeploymentSettingsException(missing);
    }
  }

  /**
   * Finds the settings that are missing.
   *
   * @param environment the environment
   * @return the missing settings, empty if everything is there
   */
  public static @NonNull List<MissingSetting> check(final @NonNull ConfigurableEnvironment environment) {
    final Binder binder = Binder.get(environment);
    final Iterable<ConfigurationPropertySource> sources = ConfigurationPropertySources.get(environment);
    final List<MissingSetting> missing = new ArrayList<>();

    if (!hasText(binder, "authn-server.base-url")) {
      missing.add(new MissingSetting("authn-server.base-url",
          "the base URL of the server, protocol, host, port and context path, for example https://idp.example.com"));
    }
    if (binder.bind("server.ssl.enabled", Boolean.class).orElse(true)) {
      final String bundle = binder.bind("server.ssl.bundle", String.class).orElse(null);
      final boolean tls = StringUtils.hasText(bundle)
          ? hasDescendants(sources, "spring.ssl.bundle.jks." + bundle + ".keystore")
              || hasDescendants(sources, "spring.ssl.bundle.pem." + bundle + ".keystore")
          : hasText(binder, "server.ssl.key-store");
      if (!tls) {
        missing.add(new MissingSetting(StringUtils.hasText(bundle)
            ? "spring.ssl.bundle.(jks|pem).%s.keystore".formatted(bundle)
            : "server.ssl.bundle",
            "the TLS key store of the server, given as a Spring Boot SSL bundle"));
      }
    }

    if (binder.bind("authn-server.saml.enabled", Boolean.class).orElse(false)) {
      if (!hasText(binder, "authn-server.saml.entity-id")) {
        missing.add(new MissingSetting("authn-server.saml.entity-id", "the SAML entity ID of the Identity Provider"));
      }
      final boolean defaultCredential = hasDescendants(sources, "authn-server.saml.credentials.default-credential");
      if (!defaultCredential && !hasDescendants(sources, "authn-server.saml.credentials.sign")) {
        missing.add(new MissingSetting("authn-server.saml.credentials.sign",
            "the SAML signing key, or authn-server.saml.credentials.default-credential for both signing and "
                + "encryption"));
      }
      if (!defaultCredential && !hasDescendants(sources, "authn-server.saml.credentials.encrypt")) {
        missing.add(new MissingSetting("authn-server.saml.credentials.encrypt",
            "the SAML encryption key, or authn-server.saml.credentials.default-credential for both signing and "
                + "encryption"));
      }
      if (!hasDescendants(sources, "authn-server.saml.metadata-providers")) {
        missing.add(new MissingSetting("authn-server.saml.metadata-providers",
            "the sources of the SAML Service Provider metadata"));
      }
    }

    if (binder.bind("authn-server.oidc.enabled", Boolean.class).orElse(false)) {
      if (!hasText(binder, "authn-server.oidc.issuer")) {
        missing.add(new MissingSetting("authn-server.oidc.issuer",
            "the issuer identifier of the OpenID Provider, which is also its OpenID Federation entity identifier"));
      }
      if (!hasDescendants(sources, "authn-server.oidc.keys.signing")) {
        missing.add(new MissingSetting("authn-server.oidc.keys.signing",
            "the signing keys of the OpenID Provider"));
      }
    }
    return missing;
  }

  /**
   * Runs after the configuration files have been read.
   */
  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE;
  }

  /**
   * Tells whether a setting has a value that is not blank.
   *
   * @param binder the binder
   * @param name the name of the setting
   * @return {@code true} if the setting has a value
   */
  private static boolean hasText(final @NonNull Binder binder, final @NonNull String name) {
    return StringUtils.hasText(binder.bind(name, String.class).orElse(null));
  }

  /**
   * Tells whether any setting under the supplied name is given.
   *
   * @param sources the property sources
   * @param name the name
   * @return {@code true} if a setting under the name is given
   */
  private static boolean hasDescendants(final @NonNull Iterable<ConfigurationPropertySource> sources,
      final @NonNull String name) {
    final ConfigurationPropertyName propertyName = ConfigurationPropertyName.of(name);
    for (final ConfigurationPropertySource source : sources) {
      if (source.containsDescendantOf(propertyName) == ConfigurationPropertyState.PRESENT) {
        return true;
      }
    }
    return false;
  }

}
