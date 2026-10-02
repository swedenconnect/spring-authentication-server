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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.mock.env.MockEnvironment;

/**
 * Tests for {@link DeploymentSettingsCheck}.
 *
 * @author Martin Lindström
 */
class DeploymentSettingsCheckTest {

  @Test
  void aCompleteConfigurationPasses() {
    assertThat(DeploymentSettingsCheck.check(complete())).isEmpty();
    new DeploymentSettingsCheck().postProcessEnvironment(complete(), new SpringApplication());
  }

  @Test
  void anEmptyConfigurationOnlyNeedsTheBaseUrlAndTls() {
    assertThat(DeploymentSettingsCheck.check(new MockEnvironment()))
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly("authn-server.base-url", "server.ssl.bundle");
  }

  @Test
  void missingSettingsFailTheStartup() {
    final MockEnvironment environment = complete();
    environment.setProperty("authn-server.base-url", " ");
    assertThatThrownBy(() -> new DeploymentSettingsCheck().postProcessEnvironment(environment,
        new SpringApplication()))
        .isInstanceOf(MissingDeploymentSettingsException.class)
        .hasMessageContaining("authn-server.base-url");
  }

  @Test
  void theSettingsOfADisabledProtocolAreNotRequired() {
    final MockEnvironment environment = new MockEnvironment()
        .withProperty("authn-server.base-url", "https://idp.example.com")
        .withProperty("server.ssl.enabled", "false")
        .withProperty("authn-server.saml.enabled", "false")
        .withProperty("authn-server.oidc.enabled", "true");
    assertThat(DeploymentSettingsCheck.check(environment))
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly("authn-server.oidc.issuer", "authn-server.oidc.keys.signing");

    environment.setProperty("authn-server.oidc.enabled", "false");
    environment.setProperty("authn-server.saml.enabled", "true");
    assertThat(DeploymentSettingsCheck.check(environment))
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly("authn-server.saml.entity-id", "authn-server.saml.credentials.sign",
            "authn-server.saml.credentials.encrypt", "authn-server.saml.metadata-providers");
  }

  @Test
  void aDefaultCredentialServesBothSigningAndEncryption() {
    final MockEnvironment withDefault = without("authn-server.saml.credentials");
    withDefault.setProperty("authn-server.saml.credentials.default-credential.bundle", "saml");
    assertThat(DeploymentSettingsCheck.check(withDefault)).isEmpty();
    assertThat(DeploymentSettingsCheck.check(without("authn-server.saml.credentials")))
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly("authn-server.saml.credentials.sign", "authn-server.saml.credentials.encrypt");
  }

  @Test
  void theTlsKeyStoreMayBeGivenInSeveralWays() {
    final MockEnvironment pem = without("server.ssl", "spring.ssl")
        .withProperty("server.ssl.bundle", "tls")
        .withProperty("spring.ssl.bundle.pem.tls.keystore.certificate", "file:/tls.crt");
    assertThat(DeploymentSettingsCheck.check(pem)).isEmpty();

    final MockEnvironment keyStore = without("server.ssl", "spring.ssl")
        .withProperty("server.ssl.key-store", "file:/tls.p12");
    assertThat(DeploymentSettingsCheck.check(keyStore)).isEmpty();

    final MockEnvironment noTls = without("server.ssl", "spring.ssl")
        .withProperty("server.ssl.enabled", "false");
    assertThat(DeploymentSettingsCheck.check(noTls)).isEmpty();

    final MockEnvironment missingBundle = without("server.ssl", "spring.ssl")
        .withProperty("server.ssl.bundle", "other");
    assertThat(DeploymentSettingsCheck.check(missingBundle))
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly("spring.ssl.bundle.(jks|pem).other.keystore");
  }

  @Test
  void settingsMayBeGivenAsEnvironmentVariables() {
    final StandardEnvironment environment = new StandardEnvironment();
    environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
        new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, Map.of(
        "AUTHN_SERVER_BASE_URL", "https://idp.example.com",
        "SERVER_SSL_BUNDLE", "tls",
        "SPRING_SSL_BUNDLE_JKS_TLS_KEYSTORE_LOCATION", "file:/tls.p12",
        "AUTHN_SERVER_OIDC_ENABLED", "true",
        "AUTHN_SERVER_OIDC_ISSUER", "https://idp.example.com",
        "AUTHN_SERVER_OIDC_KEYS_SIGNING_0_CREDENTIAL_BUNDLE", "oidc")));
    assertThat(DeploymentSettingsCheck.check(environment)).isEmpty();
  }

  /** The settings of a complete configuration. */
  private static final Map<String, String> COMPLETE = Map.ofEntries(
      Map.entry("authn-server.base-url", "https://idp.example.com"),
      Map.entry("server.ssl.bundle", "tls"),
      Map.entry("spring.ssl.bundle.jks.tls.keystore.location", "classpath:tls.p12"),
      Map.entry("authn-server.saml.enabled", "true"),
      Map.entry("authn-server.saml.entity-id", "https://idp.example.com/saml"),
      Map.entry("authn-server.saml.credentials.sign.bundle", "saml-sign"),
      Map.entry("authn-server.saml.credentials.encrypt.bundle", "saml-encrypt"),
      Map.entry("authn-server.saml.metadata-providers[0].location", "classpath:metadata.xml"),
      Map.entry("authn-server.oidc.enabled", "true"),
      Map.entry("authn-server.oidc.issuer", "https://idp.example.com"),
      Map.entry("authn-server.oidc.keys.signing[0].credential.bundle", "oidc"));

  private static MockEnvironment complete() {
    return without();
  }

  /**
   * Creates a complete configuration, without the settings that start with any of the supplied prefixes.
   */
  private static MockEnvironment without(final String... prefixes) {
    final MockEnvironment environment = new MockEnvironment();
    COMPLETE.entrySet().stream()
        .filter(e -> Arrays.stream(prefixes).noneMatch(p -> e.getKey().startsWith(p)))
        .forEach(e -> environment.setProperty(e.getKey(), e.getValue()));
    return environment;
  }

}
