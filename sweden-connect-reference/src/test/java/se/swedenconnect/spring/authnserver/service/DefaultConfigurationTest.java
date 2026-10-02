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
package se.swedenconnect.spring.authnserver.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.io.support.SpringFactoriesLoader;

import se.swedenconnect.spring.authnserver.service.config.DeploymentSettingsCheck;
import se.swedenconnect.spring.authnserver.service.config.MissingDeploymentSettingsException;
import se.swedenconnect.spring.authnserver.service.config.MissingDeploymentSettingsFailureAnalyzer;

/**
 * Tests that the service does not start with the default configuration only, and that the failure names everything
 * that the deployment must add. The OpenID Connect clients are named by the server itself.
 *
 * @author Martin Lindström
 */
class DefaultConfigurationTest {

  @Test
  void withTheDefaultConfigurationOnlyStartupFailsNamingWhatIsMissing() {
    final MissingDeploymentSettingsException error = catchThrowableOfType(MissingDeploymentSettingsException.class,
        () -> new SpringApplication(ReferenceApplication.class).run());

    assertThat(error).isNotNull();
    assertThat(error.getMissing())
        .extracting(DeploymentSettingsCheck.MissingSetting::setting)
        .containsExactly(
            "authn-server.base-url",
            "spring.ssl.bundle.(jks|pem).tls.keystore",
            "authn-server.saml.entity-id",
            "authn-server.saml.credentials.sign",
            "authn-server.saml.credentials.encrypt",
            "authn-server.saml.metadata-providers",
            "authn-server.oidc.issuer",
            "authn-server.oidc.keys.signing");
    assertThat(error.getMessage()).contains("authn-server.base-url", "authn-server.oidc.keys.signing");
  }

  @Test
  void withoutOidcClientsTheServerStopsStartupNamingTheProperty() {
    final Throwable error = catchThrowable(() -> new SpringApplication(ReferenceApplication.class).run(
        "--spring.profiles.active=complete", "--authn-server.oidc.clients=", "--server.port=0",
        "--management.server.port=0"));

    assertThat(error).isNotNull();
    assertThat(error).rootCause()
        .hasMessageContaining("No client registry backend for OIDC requesters")
        .hasMessageContaining("authn-server.oidc.clients");
  }

  @Test
  void theFailureIsReportedAsAListOfSettings() {
    final MissingDeploymentSettingsException error = catchThrowableOfType(MissingDeploymentSettingsException.class,
        () -> new SpringApplication(ReferenceApplication.class).run());

    final FailureAnalysis analysis = new MissingDeploymentSettingsFailureAnalyzer().analyze(error);
    assertThat(analysis).isNotNull();
    assertThat(analysis.getDescription())
        .contains("- authn-server.base-url: the base URL of the server")
        .contains("- authn-server.oidc.issuer: the issuer identifier of the OpenID Provider")
        .contains("- spring.ssl.bundle.(jks|pem).tls.keystore: the TLS key store");
    assertThat(analysis.getAction()).contains("README");
  }

  @Test
  void theFailureAnalyzerIsRegistered() {
    assertThat(SpringFactoriesLoader.forDefaultResourceLocation().load(FailureAnalyzer.class, null,
        SpringFactoriesLoader.FailureHandler.handleMessage((message, failure) -> {})))
        .hasAtLeastOneElementOfType(MissingDeploymentSettingsFailureAnalyzer.class);
  }

}
