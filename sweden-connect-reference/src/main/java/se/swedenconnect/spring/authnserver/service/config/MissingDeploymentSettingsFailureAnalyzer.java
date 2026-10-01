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

import org.jspecify.annotations.NonNull;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Reports a {@link MissingDeploymentSettingsException} as a list of the settings that the deployment must add, instead
 * of a stack trace.
 *
 * @author Martin Lindström
 */
public class MissingDeploymentSettingsFailureAnalyzer
    extends AbstractFailureAnalyzer<MissingDeploymentSettingsException> {

  /** {@inheritDoc} */
  @Override
  protected @NonNull FailureAnalysis analyze(final @NonNull Throwable rootFailure,
      final @NonNull MissingDeploymentSettingsException cause) {
    return new FailureAnalysis(
        "The Sweden Connect reference authentication server has no defaults for these settings, and the deployment "
            + "has not supplied them:" + System.lineSeparator() + System.lineSeparator() + cause.getMissingList(),
        "Add the settings to the configuration of the deployment, for example in an application.yml file of its own "
            + "or as environment variables. The README of the reference describes each of them.",
        cause);
  }

}
