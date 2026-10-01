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

import java.io.Serial;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Tells that the deployment has not supplied settings that the reference needs, and that no defaults exist for.
 *
 * @author Martin Lindström
 */
public class MissingDeploymentSettingsException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The missing settings. */
  private final List<DeploymentSettingsCheck.MissingSetting> missing;

  /**
   * Constructor.
   *
   * @param missing the missing settings, must not be empty
   */
  public MissingDeploymentSettingsException(final @NonNull List<DeploymentSettingsCheck.MissingSetting> missing) {
    super(toMessage(missing));
    this.missing = List.copyOf(missing);
  }

  /**
   * Gets the missing settings.
   *
   * @return the missing settings
   */
  public @NonNull List<DeploymentSettingsCheck.MissingSetting> getMissing() {
    return this.missing;
  }

  /**
   * Gets the list of missing settings, one per line.
   *
   * @return the list
   */
  public @NonNull String getMissingList() {
    return this.missing.stream()
        .map(m -> "    - %s: %s".formatted(m.setting(), m.description()))
        .collect(Collectors.joining(System.lineSeparator()));
  }

  /**
   * Creates the exception message.
   *
   * @param missing the missing settings
   * @return the message
   */
  private static @NonNull String toMessage(final @NonNull List<DeploymentSettingsCheck.MissingSetting> missing) {
    if (Objects.requireNonNull(missing, "missing must not be null").isEmpty()) {
      throw new IllegalArgumentException("missing must not be empty");
    }
    return "The deployment has not supplied these settings: " + missing.stream()
        .map(DeploymentSettingsCheck.MissingSetting::setting)
        .collect(Collectors.joining(", "));
  }

}
