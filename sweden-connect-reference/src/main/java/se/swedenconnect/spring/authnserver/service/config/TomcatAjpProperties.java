/*
 * Copyright 2016-2026 Sweden Connect
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

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the Tomcat AJP connector.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("tomcat.ajp")
public class TomcatAjpProperties {

  /**
   * Whether the AJP connector is started.
   */
  private boolean enabled = false;

  /**
   * The port of the AJP connector.
   */
  private int port = 8009;

  /**
   * The AJP secret.
   */
  private String secret;

  /**
   * Whether the AJP secret is required.
   */
  private boolean secretRequired = false;

  /**
   * Tells whether the AJP connector is started.
   *
   * @return {@code true} if the connector is started
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns whether the AJP connector is started.
   *
   * @param enabled {@code true} to start the connector
   */
  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  /**
   * Gets the port of the AJP connector.
   *
   * @return the port
   */
  public int getPort() {
    return this.port;
  }

  /**
   * Assigns the port of the AJP connector.
   *
   * @param port the port
   */
  public void setPort(final int port) {
    this.port = port;
  }

  /**
   * Gets the AJP secret.
   *
   * @return the secret, or {@code null}
   */
  public @Nullable String getSecret() {
    return this.secret;
  }

  /**
   * Assigns the AJP secret.
   *
   * @param secret the secret
   */
  public void setSecret(final @Nullable String secret) {
    this.secret = secret;
  }

  /**
   * Tells whether the AJP secret is required.
   *
   * @return {@code true} if the secret is required
   */
  public boolean isSecretRequired() {
    return this.secretRequired;
  }

  /**
   * Assigns whether the AJP secret is required.
   *
   * @param secretRequired {@code true} if the secret is required
   */
  public void setSecretRequired(final boolean secretRequired) {
    this.secretRequired = secretRequired;
  }

}
