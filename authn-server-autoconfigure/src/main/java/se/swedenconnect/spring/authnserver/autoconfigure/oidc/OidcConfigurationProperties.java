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
package se.swedenconnect.spring.authnserver.autoconfigure.oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the OpenID Provider.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(OidcConfigurationProperties.PREFIX)
public class OidcConfigurationProperties {

  /** The property prefix. */
  public static final String PREFIX = "authn-server.oidc";

  /**
   * Whether the OpenID Provider is enabled. Defaults to false.
   */
  private boolean enabled = false;

  /**
   * Tells whether the OpenID Provider is enabled.
   *
   * @return whether the OpenID Provider is enabled
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns whether the OpenID Provider is enabled.
   *
   * @param enabled whether the OpenID Provider is enabled
   */
  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

}
