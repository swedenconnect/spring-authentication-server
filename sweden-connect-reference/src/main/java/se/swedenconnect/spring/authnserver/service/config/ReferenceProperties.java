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
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

/**
 * Configuration properties of the reference that the server's own properties do not cover.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("reference")
public class ReferenceProperties {

  /**
   * The OpenID Connect clients.
   */
  private final Oidc oidc = new Oidc();

  /**
   * Gets the OpenID Connect settings.
   *
   * @return the OpenID Connect settings
   */
  public @NonNull Oidc getOidc() {
    return this.oidc;
  }

  /**
   * The OpenID Connect settings.
   */
  public static class Oidc {

    /**
     * The statically configured OpenID Connect clients. Each location holds the client metadata of one client as a JSON
     * object, with its client_id, or a JSON array of such objects.
     */
    private List<Resource> clients = new ArrayList<>();

    /**
     * Gets the locations of the statically configured clients.
     *
     * @return the locations
     */
    public @NonNull List<Resource> getClients() {
      return this.clients;
    }

    /**
     * Assigns the locations of the statically configured clients.
     *
     * @param clients the locations
     */
    public void setClients(final @Nullable List<Resource> clients) {
      this.clients = clients != null ? clients : new ArrayList<>();
    }

  }

}
