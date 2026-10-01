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

import java.util.List;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the simulated authentication.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("authn")
public class AuthnProperties {

  /**
   * The name of the authentication provider.
   */
  private String providerName;

  /**
   * The path of the user picker, where the user is sent for authentication.
   */
  private String authnPath;

  /**
   * The path that the user is sent back to after the authentication.
   */
  private String resumePath;

  /**
   * The supported levels of assurance (authentication context URIs).
   */
  private List<String> supportedLoas;

  /**
   * The SAML entity categories that the authentication provider declares.
   */
  private List<String> entityCategories;

  /**
   * Gets the name of the authentication provider.
   *
   * @return the provider name
   */
  public @Nullable String getProviderName() {
    return this.providerName;
  }

  /**
   * Assigns the name of the authentication provider.
   *
   * @param providerName the provider name
   */
  public void setProviderName(final @Nullable String providerName) {
    this.providerName = providerName;
  }

  /**
   * Gets the path of the user picker.
   *
   * @return the path
   */
  public @Nullable String getAuthnPath() {
    return this.authnPath;
  }

  /**
   * Assigns the path of the user picker.
   *
   * @param authnPath the path
   */
  public void setAuthnPath(final @Nullable String authnPath) {
    this.authnPath = authnPath;
  }

  /**
   * Gets the path that the user is sent back to after the authentication.
   *
   * @return the path
   */
  public @Nullable String getResumePath() {
    return this.resumePath;
  }

  /**
   * Assigns the path that the user is sent back to after the authentication.
   *
   * @param resumePath the path
   */
  public void setResumePath(final @Nullable String resumePath) {
    this.resumePath = resumePath;
  }

  /**
   * Gets the supported levels of assurance.
   *
   * @return the LoA URIs
   */
  public @Nullable List<String> getSupportedLoas() {
    return this.supportedLoas;
  }

  /**
   * Assigns the supported levels of assurance.
   *
   * @param supportedLoas the LoA URIs
   */
  public void setSupportedLoas(final @Nullable List<String> supportedLoas) {
    this.supportedLoas = supportedLoas;
  }

  /**
   * Gets the SAML entity categories that the authentication provider declares.
   *
   * @return the entity category URIs
   */
  public @Nullable List<String> getEntityCategories() {
    return this.entityCategories;
  }

  /**
   * Assigns the SAML entity categories that the authentication provider declares.
   *
   * @param entityCategories the entity category URIs
   */
  public void setEntityCategories(final @Nullable List<String> entityCategories) {
    this.entityCategories = entityCategories;
  }

}
