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
package se.swedenconnect.spring.authnserver.autoconfigure.saml;

import java.security.cert.X509Certificate;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

/**
 * Loads the SAML Identity Provider credentials from the {@code authn-server.saml.credentials.*} properties. Each
 * credential may instead be declared as a bean with the name given by the constants of this class.
 *
 * @author Martin Lindström
 */
@Configuration(proxyBeanMethods = false)
public class SamlCredentialConfiguration {

  /** The bean name of the default credential. */
  public static final String DEFAULT_CREDENTIAL = "authn-server.saml.credentials.Default";

  /** The bean name of the signing credential. */
  public static final String SIGN_CREDENTIAL = "authn-server.saml.credentials.Sign";

  /** The bean name of the future signing certificate. */
  public static final String FUTURE_SIGN_CERTIFICATE = "authn-server.saml.credentials.FutureSign";

  /** The bean name of the encryption credential. */
  public static final String ENCRYPT_CREDENTIAL = "authn-server.saml.credentials.Encrypt";

  /** The bean name of the previous encryption credential. */
  public static final String PREVIOUS_ENCRYPT_CREDENTIAL = "authn-server.saml.credentials.PreviousEncrypt";

  /** The bean name of the metadata signing credential. */
  public static final String METADATA_SIGN_CREDENTIAL = "authn-server.saml.credentials.MetadataSign";

  /** The credential properties. */
  private final SamlConfigurationProperties.CredentialProperties properties;

  /** The credential factory. */
  private final PkiCredentialFactory credentialFactory;

  /**
   * Constructor.
   *
   * @param properties the SAML properties
   * @param credentialFactory the credential factory
   */
  public SamlCredentialConfiguration(final SamlConfigurationProperties properties,
      final PkiCredentialFactory credentialFactory) {
    this.properties = properties.getCredentials();
    this.credentialFactory = credentialFactory;
  }

  /**
   * Gets the default credential from the properties.
   *
   * @return the default credential, or {@code null} if not configured
   * @throws Exception for errors loading the credential
   */
  @ConditionalOnMissingBean(name = DEFAULT_CREDENTIAL)
  @Bean(DEFAULT_CREDENTIAL)
  PkiCredential defaultCredential() throws Exception {
    return this.loadCredential(this.properties.getDefaultCredential());
  }

  /**
   * Gets the signing credential from the properties.
   *
   * @return the signing credential, or {@code null} if not configured
   * @throws Exception for errors loading the credential
   */
  @ConditionalOnMissingBean(name = SIGN_CREDENTIAL)
  @Bean(SIGN_CREDENTIAL)
  PkiCredential signCredential() throws Exception {
    return this.loadCredential(this.properties.getSign());
  }

  /**
   * Gets the future signing certificate from the properties.
   *
   * @return the future signing certificate, or {@code null} if not configured
   */
  @ConditionalOnMissingBean(name = FUTURE_SIGN_CERTIFICATE)
  @Bean(FUTURE_SIGN_CERTIFICATE)
  X509Certificate futureSignCertificate() {
    return this.properties.getFutureSign();
  }

  /**
   * Gets the encryption credential from the properties.
   *
   * @return the encryption credential, or {@code null} if not configured
   * @throws Exception for errors loading the credential
   */
  @ConditionalOnMissingBean(name = ENCRYPT_CREDENTIAL)
  @Bean(ENCRYPT_CREDENTIAL)
  PkiCredential encryptCredential() throws Exception {
    return this.loadCredential(this.properties.getEncrypt());
  }

  /**
   * Gets the previous encryption credential from the properties.
   *
   * @return the previous encryption credential, or {@code null} if not configured
   * @throws Exception for errors loading the credential
   */
  @ConditionalOnMissingBean(name = PREVIOUS_ENCRYPT_CREDENTIAL)
  @Bean(PREVIOUS_ENCRYPT_CREDENTIAL)
  PkiCredential previousEncryptCredential() throws Exception {
    return this.loadCredential(this.properties.getPreviousEncrypt());
  }

  /**
   * Gets the metadata signing credential from the properties.
   *
   * @return the metadata signing credential, or {@code null} if not configured
   * @throws Exception for errors loading the credential
   */
  @ConditionalOnMissingBean(name = METADATA_SIGN_CREDENTIAL)
  @Bean(METADATA_SIGN_CREDENTIAL)
  PkiCredential metadataSignCredential() throws Exception {
    return this.loadCredential(this.properties.getMetadataSign());
  }

  /**
   * Loads a credential.
   *
   * @param configuration the credential configuration
   * @return the credential, or {@code null} if no configuration was given
   * @throws Exception for errors loading the credential
   */
  private @Nullable PkiCredential loadCredential(final @Nullable PkiCredentialConfigurationProperties configuration)
      throws Exception {
    return configuration != null ? this.credentialFactory.createCredential(configuration) : null;
  }

}
