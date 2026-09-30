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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerProtocolConfigurerFactory;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.saml.config.IdpMetadataElements;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGeneratorFactory;

/**
 * Autoconfiguration for the SAML Identity Provider. Active when the SAML module is on the classpath and
 * {@code authn-server.saml.enabled} is {@code true}.
 * <p>
 * It initializes OpenSAML, loads the credentials, and declares the factory that creates the
 * {@link Saml2IdpConfigurer} from the {@link SamlConfigurationProperties}.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration(afterName = "se.swedenconnect.security.credential.spring.autoconfigure."
    + "SpringCredentialBundlesAutoConfiguration")
@ConditionalOnClass(Saml2IdpConfigurer.class)
@ConditionalOnProperty(prefix = SamlConfigurationProperties.PREFIX, name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SamlConfigurationProperties.class)
@Import(SamlCredentialConfiguration.class)
public class SamlAutoConfiguration {

  /**
   * Initializes OpenSAML, which the SAML support needs.
   *
   * @return the {@link OpenSAMLInitializer}
   * @throws Exception for initialization errors
   */
  @Bean("openSAML")
  @ConditionalOnMissingBean
  OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
        new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
        new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

  /**
   * Creates the factory for the SAML protocol configurer.
   *
   * @param openSAML the OpenSAML initializer, which must be initialized before the configurer is used
   * @param properties the SAML properties
   * @param defaultCredential the default credential
   * @param signCredential the signing credential
   * @param futureSignCertificate the future signing certificate
   * @param encryptCredential the encryption credential
   * @param previousEncryptCredential the previous encryption credential
   * @param metadataSignCredential the metadata signing credential
   * @param nameIdGeneratorFactory the NameID generator factory, if declared as a bean
   * @return an {@link AuthnServerProtocolConfigurerFactory}
   */
  @Bean
  AuthnServerProtocolConfigurerFactory samlProtocolConfigurerFactory(
      final OpenSAMLInitializer openSAML,
      final SamlConfigurationProperties properties,
      @Qualifier(SamlCredentialConfiguration.DEFAULT_CREDENTIAL) final ObjectProvider<PkiCredential> defaultCredential,
      @Qualifier(SamlCredentialConfiguration.SIGN_CREDENTIAL) final ObjectProvider<PkiCredential> signCredential,
      @Qualifier(SamlCredentialConfiguration.FUTURE_SIGN_CERTIFICATE)
      final ObjectProvider<X509Certificate> futureSignCertificate,
      @Qualifier(SamlCredentialConfiguration.ENCRYPT_CREDENTIAL) final ObjectProvider<PkiCredential> encryptCredential,
      @Qualifier(SamlCredentialConfiguration.PREVIOUS_ENCRYPT_CREDENTIAL)
      final ObjectProvider<PkiCredential> previousEncryptCredential,
      @Qualifier(SamlCredentialConfiguration.METADATA_SIGN_CREDENTIAL)
      final ObjectProvider<PkiCredential> metadataSignCredential,
      final ObjectProvider<NameIDGeneratorFactory> nameIdGeneratorFactory) {

    return server -> createConfigurer(server, properties)
        .defaultCredential(defaultCredential.getIfAvailable())
        .signCredential(signCredential.getIfAvailable())
        .futureSignCertificate(futureSignCertificate.getIfAvailable())
        .encryptCredential(encryptCredential.getIfAvailable())
        .previousEncryptCredential(previousEncryptCredential.getIfAvailable())
        .metadataSignCredential(metadataSignCredential.getIfAvailable())
        .nameIdGeneratorFactory(nameIdGeneratorFactory.getIfUnique());
  }

  /**
   * Creates a {@link Saml2IdpConfigurer} from the property values, except the credentials. Values that have not been
   * assigned are left at the configurer's defaults.
   *
   * @param server the shared configurer
   * @param properties the SAML properties
   * @return the configurer
   */
  static @Nonnull Saml2IdpConfigurer createConfigurer(final @Nonnull AuthnServerConfigurer server,
      final @Nonnull SamlConfigurationProperties properties) {

    final Saml2IdpConfigurer configurer = new Saml2IdpConfigurer();
    if (properties.getPath() != null) {
      configurer.path(properties.getPath());
    }
    configurer.entityId(properties.getEntityId());
    configurer.hokBaseUrl(properties.getHokBaseUrl());
    if (properties.getRequiresSignedRequests() != null) {
      configurer.requiresSignedRequests(properties.getRequiresSignedRequests());
    }
    if (properties.getSso().isAssigned()) {
      configurer.ssoPolicy(
          properties.getSso().toPolicy(server.getSsoPolicy(), SamlConfigurationProperties.PREFIX + ".sso"));
    }
    configurer.clockSkew(properties.getClockSkew());
    configurer.supportsUserMessage(properties.getSupportsUserMessage());
    configurer.subjectIdentifierSecret(properties.getSubjectIdentifier().getSecretBytes());
    configurer.subjectIdentifierHashAlgorithm(properties.getSubjectIdentifier().getHashAlgorithm());

    final SamlConfigurationProperties.EndpointProperties endpoints = properties.getEndpoints();
    if (endpoints.getRedirectAuthn() != null) {
      configurer.redirectAuthnEndpoint(endpoints.getRedirectAuthn());
    }
    if (endpoints.getPostAuthn() != null) {
      configurer.postAuthnEndpoint(endpoints.getPostAuthn());
    }
    configurer.hokRedirectAuthnEndpoint(endpoints.getHokRedirectAuthn());
    configurer.hokPostAuthnEndpoint(endpoints.getHokPostAuthn());
    if (endpoints.getMetadata() != null) {
      configurer.metadataEndpoint(endpoints.getMetadata());
    }

    final SamlConfigurationProperties.MetadataProperties md = properties.getMetadata();
    configurer.idpMetadataEndpoint(m -> {
      m.template(md.getTemplate());
      if (md.getCacheDuration() != null) {
        m.cacheDuration(md.getCacheDuration());
      }
      if (md.getValidityPeriod() != null) {
        m.validityPeriod(md.getValidityPeriod());
      }
      m.digestMethods(md.getDigestMethods());
      m.digestMethodsUnderRole(md.isIncludeDigestMethodsUnderRole());
      if (md.getSigningMethods() != null) {
        m.signingMethods(md.getSigningMethods().stream()
            .map(s -> new IdpMetadataElements.SigningMethod(s.getAlgorithm(), s.getMinKeySize(), s.getMaxKeySize()))
            .toList());
      }
      m.signingMethodsUnderRole(md.isIncludeSigningMethodsUnderRole());
      if (md.getEncryptionMethods() != null) {
        m.encryptionMethods(md.getEncryptionMethods().stream()
            .map(e -> new IdpMetadataElements.EncryptionMethod(
                e.getAlgorithm(), e.getKeySize(), e.getOaepParams(), e.getDigestMethod()))
            .toList());
      }
      m.uiInfo(toUiInfo(md.getUiInfo()));
      m.requestedPrincipalSelection(md.getRequestedPrincipalSelection());
      if (md.getOrganization() != null) {
        final SamlConfigurationProperties.MetadataProperties.Organization o = md.getOrganization();
        m.organization(new IdpMetadataElements.Organization(o.getNames(), o.getDisplayNames(), o.getUrls(),
            o.getNumber()));
      }
      if (md.getContactPersons() != null) {
        final Map<IdpMetadataElements.ContactPersonType, IdpMetadataElements.ContactPerson> contactPersons =
            new LinkedHashMap<>();
        md.getContactPersons().forEach((type, c) -> contactPersons.put(type,
            new IdpMetadataElements.ContactPerson(c.getCompany(), c.getGivenName(), c.getSurname(),
                c.getEmailAddresses(), c.getTelephoneNumbers())));
        m.contactPersons(contactPersons);
      }
    });
    return configurer;
  }

  /**
   * Maps the UI information properties.
   *
   * @param uiInfo the properties
   * @return the UI information, or {@code null}
   */
  private static @Nullable IdpMetadataElements.UiInfo toUiInfo(
      final @Nullable SamlConfigurationProperties.MetadataProperties.UiInfo uiInfo) {
    if (uiInfo == null) {
      return null;
    }
    return new IdpMetadataElements.UiInfo(uiInfo.getDisplayNames(), uiInfo.getDescriptions(),
        uiInfo.getLogotypes() != null
            ? uiInfo.getLogotypes().stream()
                .map(l -> new IdpMetadataElements.Logo(l.getUrl(), l.getPath(), l.getHeight(), l.getWidth(),
                    l.getLanguageTag()))
                .toList()
            : null);
  }

}
