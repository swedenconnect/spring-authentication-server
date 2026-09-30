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
package se.swedenconnect.spring.authnserver.saml.authnrequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.HtmlUtils;

import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.IDPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SingleSignOnServiceBuilder;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * Support for tests that send SAML authentication requests: an SP with its credential and metadata, the IdP metadata
 * that the SP sends requests to, and mapping of generated requests to HTTP requests.
 *
 * @author Martin Lindström
 */
final class SamlRequestTestSupport {

  static final String IDP_HOST = "idp.example.com";

  static final String CONTEXT_PATH = "/auth";

  static final String BASE_URL = "https://" + IDP_HOST + CONTEXT_PATH;

  static final String SP_ENTITY_ID = "https://sp.example.com";

  static final String ACS_URL = "https://sp.example.com/acs";

  static final String RELAY_STATE = "the-relay-state";

  static final PkiCredential SP_CREDENTIAL = load("test-sp.p12", "sp");

  static final PkiCredential OTHER_CREDENTIAL = load("test-sp.p12", "other");

  static final PkiCredential IDP_ENCRYPT = load("idp-credentials.p12", "encrypt");

  private SamlRequestTestSupport() {
  }

  static PkiCredential load(final String file, final String alias) {
    try (final InputStream is = new ClassPathResource("credentials/" + file).getInputStream()) {
      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "PKCS12", null);
      final KeyStoreCredential credential = new KeyStoreCredential(keyStore, alias, "secret".toCharArray());
      credential.setName(alias);
      return credential;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates the SP metadata: signing and encryption keys, a default POST assertion consumer service and a second one,
   * and the supplied entity categories.
   */
  static EntityDescriptor spMetadata(final Consumer<SPSSODescriptorBuilder> customizer, final String... categories) {
    final SPSSODescriptorBuilder sp = SPSSODescriptorBuilder.builder()
        .authnRequestsSigned(true)
        .keyDescriptors(
            KeyDescriptorBuilder.builder().use(UsageType.SIGNING).certificate(SP_CREDENTIAL.getCertificate()).build(),
            KeyDescriptorBuilder.builder().use(UsageType.ENCRYPTION).certificate(SP_CREDENTIAL.getCertificate())
                .build())
        .assertionConsumerServices(
            AssertionConsumerServiceBuilder.builder().postBinding().location(ACS_URL).index(0).isDefault(true)
                .build(),
            AssertionConsumerServiceBuilder.builder().postBinding().location(ACS_URL + "2").index(1).build());
    customizer.accept(sp);
    final EntityDescriptorBuilder builder = EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(sp.build());
    if (categories.length > 0) {
      builder.extensions(ExtensionsBuilder.builder()
          .extension(EntityAttributesBuilder.builder().entityCategoriesAttribute(categories).build())
          .build());
    }
    return builder.build();
  }

  /**
   * Creates IdP metadata for the SP to send requests to, with the redirect and POST endpoints at the supplied paths.
   */
  static EntityDescriptor idpMetadata(final String redirectPath, final String postPath) {
    final List<KeyDescriptor> keys = new ArrayList<>();
    keys.add(KeyDescriptorBuilder.builder().use(UsageType.ENCRYPTION).certificate(IDP_ENCRYPT.getCertificate())
        .build());
    return EntityDescriptorBuilder.builder()
        .entityID(BASE_URL)
        .roleDescriptors(IDPSSODescriptorBuilder.builder()
            .wantAuthnRequestsSigned(true)
            .keyDescriptors(keys)
            .singleSignOnServices(
                SingleSignOnServiceBuilder.builder().redirectBinding().location(BASE_URL + redirectPath).build(),
                SingleSignOnServiceBuilder.builder().postBinding().location(BASE_URL + postPath).build())
            .build())
        .build();
  }

  /**
   * Generates an authentication request.
   */
  static RequestHttpObject<AuthnRequest> generate(final EntityDescriptor spMetadata, final EntityDescriptor idpMetadata,
      final PkiCredential signCredential, final String binding, final Consumer<AuthnRequest> customizer)
      throws Exception {

    final X509Credential credential = signCredential != null ? new OpenSamlCredential(signCredential) : null;
    final AbstractAuthnRequestGenerator generator = new AbstractAuthnRequestGenerator(SP_ENTITY_ID, credential) {

      @Override
      protected EntityDescriptor getSpMetadata() {
        return spMetadata;
      }

      @Override
      protected EntityDescriptor getIdpMetadata(final String idpEntityID) {
        return idpMetadata;
      }
    };
    generator.initialize();
    return generator.generateAuthnRequest(idpMetadata, RELAY_STATE, new AuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return binding;
      }

      @Override
      public Boolean getForceAuthnAttribute() {
        return null;
      }

      @Override
      public AuthnRequestCustomizer getAuthnRequestCustomizer() {
        return customizer::accept;
      }
    });
  }

  /**
   * Maps a generated request to the HTTP request that the IdP receives.
   */
  static MockHttpServletRequest toHttpRequest(final RequestHttpObject<AuthnRequest> request) {
    final URI uri = URI.create(request.getSendUrl());
    final MockHttpServletRequest httpRequest = new MockHttpServletRequest(request.getMethod(), uri.getRawPath());
    httpRequest.setScheme("https");
    httpRequest.setSecure(true);
    httpRequest.setServerName(uri.getHost());
    httpRequest.setServerPort(443);
    httpRequest.setContextPath(CONTEXT_PATH);
    httpRequest.setServletPath(uri.getRawPath().substring(CONTEXT_PATH.length()));
    if ("GET".equals(request.getMethod())) {
      httpRequest.setQueryString(uri.getRawQuery());
      for (final String pair : uri.getRawQuery().split("&")) {
        final int eq = pair.indexOf('=');
        httpRequest.addParameter(pair.substring(0, eq),
            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    else {
      httpRequest.setContentType("application/x-www-form-urlencoded");
      for (final Map.Entry<String, String> e : request.getRequestParameters().entrySet()) {
        httpRequest.addParameter(e.getKey(), e.getValue());
      }
    }
    return httpRequest;
  }

  /**
   * Gets the SAML response posted by the response page.
   */
  static Response parseResponse(final MockHttpServletResponse response) throws Exception {
    final String html = response.getContentAsString();
    final Matcher matcher = Pattern.compile("name=\"SAMLResponse\" value=\"([^\"]*)\"").matcher(html);
    if (!matcher.find()) {
      throw new IllegalStateException("No SAMLResponse in page: " + html);
    }
    final byte[] xml = Base64.getDecoder().decode(HtmlUtils.htmlUnescape(matcher.group(1)));
    return (Response) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(xml));
  }

  /**
   * Gets the action URL of the response page.
   */
  static String responseDestination(final MockHttpServletResponse response) throws Exception {
    final Matcher matcher = Pattern.compile("<form action=\"([^\"]*)\"").matcher(response.getContentAsString());
    return matcher.find() ? HtmlUtils.htmlUnescape(matcher.group(1)) : null;
  }

  /**
   * Gets the relay state of the response page.
   */
  static String responseRelayState(final MockHttpServletResponse response) throws Exception {
    final Matcher matcher =
        Pattern.compile("name=\"RelayState\" value=\"([^\"]*)\"").matcher(response.getContentAsString());
    return matcher.find() ? HtmlUtils.htmlUnescape(matcher.group(1)) : null;
  }

  static final String REDIRECT_BINDING = SAMLConstants.SAML2_REDIRECT_BINDING_URI;

  static final String POST_BINDING = SAMLConstants.SAML2_POST_BINDING_URI;

}
