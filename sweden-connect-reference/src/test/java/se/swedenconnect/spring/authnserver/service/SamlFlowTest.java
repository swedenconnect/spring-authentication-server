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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * End-to-end tests of SAML flows through the user picker, with the complete profile.
 *
 * @author Martin Lindström
 */
class SamlFlowTest extends AbstractCompleteProfileTest {

  static final String SP = "https://sp.test.local";

  static final String SIGN_SP = "https://sign.test.local";

  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  static final String USER = "197705232382";

  static final String OTHER_USER = "188803099368";

  @Test
  void samlFlowWithChoiceOfLevelOfAssurance() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final HttpResponse<String> page = this.startAuthentication(browser, SP, r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
            .authnContextClassRefs(LOA3, LOA2)
            .build()));

    assertThat(page.statusCode()).isEqualTo(200);
    final String html = page.body();
    // The requester name from the SP metadata, and the requested levels of assurance to choose among
    assertThat(html).contains("Test Service").contains("https://sp.test.local/logo.svg");
    assertThat(TestBrowser.optionValues(html, "selectLoa")).containsExactly(LOA3, LOA2);
    assertThat(TestBrowser.startTag(html, "selectSimulatedUser")).doesNotContain("disabled");
    assertThat(html).doesNotContain("sign-message");
    // The users that the advanced view fills in names from
    assertThat(html).containsPattern(
        "var users = \\[.*\\{\"pnr\":\"197705232382\",\"givenName\":\"Frida\",\"surname\":\"Kranstege\"\\}");

    final Assertion assertion = this.assertion(this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA2)));
    assertThat(assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI())
        .isEqualTo(LOA2);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isEqualTo(USER);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isEqualTo("Frida");

    // The last selection is remembered and pre-selected
    final String next = this.startAuthentication(browser, SP, r -> {}).body();
    assertThat(TestBrowser.startTag(next, "selectSimulatedUser")).doesNotContain("disabled");
    assertThat(TestBrowser.selectedOption(next, "selectSimulatedUser")).isEqualTo(USER);
    assertThat(TestBrowser.selectedOption(next, "selectLoa")).isEqualTo(LOA2);
  }

  @Test
  void aUserIsAuthenticatedAtLoa4() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final HttpResponse<String> page = this.startAuthentication(browser, SP, r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
            .authnContextClassRefs(LOA4)
            .build()));
    assertThat(page.statusCode()).isEqualTo(200);
    // A single level of assurance is not offered as a choice
    assertThat(TestBrowser.inputValue(page.body(), "loa")).isEqualTo(LOA4);

    final Assertion assertion = this.assertion(this.complete(browser, page.body(), Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA4)));
    assertThat(assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI())
        .isEqualTo(LOA4);
  }

  @Test
  void signatureServiceWithSignMessageAndLockedUser() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final HttpResponse<String> page = this.startAuthentication(browser, SIGN_SP, r -> r.setExtensions(
        ExtensionsBuilder.builder()
            .extension(signMessage("I approve **this** document"))
            .extension(PrincipalSelectionBuilder.builder()
                .matchValues(MatchValueBuilder.builder()
                    .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                    .value(OTHER_USER)
                    .build())
                .build())
            .build()));

    assertThat(page.statusCode()).isEqualTo(200);
    final String html = page.body();
    // A signature service, with its sign message shown as HTML
    assertThat(html).contains("Test Signature Service").contains("requests your signature");
    assertThat(html).contains("sign-message").contains("<strong>this</strong>");
    // The user is locked
    assertThat(TestBrowser.startTag(html, "selectSimulatedUser")).contains("disabled");
    assertThat(TestBrowser.selectedOption(html, "selectSimulatedUser")).isEqualTo(OTHER_USER);
    assertThat(TestBrowser.inputValue(html, "personalIdentityNumber")).isEqualTo(OTHER_USER);

    final Response response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", OTHER_USER,
        "loa", LOA3,
        "signMessageDisplayed", "true"));
    final Assertion assertion = this.assertion(response);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isEqualTo(OTHER_USER);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST)).isNotBlank();
  }

  @Test
  void aSignMessageThatIsNotDisplayedFails() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SIGN_SP, r -> r.setExtensions(
        ExtensionsBuilder.builder().extension(signMessage("Sign it")).build())).body();
    final Response response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA3));
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.RESPONDER);
  }

  @Test
  void cancelGivesTheCancelStatus() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> {}).body();
    final Response response = this.complete(browser, html, Map.of("action", "cancel"));
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.RESPONDER);
    assertThat(response.getStatus().getStatusCode().getStatusCode().getValue())
        .isEqualTo("http://id.elegnamnden.se/status/1.0/cancel");
  }

  @Test
  void aSimulatedErrorIsReported() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> {}).body();
    assertThat(TestBrowser.optionValues(html, "selectError")).contains("AUTHN_FAILED", "FRAUD", "CANCEL");
    final Response response = this.complete(browser, html, Map.of(
        "action", "error",
        "error", "FRAUD",
        "errorMessage", "Simulated fraud"));
    assertThat(response.getStatus().getStatusCode().getStatusCode().getValue())
        .isEqualTo("http://id.elegnamnden.se/status/1.0/fraud");
    assertThat(response.getStatus().getStatusMessage().getValue()).isEqualTo("Simulated fraud");
  }

  @Test
  void anUnknownUserGivesUnknownPrincipal() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> {}).body();
    final Response response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", "NONE",
        "loa", LOA3));
    assertThat(response.getStatus().getStatusCode().getStatusCode().getValue())
        .isEqualTo(StatusCode.UNKNOWN_PRINCIPAL);
  }

  @Test
  void aLevelOfAssuranceThatWasNotRequestedFails() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
            .authnContextClassRefs(LOA3)
            .build())).body();
    // A single level of assurance is not offered as a choice
    assertThat(TestBrowser.optionValues(html, "selectLoa")).isEmpty();
    assertThat(TestBrowser.inputValue(html, "loa")).isEqualTo(LOA3);

    final Response response = this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", USER,
        "loa", LOA2));
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.RESPONDER);
  }

  @Test
  void aCustomUserIsSavedAndOfferedTheNextTime() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> {}).body();
    final Assertion assertion = this.assertion(this.complete(browser, html, Map.of(
        "action", "ok",
        "personalIdentityNumber", "NONE",
        "customPersonalIdentityNumber", "199001022389",
        "givenName", "Kalle",
        "surname", "Kula",
        "loa", LOA3)));
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .isEqualTo("199001022389");
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH)).isEqualTo("1990-01-02");

    final String next = this.startAuthentication(browser, SP, r -> {}).body();
    assertThat(TestBrowser.optionValues(next, "selectSimulatedUser")).contains("199001022389");
  }

  @Test
  void theLanguageCanBeSwitchedDuringTheAuthentication() throws Exception {
    final TestBrowser browser = new TestBrowser();
    final String html = this.startAuthentication(browser, SP, r -> {}).body();
    assertThat(html).contains("Test Service");
    final String authnId = TestBrowser.inputValue(html, "authnId");

    final HttpResponse<String> swedish = browser.get(BASE_URL + "/extauth?authnId=" + authnId + "&lang=sv");
    assertThat(swedish.statusCode()).isEqualTo(200);
    assertThat(swedish.body()).contains("Testtjänst").contains("begär att du legitimerar dig");
    assertThat(TestBrowser.inputValue(swedish.body(), "authnId")).isEqualTo(authnId);
  }

  @Test
  void aRequestToTheUserPickerWithoutAnAuthenticationShowsTheErrorPage() throws Exception {
    final HttpResponse<String> response = new TestBrowser().get(BASE_URL + "/extauth?authnId=unknown");
    assertThat(response.statusCode()).isEqualTo(400);
    assertThat(response.body()).contains("An error occurred").contains("session data was not found");
  }

  /**
   * Sends an authentication request from a Service Provider and follows the redirects to the user picker.
   */
  private HttpResponse<String> startAuthentication(final TestBrowser browser, final String sp,
      final Consumer<AuthnRequest> customizer) throws Exception {
    final RequestHttpObject<AuthnRequest> request = generate(sp, customizer);
    return browser.follow(browser.get(request.getSendUrl()), BASE_URL);
  }

  /**
   * Posts the user picker and returns the SAML response that the response page posts.
   */
  private Response complete(final TestBrowser browser, final String html, final Map<String, String> form)
      throws Exception {
    final Map<String, String> parameters = new HashMap<>(form);
    parameters.put("authnId", TestBrowser.inputValue(html, "authnId"));
    final HttpResponse<String> page = browser.follow(
        browser.post(BASE_URL + TestBrowser.formAction(html), parameters), BASE_URL);
    assertThat(page.statusCode()).isEqualTo(200);
    final String samlResponse = TestBrowser.inputValue(page.body(), "SAMLResponse");
    assertThat(samlResponse).isNotNull();
    assertThat(TestBrowser.inputValue(page.body(), "RelayState")).isEqualTo("relay");
    return (Response) unmarshall(Base64.getDecoder().decode(samlResponse));
  }

  private Assertion assertion(final Response response) throws Exception {
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
    final SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(List.<Credential>of(new OpenSamlCredential(
        SP_CREDENTIAL)));
    return decrypter.decrypt(response.getEncryptedAssertions().getFirst().getEncryptedData(), Assertion.class);
  }

  private static String attribute(final Assertion assertion, final String name) {
    return assertion.getAttributeStatements().getFirst().getAttributes().stream()
        .filter(a -> name.equals(a.getName()))
        .map(AttributeUtils::getAttributeStringValue)
        .findFirst()
        .orElse(null);
  }

  private static SignMessage signMessage(final String markdown) {
    final SignMessage signMessage = (SignMessage) XMLObjectSupport.buildXMLObject(SignMessage.DEFAULT_ELEMENT_NAME);
    signMessage.setDisplayEntity(ENTITY_ID);
    signMessage.setMustShow(true);
    signMessage.setMimeType("text/markdown");
    final Message message = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
    message.setValue(Base64.getEncoder().encodeToString(markdown.getBytes(StandardCharsets.UTF_8)));
    signMessage.setMessage(message);
    return signMessage;
  }

  // SAML support

  static final PkiCredential SP_CREDENTIAL = loadCredential();

  private static RequestHttpObject<AuthnRequest> generate(final String sp, final Consumer<AuthnRequest> customizer)
      throws Exception {
    final EntityDescriptor spMetadata = spMetadata(sp);
    final EntityDescriptor idpMetadata = idpMetadata();
    final AbstractAuthnRequestGenerator generator =
        new AbstractAuthnRequestGenerator(sp, new OpenSamlCredential(SP_CREDENTIAL)) {

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
    return generator.generateAuthnRequest(idpMetadata, "relay", new AuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
      }

      @Override
      public AuthnRequestCustomizer getAuthnRequestCustomizer() {
        return customizer::accept;
      }
    });
  }

  private static EntityDescriptor spMetadata(final String entityId) throws Exception {
    try (final InputStream is = new ClassPathResource("complete/sp-metadata.xml").getInputStream()) {
      final EntitiesDescriptor entities = (EntitiesDescriptor) XMLObjectSupport.unmarshallFromInputStream(
          XMLObjectProviderRegistrySupport.getParserPool(), is);
      return entities.getEntityDescriptors().stream()
          .filter(e -> entityId.equals(e.getEntityID()))
          .findFirst()
          .orElseThrow();
    }
  }

  private static EntityDescriptor idpMetadata() throws Exception {
    final HttpResponse<String> response = new TestBrowser().get(BASE_URL + "/saml2/metadata");
    assertThat(response.statusCode()).isEqualTo(200);
    return (EntityDescriptor) unmarshall(response.body().getBytes(StandardCharsets.UTF_8));
  }

  private static XMLObject unmarshall(final byte[] xml) throws Exception {
    return XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(),
        new ByteArrayInputStream(xml));
  }

  private static PkiCredential loadCredential() {
    try (final InputStream is = new ClassPathResource("complete/test-clients.p12").getInputStream()) {
      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "PKCS12", null);
      return new KeyStoreCredential(keyStore, "sp", "secret".toCharArray());
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
