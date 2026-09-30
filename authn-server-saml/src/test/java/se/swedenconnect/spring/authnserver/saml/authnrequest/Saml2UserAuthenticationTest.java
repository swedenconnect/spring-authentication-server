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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.ACS_URL;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.BASE_URL;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.CONTEXT_PATH;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.IDP_ENCRYPT;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.OTHER_CREDENTIAL;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.POST_BINDING;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.RELAY_STATE;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.SP_CREDENTIAL;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.SP_ENTITY_ID;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.generate;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.idpMetadata;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.parseResponse;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.responseDestination;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.responseRelayState;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.spMetadata;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.toHttpRequest;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.Filter;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.KeyInfoConfirmationDataType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseVote;
import se.swedenconnect.spring.authnserver.attributes.release.DefaultAttributeProducer;
import se.swedenconnect.spring.authnserver.attributes.release.IncludeAllAttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.SwedenConnectPostAuthenticationProcessor;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.attributes.release.SwedenConnectAttributeProducer;
import se.swedenconnect.spring.authnserver.saml.attributes.release.SwedenConnectAttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.sso.RequestedAttributesSsoVoter;
import se.swedenconnect.spring.authnserver.sso.SsoDecision;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

/**
 * End-to-end tests of the SAML Identity Provider: an authentication request from a test SP, the user authentication
 * through a direct or a redirect provider, single sign-on, and the response.
 *
 * @author Martin Lindström
 */
class Saml2UserAuthenticationTest extends OpenSamlTestBase {

  private static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private static final String PNR = "197705232382";

  private static final String COORDINATION_NUMBER = "197010632391";

  private static final String LOA3_PNR = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri();

  private static final String SIGSERVICE = EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri();

  private static final String ACCEPTS_COORDINATION_NUMBER =
      EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri();

  private static final PkiCredential IDP_SIGN = SamlRequestTestSupport.load("idp-credentials.p12", "sign");

  private static final String AUTHN_PATH = "/authn/login";

  private static final String RESUME_PATH = "/authn/resume";

  /** The providers of the current test. */
  private static List<AbstractUserAuthenticationProvider> providers;

  /** The customization of the configurers for the current test. */
  private static Consumer<AuthnServerConfigurer> customizer;

  /** The SP metadata known by the IdP in the current test. */
  private static EntityDescriptor knownSpMetadata;

  private AnnotationConfigWebApplicationContext context;

  private MockHttpSession session;

  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .protocol(new Saml2IdpConfigurer()
              .defaultCredential(IDP_SIGN)
              .encryptCredential(IDP_ENCRYPT)
              .hokRedirectAuthnEndpoint("/hok/redirect/authn")
              .metadataResolver(resolver(knownSpMetadata)));
      providers.forEach(configurer::authenticationProvider);
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      return http.build();
    }
  }

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();
  }

  @AfterEach
  void close() {
    if (this.context != null) {
      this.context.close();
      this.context = null;
    }
  }

  // Direct authentication, the response and the assertion

  @Test
  void aDirectProviderGivesASignedResponseWithAnEncryptedAssertion() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    final RequestHttpObject<AuthnRequest> request = this.request(r -> {});

    final MockHttpServletResponse httpResponse = this.send(toHttpRequest(request));

    assertThat(responseDestination(httpResponse)).isEqualTo(ACS_URL);
    assertThat(responseRelayState(httpResponse)).isEqualTo(RELAY_STATE);
    final Response response = parseResponse(httpResponse);
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
    assertThat(response.getInResponseTo()).isEqualTo(request.getRequest().getID());
    assertThat(response.getDestination()).isEqualTo(ACS_URL);
    assertThat(response.getIssuer().getValue()).isEqualTo(BASE_URL);
    assertSignedByIdp(response.getSignature());
    assertThat(response.getAssertions()).isEmpty();
    assertThat(response.getEncryptedAssertions()).hasSize(1);

    final Assertion assertion = assertion(response);
    assertThat(assertion.isSigned()).isFalse();
    assertThat(assertion.getIssuer().getValue()).isEqualTo(BASE_URL);

    assertThat(assertion.getSubject().getNameID().getValue()).isNotBlank();
    assertThat(assertion.getSubject().getNameID().getNameQualifier()).isEqualTo(BASE_URL);
    final SubjectConfirmation confirmation = assertion.getSubject().getSubjectConfirmations().getFirst();
    assertThat(confirmation.getMethod()).isEqualTo(SubjectConfirmation.METHOD_BEARER);
    assertThat(confirmation.getSubjectConfirmationData().getRecipient()).isEqualTo(ACS_URL);
    assertThat(confirmation.getSubjectConfirmationData().getInResponseTo()).isEqualTo(request.getRequest().getID());
    assertThat(confirmation.getSubjectConfirmationData().getAddress()).isEqualTo("127.0.0.1");
    assertThat(confirmation.getSubjectConfirmationData().getNotOnOrAfter()).isAfter(Instant.now());

    assertThat(assertion.getConditions().getAudienceRestrictions().getFirst().getAudiences().getFirst().getURI())
        .isEqualTo(SP_ENTITY_ID);
    assertThat(assertion.getConditions().getNotBefore()).isBefore(Instant.now());

    final AuthnStatement statement = assertion.getAuthnStatements().getFirst();
    assertThat(statement.getAuthnContext().getAuthnContextClassRef().getURI()).isEqualTo(LOA3);
    assertThat(statement.getAuthnContext().getAuthenticatingAuthorities()).isEmpty();
    assertThat(statement.getSessionIndex()).isEqualTo(assertion.getID());

    // The requested attributes are released, the others are not
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isEqualTo(PNR);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isEqualTo("Kalle");
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_MAIL)).isNull();
  }

  @Test
  void theNameIdIsTheSameForTheSameUserAndServiceProvider() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, new TestProvider("direct", LOA3));
    final Assertion first =
        assertion(parseResponse(this.send(toHttpRequest(this.request(r -> r.setForceAuthn(true))))));
    final Assertion second =
        assertion(parseResponse(this.send(toHttpRequest(this.request(r -> r.setForceAuthn(true))))));
    assertThat(first.getSubject().getNameID().getValue()).isEqualTo(second.getSubject().getNameID().getValue());
  }

  @Test
  void theAssertionIsSignedWhenTheSpWantsItAndIsNotEncryptedWhenTurnedOff() throws Exception {
    this.start(spMetadata(sp -> sp.wantAssertionsSigned(true), LOA3_PNR),
        c -> c.protocol(Saml2IdpConfigurer.class, saml -> saml.encryptAssertions(false)),
        new TestProvider("direct", LOA3));

    final Response response = parseResponse(this.send(toHttpRequest(this.request(r -> {}))));
    assertThat(response.getEncryptedAssertions()).isEmpty();
    assertThat(response.getAssertions()).hasSize(1);
    assertSignedByIdp(response.getAssertions().getFirst().getSignature());
  }

  @Test
  void theAuthenticationProviderAttributeBecomesTheAuthenticatingAuthority() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.extraAttributes.add(GenericAttribute.of(AttributeIdentifiers.AUTHENTICATION_PROVIDER,
        "https://proxied.example.com"));
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);

    final Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthenticatingAuthorities())
        .extracting(a -> a.getURI())
        .containsExactly("https://proxied.example.com");
  }

  @Test
  void theAssertionTimesCanBeConfigured() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c.protocol(Saml2IdpConfigurer.class, saml -> saml
        .assertionNotOnOrAfter(Duration.ofMinutes(30))
        .assertionNotBefore(Duration.ofMinutes(2))), new TestProvider("direct", LOA3));

    final Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(assertion.getConditions().getNotOnOrAfter()).isAfter(Instant.now().plusSeconds(25 * 60));
    assertThat(assertion.getConditions().getNotBefore()).isBefore(Instant.now().minusSeconds(100));
  }

  // Holder-of-key

  @Test
  void aHolderOfKeyRequestGivesAHolderOfKeyConfirmationWithTheClientCertificate() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, new TestProvider("direct", LOA3));
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata,
        idpMetadata("/saml2/hok/redirect/authn", "/saml2/post/authn"), SP_CREDENTIAL,
        SamlRequestTestSupport.REDIRECT_BINDING, r -> {});
    final MockHttpServletRequest httpRequest = toHttpRequest(request);
    httpRequest.setAttribute(Saml2AuthnRequestAuthenticationConverter.CLIENT_CERTIFICATE_ATTRIBUTE,
        new X509Certificate[] { OTHER_CREDENTIAL.getCertificate() });

    final Assertion assertion = assertion(parseResponse(this.send(httpRequest)));

    // The Holder-of-key profile requires the assertion to be signed
    assertSignedByIdp(assertion.getSignature());
    final SubjectConfirmation confirmation = assertion.getSubject().getSubjectConfirmations().getFirst();
    assertThat(assertion.getSubject().getSubjectConfirmations()).hasSize(1);
    assertThat(confirmation.getMethod()).isEqualTo(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
    assertThat(confirmation.getSubjectConfirmationData()).isInstanceOf(KeyInfoConfirmationDataType.class);
    final KeyInfoConfirmationDataType data = (KeyInfoConfirmationDataType) confirmation.getSubjectConfirmationData();
    assertThat(KeyInfoSupport.getCertificates(
        (KeyInfo) data.getKeyInfos().getFirst()))
        .containsExactly(OTHER_CREDENTIAL.getCertificate());
    assertThat(data.getRecipient()).isEqualTo(ACS_URL);
    assertThat(data.getInResponseTo()).isEqualTo(request.getRequest().getID());
  }

  // The redirect flow and resume

  @Test
  void aRedirectProviderAuthenticatesOnItsOwnPagesAndTheFlowResumes() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA4);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    final RequestHttpObject<AuthnRequest> request = this.request(r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
            .authnContextClassRefs(LOA4)
            .build()));

    final MockHttpServletResponse redirect = this.send(toHttpRequest(request));
    assertThat(redirect.getRedirectedUrl()).startsWith(CONTEXT_PATH + AUTHN_PATH + "?authnId=");
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);

    // The module's controller authenticates the user ...
    final MockHttpServletRequest controllerRequest = this.appRequest("GET", AUTHN_PATH, authnId);
    final RedirectForAuthenticationToken input = provider.getAuthenticatorRepository().getInputToken(controllerRequest);
    assertThat(input).isNotNull();
    assertThat(input.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(input.getAuthnContextUris()).containsExactly(LOA4);
    provider.getAuthenticatorRepository()
        .complete(new UserAuthentication(user(LOA4, List.of())), controllerRequest);

    // ... and sends the user back to the resume path
    final MockHttpServletResponse httpResponse = this.send(this.appRequest("GET", RESUME_PATH, authnId));
    assertThat(responseDestination(httpResponse)).isEqualTo(ACS_URL);
    assertThat(responseRelayState(httpResponse)).isEqualTo(RELAY_STATE);
    final Response response = parseResponse(httpResponse);
    assertThat(response.getInResponseTo()).isEqualTo(request.getRequest().getID());
    assertSignedByIdp(response.getSignature());
    final Assertion assertion = assertion(response);
    assertThat(assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI())
        .isEqualTo(LOA4);
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isEqualTo(PNR);

    // The authentication may not be resumed twice
    assertInvalidSession(this.appRequest("GET", RESUME_PATH, authnId));
  }

  @Test
  void theAuthnPathOfARedirectProviderIsOpenAndServedByTheChain() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, new TestRedirectProvider(LOA3));
    final MockHttpServletResponse response = this.send(this.appRequest("GET", AUTHN_PATH, "x"));
    // The chain lets the request through to the (missing) controller
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void aCancelledRedirectAuthenticationGivesAnErrorResponse() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    final RequestHttpObject<AuthnRequest> request = this.request(r -> {});
    final String authnId = this.redirectedAuthnId(this.send(toHttpRequest(request)));

    provider.getAuthenticatorRepository().complete(new AuthenticationErrorException(AuthenticationError.CANCEL),
        this.appRequest("POST", "/authn/cancel", authnId));

    this.assertErrorResponse(this.send(this.appRequest("GET", RESUME_PATH, authnId)), request,
        StatusCode.RESPONDER, SamlErrorStatus.CANCEL);
  }

  @Test
  void aResumedAuthenticationThatFailsThePostProcessingGivesAnErrorResponse() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {}, provider);
    final RequestHttpObject<AuthnRequest> request =
        this.request(r -> r.setExtensions(ExtensionsBuilder.builder().extension(signMessage("Sign it")).build()));
    final String authnId = this.redirectedAuthnId(this.send(toHttpRequest(request)));

    provider.getAuthenticatorRepository().complete(new UserAuthentication(user(LOA3, List.of())),
        this.appRequest("GET", AUTHN_PATH, authnId));

    this.assertErrorResponse(this.send(this.appRequest("GET", RESUME_PATH, authnId)), request,
        StatusCode.RESPONDER, StatusCode.AUTHN_FAILED);
  }

  @Test
  void aResumeWithoutAMatchingAuthenticationInProgressIsUnrecoverable() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, new TestRedirectProvider(LOA3));
    assertInvalidSession(this.appRequest("GET", RESUME_PATH, null));
    assertInvalidSession(this.appRequest("GET", RESUME_PATH, "unknown"));
  }

  @Test
  void aResumeForAProtocolThatIsNotEnabledIsUnrecoverable() throws Exception {
    final TestRedirectProvider provider = new TestRedirectProvider(LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);

    final UserAuthenticationInputToken oidcToken = new UserAuthenticationInputToken(new AuthenticationRequirements(),
        new Requester(AuthenticationProtocol.OIDC, "client"));
    final RedirectForAuthenticationToken redirectToken =
        new RedirectForAuthenticationToken("oidc-authn", oidcToken, List.of(LOA3), AUTHN_PATH, RESUME_PATH);
    final MockHttpServletRequest request = this.appRequest("GET", AUTHN_PATH, "oidc-authn");
    provider.getFlowRepository().start(redirectToken, request);
    provider.getAuthenticatorRepository().complete(new UserAuthentication(user(LOA3, List.of())), request);

    assertInvalidSession(this.appRequest("GET", RESUME_PATH, "oidc-authn"));
  }

  // Choosing the provider

  @Test
  void theFirstProviderThatHandlesTheRequestIsUsed() throws Exception {
    final TestProvider loa3 = new TestProvider("loa3", LOA3);
    final TestProvider loa3and4 = new TestProvider("loa3and4", LOA3, LOA4);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, loa3, loa3and4);

    this.send(toHttpRequest(this.request(r -> r.setForceAuthn(true))));
    assertThat(loa3.calls).isOne();
    assertThat(loa3and4.calls).isZero();

    final Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {
      r.setForceAuthn(true);
      r.setRequestedAuthnContext(RequestedAuthnContextBuilder.builder()
          .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(LOA4).build());
    })))));
    assertThat(loa3.calls).isOne();
    assertThat(loa3and4.calls).isOne();
    assertThat(assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI())
        .isEqualTo(LOA4);
  }

  @Test
  void whenNoProviderHandlesTheRequestTheSpGetsNoAuthnContext() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, new TestProvider("loa3", LOA3));
    final RequestHttpObject<AuthnRequest> request = this.request(r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(LOA2).build()));
    this.assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.NO_AUTHN_CONTEXT);
  }

  @Test
  void anErrorFromAProviderIsAnsweredToTheSp() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.error = new AuthenticationErrorException(AuthenticationError.FRAUD, "Fraud detected");
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    final RequestHttpObject<AuthnRequest> request = this.request(r -> {});
    this.assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.RESPONDER, SamlErrorStatus.FRAUD);
    assertThat(this.session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
  }

  // Single sign-on

  @Test
  void singleSignOnReusesTheAuthenticationInTheSession() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);

    final Assertion first = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    final Assertion second = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(provider.calls).isOne();
    assertThat(second.getAuthnStatements().getFirst().getAuthnInstant())
        .isEqualTo(first.getAuthnStatements().getFirst().getAuthnInstant());

    // Another session means another authentication
    this.session = new MockHttpSession();
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(2);
  }

  @Test
  void theSessionAuthenticationIsNotReusedWhenTheRequesterForcesAuthentication() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    this.send(toHttpRequest(this.request(r -> {})));
    this.send(toHttpRequest(this.request(r -> r.setForceAuthn(true))));
    assertThat(provider.calls).isEqualTo(2);
  }

  @Test
  void theSessionIsKeptWhileARedirectAuthenticationIsInProgress() throws Exception {
    final TestProvider direct = new TestProvider("direct", LOA3);
    final TestRedirectProvider redirect = new TestRedirectProvider(LOA4);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, direct, redirect);
    this.send(toHttpRequest(this.request(r -> {})));

    this.redirectedAuthnId(this.send(toHttpRequest(this.request(r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(LOA4).build())))));

    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(direct.calls).isOne();
  }

  @Test
  void anErrorFromTheProviderRemovesTheSessionAuthentication() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    this.send(toHttpRequest(this.request(r -> {})));

    for (final AuthenticationError error : List.of(AuthenticationError.FRAUD, AuthenticationError.POSSIBLE_FRAUD,
        AuthenticationError.AUTHN_FAILED)) {
      this.send(toHttpRequest(this.request(r -> {})));
      final int calls = provider.calls;
      provider.error = new AuthenticationErrorException(error);
      final RequestHttpObject<AuthnRequest> failing = this.request(r -> r.setForceAuthn(true));
      this.assertErrorResponse(this.send(toHttpRequest(failing)), failing, StatusCode.RESPONDER,
          SamlErrorStatus.of(error).subStatusCode());
      assertThat(this.session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();

      provider.error = null;
      this.send(toHttpRequest(this.request(r -> {})));
      assertThat(provider.calls).as("not reused after " + error).isEqualTo(calls + 2);
    }
  }

  @Test
  void aCancelledRedirectAuthenticationRemovesTheSessionAuthentication() throws Exception {
    final TestProvider direct = new TestProvider("direct", LOA3);
    final TestRedirectProvider redirect = new TestRedirectProvider(LOA4);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, direct, redirect);
    this.send(toHttpRequest(this.request(r -> {})));

    final String authnId = this.redirectedAuthnId(this.send(toHttpRequest(this.request(r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(LOA4).build())))));
    // A redirect keeps the session authentication ...
    assertThat(this.session.getAttribute("SPRING_SECURITY_CONTEXT")).isNotNull();

    redirect.getAuthenticatorRepository().complete(new AuthenticationErrorException(AuthenticationError.CANCEL),
        this.appRequest("POST", "/authn/cancel", authnId));
    this.send(this.appRequest("GET", RESUME_PATH, authnId));

    // ... but the cancel removes it
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(direct.calls).isEqualTo(2);
  }

  @Test
  void aFailureWhileCompletingTheResultRemovesTheSessionAuthentication() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    final boolean[] failRelease = { false };
    this.start(spMetadata(sp -> {}, LOA3_PNR, SIGSERVICE), c -> c.protocol(Saml2IdpConfigurer.class,
        saml -> saml.attributeProducers(l -> l.addFirst(a -> {
          if (failRelease[0]) {
            throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Release failed");
          }
          return List.of();
        }))), provider);
    this.send(toHttpRequest(this.request(r -> {})));

    // Sign message not displayed, raised by the post-authentication processing ...
    final RequestHttpObject<AuthnRequest> withSignMessage =
        this.request(r -> r.setExtensions(ExtensionsBuilder.builder().extension(signMessage("Sign it")).build()));
    this.assertErrorResponse(this.send(toHttpRequest(withSignMessage)), withSignMessage, StatusCode.RESPONDER,
        StatusCode.AUTHN_FAILED);
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(3);

    // ... and an error from the release, after single sign-on
    failRelease[0] = true;
    final RequestHttpObject<AuthnRequest> failing = this.request(r -> {});
    this.assertErrorResponse(this.send(toHttpRequest(failing)), failing, StatusCode.RESPONDER,
        StatusCode.AUTHN_FAILED);
    assertThat(provider.calls).isEqualTo(3);
    failRelease[0] = false;
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(4);
  }

  @Test
  void aFailureBeforeTheAuthenticationStartedKeepsTheSessionAuthentication() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    this.send(toHttpRequest(this.request(r -> {})));

    // An invalid request
    final RequestHttpObject<AuthnRequest> invalid = this.request(r -> {
      r.setForceAuthn(true);
      r.setIsPassive(true);
    });
    this.assertErrorResponse(this.send(toHttpRequest(invalid)), invalid, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);

    // No provider for the requested authentication context
    final RequestHttpObject<AuthnRequest> noProvider = this.request(r -> r.setRequestedAuthnContext(
        RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(LOA2).build()));
    this.assertErrorResponse(this.send(toHttpRequest(noProvider)), noProvider, StatusCode.REQUESTER,
        StatusCode.NO_AUTHN_CONTEXT);

    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isOne();
  }

  @Test
  void theSamlPolicyWinsOverTheSharedPolicy() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c
        .ssoPolicy(SsoPolicy.defaultPolicy())
        .protocol(Saml2IdpConfigurer.class, saml -> saml.ssoPolicy(SsoPolicy.none())), provider);
    this.send(toHttpRequest(this.request(r -> {})));
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(2);
  }

  @Test
  void theSharedPolicyAppliesWhenTheSamlPolicyIsNotSet() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c.ssoPolicy(SsoPolicy.none()), provider);
    this.send(toHttpRequest(this.request(r -> {})));
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(2);
  }

  @Test
  void theProviderPolicyWinsOverTheSamlAndSharedPolicies() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.setSsoPolicy(SsoPolicy.defaultPolicy());
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c
        .ssoPolicy(SsoPolicy.none())
        .protocol(Saml2IdpConfigurer.class, saml -> saml.ssoPolicy(SsoPolicy.none())), provider);
    this.send(toHttpRequest(this.request(r -> {})));
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isOne();
  }

  @Test
  void aVoterInTheSamlOrSharedListCanRefuseSingleSignOn() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c.ssoVoters(v -> v.add((p, r, q, a) ->
        SsoDecision.deny(SsoDenialReason.NOT_ALLOWED))), provider);
    this.send(toHttpRequest(this.request(r -> {})));
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isEqualTo(2);
  }

  @Test
  void theReleaseAfterSingleSignOnFollowsTheNewRequest() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    // Let a request with another set of attributes reuse the authentication
    provider.getSsoVoters().removeIf(RequestedAttributesSsoVoter.class::isInstance);
    provider.extraAttributes.add(GenericAttribute.of(AttributeIdentifiers.EMAIL, "kalle@example.com"));
    this.start(spMetadata(sp -> {}), c -> {}, provider);

    final Assertion first = assertion(parseResponse(this.send(toHttpRequest(
        this.request(r -> r.setExtensions(requestedAttributes(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)))))));
    assertThat(attribute(first, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isEqualTo("Kalle");
    assertThat(attribute(first, AttributeConstants.ATTRIBUTE_NAME_MAIL)).isNull();

    final Assertion second = assertion(parseResponse(this.send(toHttpRequest(
        this.request(r -> r.setExtensions(requestedAttributes(AttributeConstants.ATTRIBUTE_NAME_MAIL)))))));
    assertThat(provider.calls).isOne();
    assertThat(attribute(second, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isNull();
    assertThat(attribute(second, AttributeConstants.ATTRIBUTE_NAME_MAIL)).isEqualTo("kalle@example.com");
  }

  // Producers, voters and processors

  @Test
  void theDefaultsAreTheSwedenConnectOnesInTheSamlListsAndTheNeutralOnesInTheSharedLists() {
    final AuthnServerConfigurer server = new AuthnServerConfigurer();
    final Saml2IdpConfigurer saml = new Saml2IdpConfigurer();
    assertThat(saml.getAttributeProducers()).singleElement().isInstanceOf(SwedenConnectAttributeProducer.class);
    assertThat(saml.getAttributeReleaseVoters()).singleElement().isInstanceOf(SwedenConnectAttributeReleaseVoter.class);
    assertThat(saml.getSsoVoters()).isEmpty();
    assertThat(saml.getPostAuthenticationProcessors()).isEmpty();
    assertThat(server.getAttributeProducers()).singleElement().isInstanceOf(DefaultAttributeProducer.class);
    assertThat(server.getAttributeReleaseVoters()).singleElement().isInstanceOf(IncludeAllAttributeReleaseVoter.class);
    assertThat(server.getSsoVoters()).isEmpty();
    assertThat(server.getPostAuthenticationProcessors()).singleElement()
        .isInstanceOf(SwedenConnectPostAuthenticationProcessor.class);
  }

  @Test
  void samlEntriesRunBeforeSharedEntries() throws Exception {
    final List<String> calls = new CopyOnWriteArrayList<>();
    final TestProvider provider = new TestProvider("direct", LOA3);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c
        .attributeProducers(l -> l.add(a -> record(calls, "shared-producer")))
        .attributeReleaseVoters(l -> l.addFirst((a, attr) -> recordVote(calls, "shared-voter")))
        .ssoVoters(l -> l.add((p, r, q, a) -> {
          calls.add("shared-sso");
          return SsoDecision.abstain();
        }))
        .postAuthenticationProcessors(l -> l.add(a -> calls.add("shared-processor")))
        .protocol(Saml2IdpConfigurer.class, saml -> saml
            .attributeProducers(l -> l.add(a -> record(calls, "saml-producer")))
            .attributeReleaseVoters(l -> l.add((a, attr) -> recordVote(calls, "saml-voter")))
            .ssoVoters(l -> l.add((p, r, q, a) -> {
              calls.add("saml-sso");
              return SsoDecision.abstain();
            }))
            .postAuthenticationProcessors(l -> l.add(a -> calls.add("saml-processor")))), provider);

    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(calls.stream().filter(s -> s.endsWith("processor")).toList())
        .containsExactly("saml-processor", "shared-processor");
    assertThat(calls.stream().filter(s -> s.endsWith("producer")).toList())
        .containsExactly("saml-producer", "shared-producer");
    assertThat(calls.stream().filter(s -> s.endsWith("voter")).distinct().toList())
        .containsExactly("saml-voter", "shared-voter");

    calls.clear();
    this.send(toHttpRequest(this.request(r -> {})));
    assertThat(provider.calls).isOne();
    assertThat(calls.stream().filter(s -> s.endsWith("sso")).toList()).containsExactly("saml-sso", "shared-sso");
  }

  @Test
  void theFirstProducerToReleaseAnAttributeWins() throws Exception {
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c
        .attributeProducers(l -> l.add(a -> List.of(GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Shared"))))
        .protocol(Saml2IdpConfigurer.class, saml -> saml.attributeProducers(l -> l.addFirst(
            a -> List.of(GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Saml"))))),
        new TestProvider("direct", LOA3));
    final Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isEqualTo("Saml");
  }

  @Test
  void withTheDefaultsACoordinationNumberIsOnlyReleasedToAnSpThatAcceptsIt() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.identityAttribute = GenericAttribute.of(AttributeIdentifiers.COORDINATION_NUMBER, COORDINATION_NUMBER);
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> {}, provider);
    Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isNull();
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isEqualTo("Kalle");
    this.close();

    this.session = new MockHttpSession();
    this.start(spMetadata(sp -> {}, LOA3_PNR, ACCEPTS_COORDINATION_NUMBER), c -> {}, provider);
    assertion = assertion(parseResponse(this.send(toHttpRequest(this.request(r -> {})))));
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .isEqualTo(COORDINATION_NUMBER);
  }

  @Test
  void withTheDefaultsADisplayedSignMessageGivesTheSignMessageDigest() throws Exception {
    final TestProvider provider = new TestProvider("direct", LOA3);
    provider.displaySignMessage = true;
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {}, provider);
    final Assertion assertion = assertion(parseResponse(this.send(toHttpRequest(
        this.request(r -> r.setExtensions(ExtensionsBuilder.builder().extension(signMessage("Sign it")).build()))))));
    assertThat(attribute(assertion, AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST)).isNotBlank();
    // A result where a sign message was displayed is never kept for single sign-on
    assertThat(this.session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
  }

  @Test
  void withTheDefaultsASignMessageThatWasNotDisplayedGivesAnErrorResponse() throws Exception {
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {}, new TestProvider("direct", LOA3));
    final RequestHttpObject<AuthnRequest> request =
        this.request(r -> r.setExtensions(ExtensionsBuilder.builder().extension(signMessage("Sign it")).build()));
    this.assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.RESPONDER,
        StatusCode.AUTHN_FAILED);
  }

  // Support

  private void start(final EntityDescriptor spMetadata, final Consumer<AuthnServerConfigurer> c,
      final AbstractUserAuthenticationProvider... testProviders) {
    knownSpMetadata = spMetadata;
    customizer = c;
    providers = List.of(testProviders);
    this.context = new AnnotationConfigWebApplicationContext();
    this.context.setServletContext(new MockServletContext());
    this.context.register(TestConfiguration.class);
    this.context.refresh();
  }

  private RequestHttpObject<AuthnRequest> request(final Consumer<AuthnRequest> requestCustomizer) throws Exception {
    return generate(knownSpMetadata, idpMetadata("/saml2/redirect/authn", "/saml2/post/authn"), SP_CREDENTIAL,
        POST_BINDING, requestCustomizer);
  }

  private MockHttpServletResponse send(final MockHttpServletRequest request) throws Exception {
    request.setSession(this.session);
    final Filter filter = this.context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private MockHttpServletRequest appRequest(final String method, final String path, final @Nullable String authnId) {
    final MockHttpServletRequest request = new MockHttpServletRequest(method, CONTEXT_PATH + path);
    request.setScheme("https");
    request.setSecure(true);
    request.setServerName("idp.example.com");
    request.setServerPort(443);
    request.setContextPath(CONTEXT_PATH);
    request.setServletPath(path);
    if (authnId != null) {
      request.addParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, authnId);
    }
    request.setSession(this.session);
    return request;
  }

  private String redirectedAuthnId(final MockHttpServletResponse response) {
    assertThat(response.getRedirectedUrl()).startsWith(CONTEXT_PATH + AUTHN_PATH);
    return response.getRedirectedUrl().substring(response.getRedirectedUrl().indexOf('=') + 1);
  }

  private void assertInvalidSession(final MockHttpServletRequest request) {
    assertThatThrownBy(() -> this.send(request))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(CommonUnrecoverableError.INVALID_SESSION));
  }

  private void assertErrorResponse(final MockHttpServletResponse httpResponse,
      final RequestHttpObject<AuthnRequest> request, final String statusCode, final String subStatusCode)
      throws Exception {
    assertThat(responseDestination(httpResponse)).isEqualTo(ACS_URL);
    final Response response = parseResponse(httpResponse);
    assertThat(response.getInResponseTo()).isEqualTo(request.getRequest().getID());
    assertSignedByIdp(response.getSignature());
    assertThat(response.getAssertions()).isEmpty();
    assertThat(response.getEncryptedAssertions()).isEmpty();
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(statusCode);
    assertThat(response.getStatus().getStatusCode().getStatusCode().getValue()).isEqualTo(subStatusCode);
  }

  private static void assertSignedByIdp(final Signature signature) throws Exception {
    assertThat(signature).isNotNull();
    SignatureValidator.validate(signature, new BasicX509Credential(IDP_SIGN.getCertificate()));
  }

  private static Assertion assertion(final Response response) throws Exception {
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
    if (!response.getAssertions().isEmpty()) {
      return response.getAssertions().getFirst();
    }
    final SAMLObjectDecrypter decrypter =
        new SAMLObjectDecrypter(List.<Credential>of(new OpenSamlCredential(SP_CREDENTIAL)));
    return decrypter.decrypt(response.getEncryptedAssertions().getFirst().getEncryptedData(), Assertion.class);
  }

  private static @Nullable String attribute(final Assertion assertion, final String name) {
    return assertion.getAttributeStatements().getFirst().getAttributes().stream()
        .filter(a -> name.equals(a.getName()))
        .map(AttributeUtils::getAttributeStringValue)
        .findFirst()
        .orElse(null);
  }

  private static org.opensaml.saml.saml2.core.Extensions requestedAttributes(final String... names) {
    final RequestedAttributes extension =
        (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    for (final String name : names) {
      extension.getRequestedAttributes().add(RequestedAttributeBuilder.builder(name).isRequired(true).build());
    }
    return ExtensionsBuilder.builder().extension(extension).build();
  }

  private static SignMessage signMessage(final String text) {
    final SignMessage signMessage = (SignMessage) XMLObjectSupport.buildXMLObject(SignMessage.DEFAULT_ELEMENT_NAME);
    signMessage.setDisplayEntity(BASE_URL);
    signMessage.setMustShow(true);
    final Message message = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
    message.setValue(Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)));
    signMessage.setMessage(message);
    return signMessage;
  }

  private static List<GenericAttribute<? extends Serializable>> record(final List<String> calls, final String name) {
    calls.add(name);
    return List.of();
  }

  private static AttributeReleaseVote recordVote(final List<String> calls, final String name) {
    calls.add(name);
    return AttributeReleaseVote.DONT_KNOW;
  }

  private static AuthenticatedUser user(final String authnContext, final List<GenericAttribute<?>> extra) {
    return user(authnContext, GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, PNR), extra);
  }

  private static AuthenticatedUser user(final String authnContext, final GenericAttribute<?> identity,
      final List<GenericAttribute<?>> extra) {
    final List<GenericAttribute<?>> attributes = new ArrayList<>();
    attributes.add(identity);
    attributes.add(GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Kalle"));
    attributes.add(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Kula"));
    attributes.add(GenericAttribute.of(AttributeIdentifiers.DISPLAY_NAME, "Kalle Kula"));
    attributes.addAll(extra);
    return new AuthenticatedUser(attributes, identity.getIdentifier(), authnContext, Instant.now(), "127.0.0.1");
  }

  private static MetadataResolver resolver(final EntityDescriptor spMetadata) {
    try {
      final EntitiesDescriptor entities =
          (EntitiesDescriptor) XMLObjectSupport.buildXMLObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
      entities.getEntityDescriptors().add(XMLObjectSupport.cloneXMLObject(spMetadata));
      final StaticMetadataProvider provider = new StaticMetadataProvider(entities);
      provider.initialize();
      return provider.getMetadataResolver();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** A provider that authenticates the user directly. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    private final String name;

    private final List<String> authnContexts;

    final List<GenericAttribute<?>> extraAttributes = new ArrayList<>();

    GenericAttribute<?> identityAttribute = GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, PNR);

    boolean displaySignMessage = false;

    AuthenticationErrorException error;

    int calls = 0;

    TestProvider(final String name, final String... authnContexts) {
      this.name = name;
      this.authnContexts = List.of(authnContexts);
    }

    @Override
    protected @Nonnull Authentication authenticate(final @Nonnull UserAuthenticationInputToken token,
        final @Nonnull List<String> authnContextUris) {
      this.calls++;
      if (this.error != null) {
        throw this.error;
      }
      final AuthenticatedUser user = user(authnContextUris.getFirst(), this.identityAttribute, this.extraAttributes);
      if (this.displaySignMessage) {
        user.setSignMessageDisplayed(true, null);
      }
      return new UserAuthentication(user);
    }

    @Override
    public @Nonnull String getName() {
      return this.name;
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return this.authnContexts;
    }

    @Override
    public @Nonnull List<String> getEntityCategories() {
      return List.of(LOA3_PNR);
    }
  }

  /** A provider that authenticates the user on pages of its own. */
  static class TestRedirectProvider extends AbstractUserRedirectAuthenticationProvider {

    private final List<String> authnContexts;

    TestRedirectProvider(final String... authnContexts) {
      super(AUTHN_PATH, RESUME_PATH);
      this.authnContexts = List.of(authnContexts);
    }

    @Override
    public boolean supportsUserAuthenticationToken(final @Nullable Authentication authentication) {
      return authentication instanceof UserAuthentication;
    }

    @Override
    protected @Nonnull UserAuthentication createUserAuthentication(final @Nonnull ResumedAuthenticationToken token) {
      return (UserAuthentication) token.getAuthnToken();
    }

    @Override
    public @Nonnull String getName() {
      return "redirect";
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return this.authnContexts;
    }

    @Override
    public @Nonnull List<String> getEntityCategories() {
      return List.of(LOA3_PNR);
    }
  }

}
