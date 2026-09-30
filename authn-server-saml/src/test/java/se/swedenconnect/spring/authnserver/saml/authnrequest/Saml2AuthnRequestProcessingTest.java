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
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.OTHER_CREDENTIAL;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.POST_BINDING;
import static se.swedenconnect.spring.authnserver.saml.authnrequest.SamlRequestTestSupport.REDIRECT_BINDING;
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
import jakarta.servlet.Filter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.Message;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADVersion;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.OriginalRequester;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequiredMarksRequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.WhitelistRequesterPredicate;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;

/**
 * Tests for the processing of SAML authentication requests, through the filter chain built by the configurers.
 *
 * @author Martin Lindström
 */
class Saml2AuthnRequestProcessingTest extends OpenSamlTestBase {

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private static final String PNR_OID = "urn:oid:1.2.752.29.4.13";

  private static final String SIGSERVICE = EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri();

  private static final String LOA3_PNR = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri();

  /** The customization of the configurers for the current test. */
  private static Consumer<AuthnServerConfigurer> customizer;

  /** The SP metadata known by the IdP in the current test. */
  private static EntityDescriptor knownSpMetadata;

  /** The result of the processing. */
  private static final AtomicReference<UserAuthenticationInputToken> RESULT = new AtomicReference<>();

  private AnnotationConfigWebApplicationContext context;

  /** The configuration of the server. */
  @Configuration
  @EnableWebSecurity
  static class TestConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .protocol(new Saml2IdpConfigurer()
              .defaultCredential(SamlRequestTestSupport.load("idp-credentials.p12", "sign"))
              .encryptCredential(SamlRequestTestSupport.IDP_ENCRYPT)
              .hokRedirectAuthnEndpoint("/hok/redirect/authn")
              .metadataResolver(resolver(knownSpMetadata))
              .authnRequestProcessor(c -> c.successHandler(
                  (request, response, authentication) -> RESULT.set((UserAuthenticationInputToken) authentication))));
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      customizer.accept(configurer);
      return http.build();
    }
  }

  @AfterEach
  void close() {
    if (this.context != null) {
      this.context.close();
      this.context = null;
    }
    RESULT.set(null);
  }

  @Test
  void aSignedRedirectRequestGivesTheAuthenticationRequirements() throws Exception {
    // The IdP must declare the entity category for it to give requested attributes
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c.authenticationProvider(new UserAuthenticationProvider() {

      @Override
      public @Nonnull String getName() {
        return "test";
      }

      @Override
      public @Nonnull List<String> getSupportedAuthnContextUris() {
        return List.of(LOA3, LOA4);
      }

      @Override
      public @Nonnull List<String> getEntityCategories() {
        return List.of(LOA3_PNR);
      }

      @Override
      public Authentication authenticateUser(final @Nonnull UserAuthenticationInputToken token) {
        return null;
      }
    }));
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, REDIRECT_BINDING,
        r -> {
          r.setRequestedAuthnContext(RequestedAuthnContextBuilder.builder()
              .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
              .authnContextClassRefs(LOA3, LOA4)
              .build());
          r.setForceAuthn(true);
        });

    final UserAuthenticationInputToken token = this.process(request);

    assertThat(token.getRequester().protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(token.getRequester().identifier()).isEqualTo(SP_ENTITY_ID);
    assertThat(token.getRequestId()).isEqualTo(request.getRequest().getID());

    final SamlAuthenticationRequirements requirements =
        (SamlAuthenticationRequirements) token.getAuthnRequirements();
    assertThat(requirements.isForceAuthn()).isTrue();
    assertThat(requirements.isPassiveAuthn()).isFalse();
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA3, LOA4);
    assertThat(requirements.getEntityCategories()).containsExactly(LOA3_PNR);
    assertThat(requirements.getRequestedAttributes())
        .extracting(GenericRequestedAttribute::getIdentifier)
        .contains(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
    assertThat(requirements.getSignMessage()).isNull();
    assertThat(requirements.getUserMessage()).isNull();

    final Saml2AuthnRequestData data = (Saml2AuthnRequestData) token.getProtocolRequestData();
    assertThat(data).isNotNull();
    assertThat(data.holderOfKey()).isFalse();
    assertThat(data.responseAttributes().destination()).isEqualTo(ACS_URL);
    assertThat(data.responseAttributes().relayState()).isEqualTo(RELAY_STATE);
    assertThat(data.responseAttributes().inResponseTo()).isEqualTo(request.getRequest().getID());
    assertThat(data.nameIdGenerator()).isNotNull();
  }

  @Test
  void aSignedPostRequestIsProcessed() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setIsPassive(true));

    final UserAuthenticationInputToken token = this.process(request);
    assertThat(token.getAuthnRequirements().isPassiveAuthn()).isTrue();
    assertThat(token.getAuthnRequirements().getAuthnContextRequirements()).isEmpty();
  }

  @Test
  void aRequestOnTheHolderOfKeyEndpointIsMarkedAsHolderOfKey() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata,
        idpMetadata("/saml2/hok/redirect/authn", "/saml2/post/authn"), SP_CREDENTIAL, REDIRECT_BINDING, r -> {});

    final UserAuthenticationInputToken token = this.process(request);
    assertThat(((Saml2AuthnRequestData) token.getProtocolRequestData()).holderOfKey()).isTrue();
  }

  @Test
  void theRequestedAttributesComeFromTheRequestAndTheMetadata() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setExtensions(se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder.builder()
            .extension(PrincipalSelectionBuilder.builder()
                .matchValues(MatchValueBuilder.builder().name(PNR_OID).value("197705232382").build())
                .build())
            .build()));

    final UserAuthenticationInputToken token = this.process(request);
    final GenericRequestedAttribute pnr = token.getAuthnRequirements().getRequestedAttributes().stream()
        .filter(a -> AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER.equals(a.getIdentifier()))
        .findFirst()
        .orElseThrow();
    assertThat(pnr.getRequestedValues()).asList().containsExactly("197705232382");
  }

  @Test
  void theScopingGivesProvidersAndOriginalRequesters() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> {
          final Scoping scoping = (Scoping) XMLObjectSupport.buildXMLObject(Scoping.DEFAULT_ELEMENT_NAME);
          final IDPList idpList = (IDPList) XMLObjectSupport.buildXMLObject(IDPList.DEFAULT_ELEMENT_NAME);
          final IDPEntry entry = (IDPEntry) XMLObjectSupport.buildXMLObject(IDPEntry.DEFAULT_ELEMENT_NAME);
          entry.setProviderID("https://provider.example.com");
          idpList.getIDPEntrys().add(entry);
          scoping.setIDPList(idpList);
          final RequesterID requesterId =
              (RequesterID) XMLObjectSupport.buildXMLObject(RequesterID.DEFAULT_ELEMENT_NAME);
          requesterId.setURI("https://original.example.com");
          scoping.getRequesterIDs().add(requesterId);
          r.setScoping(scoping);
        });

    final UserAuthenticationInputToken token = this.process(request);
    assertThat(token.getAuthnRequirements().getRequestedAuthnProviders())
        .containsExactly("https://provider.example.com");
    assertThat(token.getAuthnRequirements().getOriginalRequesters())
        .containsExactly(OriginalRequester.of("https://original.example.com"));
  }

  // Signature

  @Test
  void anUnsignedRequestIsRejectedWhenSignedRequestsAreRequired() throws Exception {
    this.start(spMetadata(sp -> sp.authnRequestsSigned(false)), c -> {});
    assertUnrecoverable(generate(knownSpMetadata, idp(), null, REDIRECT_BINDING, r -> {}),
        SamlUnrecoverableError.MISSING_AUTHNREQUEST_SIGNATURE);
  }

  @Test
  void anUnsignedRequestIsRejectedWhenTheSpMetadataStatesThatRequestsAreSigned() throws Exception {
    this.start(spMetadata(sp -> {}), c -> saml(c).requiresSignedRequests(false));
    assertUnrecoverable(generate(knownSpMetadata, idp(), null, POST_BINDING, r -> {}),
        SamlUnrecoverableError.MISSING_AUTHNREQUEST_SIGNATURE);
  }

  @Test
  void anUnsignedRequestIsAcceptedWhenNoSignatureIsRequired() throws Exception {
    this.start(spMetadata(sp -> sp.authnRequestsSigned(false)), c -> saml(c).requiresSignedRequests(false));
    assertThat(this.process(generate(knownSpMetadata, idp(), null, REDIRECT_BINDING, r -> {}))).isNotNull();
  }

  @Test
  void aRequestSignedWithAnotherKeyIsRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    assertUnrecoverable(generate(knownSpMetadata, idp(), OTHER_CREDENTIAL, REDIRECT_BINDING, r -> {}),
        SamlUnrecoverableError.INVALID_AUTHNREQUEST_SIGNATURE);
    assertUnrecoverable(generate(knownSpMetadata, idp(), OTHER_CREDENTIAL, POST_BINDING, r -> {}),
        SamlUnrecoverableError.INVALID_AUTHNREQUEST_SIGNATURE);
  }

  // Finding the SP

  @Test
  void anUnknownSpIsUnrecoverable() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final EntityDescriptor other = spMetadata(sp -> {});
    other.setEntityID("https://unknown.example.com");
    assertUnrecoverable(generate(other, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.getIssuer().setValue("https://unknown.example.com")), SamlUnrecoverableError.UNKNOWN_PEER);
  }

  @Test
  void aRegistryFailureIsToldApartFromAnUnknownSp() throws Exception {
    this.start(spMetadata(sp -> {}), c -> c.clientRegistryBackend(new ClientRegistryBackend() {

      @Override
      public @Nonnull String getName() {
        return "failing";
      }

      @Override
      public @Nonnull AuthenticationProtocol getProtocol() {
        return AuthenticationProtocol.SAML;
      }

      @Override
      public RequesterRecord lookup(final @Nonnull String identifier) throws ClientRegistryException {
        throw new ClientRegistryException("The backend is down");
      }
    }));
    assertUnrecoverable(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}),
        SamlUnrecoverableError.PEER_LOOKUP_FAILED);
  }

  // Message checks

  @Test
  void aReplayedRequestIsRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request =
        generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {});
    assertThat(this.process(request)).isNotNull();
    assertUnrecoverable(request, SamlUnrecoverableError.REPLAY_DETECTED);
  }

  @Test
  void aRequestThatIsTooOldIsRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    assertUnrecoverable(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setIssueInstant(Instant.now().minusSeconds(600))), SamlUnrecoverableError.MESSAGE_TOO_OLD);
  }

  @Test
  void aRequestForAnotherDestinationIsRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    assertUnrecoverable(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setDestination(BASE_URL + "/other")), SamlUnrecoverableError.ENDPOINT_CHECK_FAILURE);
  }

  @Test
  void aMessageThatCannotBeDecodedIsRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/saml2/post/authn");
    request.setContextPath("/auth");
    request.setServletPath("/saml2/post/authn");
    request.addParameter("SAMLRequest", "bm90IGEgU0FNTCBtZXNzYWdl");
    assertThatThrownBy(() -> this.send(request))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(SamlUnrecoverableError.FAILED_DECODE));
  }

  // Assertion consumer service

  @Test
  void anAssertionConsumerServiceThatIsNotInTheMetadataIsUnrecoverable() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    assertUnrecoverable(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setAssertionConsumerServiceURL("https://evil.example.com/acs")),
        SamlUnrecoverableError.INVALID_ASSERTION_CONSUMER_SERVICE);
    assertUnrecoverable(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setAssertionConsumerServiceIndex(1)),
        SamlUnrecoverableError.INVALID_ASSERTION_CONSUMER_SERVICE);
  }

  @Test
  void theAssertionConsumerServiceIsFoundByIndexOrByDefault() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> {
          r.setAssertionConsumerServiceURL(null);
          r.setProtocolBinding(null);
          r.setAssertionConsumerServiceIndex(1);
        }));
    assertThat(((Saml2AuthnRequestData) token.getProtocolRequestData()).responseAttributes().destination())
        .isEqualTo(ACS_URL + "2");

    token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {
      r.setAssertionConsumerServiceURL(null);
      r.setProtocolBinding(null);
    }));
    assertThat(((Saml2AuthnRequestData) token.getProtocolRequestData()).responseAttributes().destination())
        .isEqualTo(ACS_URL);
  }

  // Errors reported to the SP

  @Test
  void forceAuthnTogetherWithIsPassiveIsAnErrorResponse() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> {
          r.setForceAuthn(true);
          r.setIsPassive(true);
        });
    final MockHttpServletResponse response = this.send(toHttpRequest(request));
    assertErrorResponse(response, request, StatusCode.REQUESTER, StatusCode.REQUEST_UNSUPPORTED);
    assertThat(responseRelayState(response)).isEqualTo(RELAY_STATE);
  }

  @Test
  void anSpWithoutEncryptionKeyGetsAnErrorResponseWhenAssertionsAreEncrypted() throws Exception {
    this.start(spMetadata(sp -> sp.keyDescriptors(se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder
        .builder().use(org.opensaml.security.credential.UsageType.SIGNING)
        .certificate(SP_CREDENTIAL.getCertificate()).build())), c -> {});
    final RequestHttpObject<AuthnRequest> request =
        generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {});
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER, StatusCode.REQUEST_DENIED);
  }

  @Test
  void anSpWithoutEncryptionKeyIsAcceptedWhenAssertionsAreNotEncrypted() throws Exception {
    this.start(spMetadata(sp -> sp.keyDescriptors(se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder
        .builder().use(org.opensaml.security.credential.UsageType.SIGNING)
        .certificate(SP_CREDENTIAL.getCertificate()).build())), c -> saml(c).encryptAssertions(false));
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
  }

  @Test
  void anUnsupportedNameIdFormatIsAnErrorResponse() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> {
          final NameIDPolicy policy = (NameIDPolicy) XMLObjectSupport.buildXMLObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
          policy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
          r.setNameIDPolicy(policy);
        });
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.INVALID_NAMEID_POLICY);
  }

  @Test
  void aComparisonWithoutMappingIsAnErrorResponseAndAMappingResolvesIt() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final Consumer<AuthnRequest> minimum = r -> r.setRequestedAuthnContext(RequestedAuthnContextBuilder.builder()
        .comparison(AuthnContextComparisonTypeEnumeration.MINIMUM)
        .authnContextClassRefs(LOA3)
        .build());
    final RequestHttpObject<AuthnRequest> request =
        generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, minimum);
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);
    this.close();

    this.start(knownSpMetadata, c -> saml(c).authnContextMappings(Map.of(LOA3, List.of(LOA3, LOA4)), null, null));
    final UserAuthenticationInputToken token =
        this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, minimum));
    assertThat(token.getAuthnRequirements().getAuthnContextRequirements()).containsExactly(LOA3, LOA4);
  }

  // Extensions

  @Test
  void aSignMessageFromASignatureServiceIsExtracted() throws Exception {
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {});
    final UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(signMessage("Sign this")))));
    assertThat(token.getAuthnRequirements().getSignMessage()).isNotNull();
    assertThat(token.getAuthnRequirements().getSignMessage().getDefaultMessage().getText()).isEqualTo("Sign this");
    assertThat(token.getAuthnRequirements().getSignMessage().isMustShow()).isTrue();
  }

  @Test
  void aSignMessageFromAnotherSpIsIgnored() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(signMessage("Sign this")))));
    assertThat(token.getAuthnRequirements().getSignMessage()).isNull();
  }

  @Test
  void aSignMessageWithoutDataIsAnErrorResponse() throws Exception {
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {});
    final SignMessage signMessage = signMessage("x");
    signMessage.setMessage(null);
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setExtensions(extensions(signMessage)));
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);
  }

  @Test
  void aUserMessageIsExtracted() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(userMessage("text/markdown", "Hej")))));
    assertThat(token.getAuthnRequirements().getUserMessage()).isNotNull();
    assertThat(token.getAuthnRequirements().getUserMessage().getMimeType()).isEqualTo(MessageMimeType.TEXT_MARKDOWN);
    assertThat(token.getAuthnRequirements().getUserMessage().getMessage("sv").getText()).isEqualTo("Hej");
  }

  @Test
  void aUserMessageWithUnsupportedMimeTypeIsIgnoredOrRejected() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(userMessage("text/rtf", "Hej")))));
    assertThat(token.getAuthnRequirements().getUserMessage()).isNull();
    this.close();

    this.start(knownSpMetadata, c -> saml(c).supportsUserMessage(true));
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setExtensions(extensions(userMessage("text/rtf", "Hej"))));
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);
  }

  @Test
  void theSharedUserMessageSettingAppliesWhenSamlHasNone() throws Exception {
    this.start(spMetadata(sp -> {}), c -> c.supportsUserMessage(true));
    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setExtensions(extensions(userMessage("text/rtf", "Hej"))));
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);
  }

  @Test
  void aSadRequestFromASignatureServiceIsValidated() throws Exception {
    this.start(spMetadata(sp -> {}, SIGSERVICE), c -> {});
    final UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(sadRequest(SP_ENTITY_ID)))));
    final SamlAuthenticationRequirements requirements =
        (SamlAuthenticationRequirements) token.getAuthnRequirements();
    assertThat(requirements.getSadRequestExtension()).isNotNull();
    assertThat(requirements.getSadRequestExtension().getDocumentCount()).isEqualTo(2);

    final RequestHttpObject<AuthnRequest> request = generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING,
        r -> r.setExtensions(extensions(sadRequest("https://other.example.com"))));
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.REQUESTER,
        StatusCode.REQUEST_UNSUPPORTED);
  }

  @Test
  void aSadRequestFromAnotherSpIsIgnored() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    final UserAuthenticationInputToken token = this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL,
        POST_BINDING, r -> r.setExtensions(extensions(sadRequest(SP_ENTITY_ID)))));
    assertThat(((SamlAuthenticationRequirements) token.getAuthnRequirements()).getSadRequestExtension()).isNull();
  }

  // Requester acceptance

  @Test
  void withoutAcceptanceConfigurationEverySpIsAccepted() throws Exception {
    this.start(spMetadata(sp -> {}), c -> {});
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
  }

  @Test
  void aWhitelistAcceptsAndRejects() throws Exception {
    this.start(spMetadata(sp -> {}), c -> c.configurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of(SP_ENTITY_ID))));
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
    this.close();

    this.start(knownSpMetadata, c -> c.configurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of("https://other.sp"))));
    assertRejected(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}));
  }

  @Test
  void requiredMarksAndCombinationModes() throws Exception {
    final RequesterPredicate marks = new RequiredMarksRequesterPredicate(AuthenticationProtocol.SAML,
        List.of(List.of(LOA3_PNR, "http://example.com/other"), List.of(SIGSERVICE)));
    final RequesterPredicate whitelist =
        new WhitelistRequesterPredicate(AuthenticationProtocol.SAML, List.of(SP_ENTITY_ID));

    this.start(spMetadata(sp -> {}, LOA3_PNR, SIGSERVICE), c -> c.configurableRequesterAcceptance()
        .addPredicate(marks));
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
    this.close();

    // Missing the second group
    this.start(spMetadata(sp -> {}, LOA3_PNR), c -> c.configurableRequesterAcceptance()
        .addPredicate(marks).addPredicate(whitelist));
    assertRejected(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}));
    this.close();

    // Any mode: the whitelist is enough
    this.start(knownSpMetadata, c -> c.configurableRequesterAcceptance()
        .addPredicate(marks).addPredicate(whitelist)
        .mode(AuthenticationProtocol.SAML, ConfigurableRequesterAcceptance.Mode.ANY));
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
  }

  @Test
  void predicatesOfAnotherProtocolAreNotEvaluated() throws Exception {
    this.start(spMetadata(sp -> {}), c -> c.configurableRequesterAcceptance()
        .addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.OIDC, List.of("client"))));
    assertThat(this.process(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}))).isNotNull();
  }

  @Test
  void aPredicateMayReadTheSamlMetadata() throws Exception {
    final RequesterPredicate hasOrganization = new RequesterPredicate() {

      @Override
      public @Nonnull AuthenticationProtocol getProtocol() {
        return AuthenticationProtocol.SAML;
      }

      @Override
      public boolean test(final @Nonnull RequesterRecord record,
          final @Nonnull se.swedenconnect.spring.authnserver.registry.ClientRegistry registry) {
        return record.getProtocolMetadata(EntityDescriptor.class).getOrganization() != null;
      }
    };
    this.start(spMetadata(sp -> {}), c -> c.configurableRequesterAcceptance().addPredicate(hasOrganization));
    assertRejected(generate(knownSpMetadata, idp(), SP_CREDENTIAL, POST_BINDING, r -> {}));
  }

  // Helpers

  private void start(final EntityDescriptor spMetadata, final Consumer<AuthnServerConfigurer> c) {
    knownSpMetadata = spMetadata;
    customizer = c;
    this.context = new AnnotationConfigWebApplicationContext();
    this.context.setServletContext(new MockServletContext());
    this.context.register(TestConfiguration.class);
    this.context.refresh();
  }

  private static Saml2IdpConfigurer saml(final AuthnServerConfigurer configurer) {
    return configurer.getProtocolConfigurer(Saml2IdpConfigurer.class);
  }

  private static EntityDescriptor idp() {
    return idpMetadata("/saml2/redirect/authn", "/saml2/post/authn");
  }

  private MockHttpServletResponse send(final MockHttpServletRequest request) throws Exception {
    RESULT.set(null);
    final Filter filter = this.context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private UserAuthenticationInputToken process(final RequestHttpObject<AuthnRequest> request) throws Exception {
    RESULT.set(null);
    this.send(toHttpRequest(request));
    assertThat(RESULT.get()).as("The request was not processed").isNotNull();
    return RESULT.get();
  }

  private void assertUnrecoverable(final RequestHttpObject<AuthnRequest> request,
      final SamlUnrecoverableError error) {
    assertThatThrownBy(() -> this.send(toHttpRequest(request)))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(error));
  }

  private void assertRejected(final RequestHttpObject<AuthnRequest> request) throws Exception {
    assertErrorResponse(this.send(toHttpRequest(request)), request, StatusCode.RESPONDER, StatusCode.REQUEST_DENIED);
  }

  private static void assertErrorResponse(final MockHttpServletResponse httpResponse,
      final RequestHttpObject<AuthnRequest> request, final String statusCode, final String subStatusCode)
      throws Exception {
    assertThat(RESULT.get()).isNull();
    assertThat(responseDestination(httpResponse)).isEqualTo(ACS_URL);
    final Response response = parseResponse(httpResponse);
    assertThat(response.getInResponseTo()).isEqualTo(request.getRequest().getID());
    assertThat(response.getDestination()).isEqualTo(ACS_URL);
    assertThat(response.getIssuer().getValue()).isEqualTo(BASE_URL);
    assertThat(response.isSigned()).isTrue();
    assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(statusCode);
    assertThat(response.getStatus().getStatusCode().getStatusCode().getValue()).isEqualTo(subStatusCode);
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

  private static org.opensaml.saml.saml2.core.Extensions extensions(
      final org.opensaml.core.xml.XMLObject extension) {
    return se.swedenconnect.opensaml.saml2.core.build.ExtensionsBuilder.builder().extension(extension).build();
  }

  private static SignMessage signMessage(final String text) {
    final SignMessage signMessage = (SignMessage) XMLObjectSupport.buildXMLObject(SignMessage.DEFAULT_ELEMENT_NAME);
    signMessage.setDisplayEntity(BASE_URL);
    signMessage.setMustShow(true);
    final se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message message =
        (se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message) XMLObjectSupport.buildXMLObject(
            se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message.DEFAULT_ELEMENT_NAME);
    message.setValue(Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)));
    signMessage.setMessage(message);
    return signMessage;
  }

  private static UserMessage userMessage(final String mimeType, final String text) {
    final UserMessage userMessage = (UserMessage) XMLObjectSupport.buildXMLObject(UserMessage.DEFAULT_ELEMENT_NAME);
    userMessage.setMimeType(mimeType);
    final Message message = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
    message.setXMLLang("sv");
    message.setValue(Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)));
    userMessage.getMessages().add(message);
    return userMessage;
  }

  private static SADRequest sadRequest(final String requesterId) {
    final SADRequest sadRequest = (SADRequest) XMLObjectSupport.buildXMLObject(SADRequest.DEFAULT_ELEMENT_NAME);
    sadRequest.setID("_sad-request-id");
    sadRequest.setRequesterID(requesterId);
    sadRequest.setSignRequestID("sign-request-id");
    sadRequest.setDocCount(2);
    sadRequest.setRequestedVersion(SADVersion.VERSION_10);
    return sadRequest;
  }

}
