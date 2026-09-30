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
package se.swedenconnect.spring.authnserver.saml.response;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.KeyInfoConfirmationDataType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.SubjectLocality;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.Customizer;

import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseManager;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestData;

/**
 * Builds the SAML {@link Assertion} for an authenticated user.
 * <p>
 * The assertion holds the {@code NameID} from the generator of the request, a subject confirmation, the conditions
 * with the Service Provider as audience, an authentication statement and an attribute statement. The subject
 * confirmation is {@code bearer}, or {@code holder-of-key} for a request received on a Holder-of-key endpoint, see the
 * SAML V2.0 Holder-of-Key Web Browser SSO Profile.
 * </p>
 * <p>
 * The released attributes come from the {@link AttributeReleaseManager}, which works from the requirements of the
 * request being answered, and are mapped to SAML attributes by the {@link SamlAttributeMapping}. The
 * {@link AttributeIdentifiers#AUTHENTICATION_PROVIDER} attribute becomes an {@code AuthenticatingAuthority}.
 * </p>
 * <p>
 * The assertion is signed if the Service Provider metadata states {@code WantAssertionsSigned}, and always for
 * Holder-of-key.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2AssertionBuilder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2AssertionBuilder.class);

  /** The default time that an assertion is valid after it was issued, 5 minutes. */
  public static final Duration DEFAULT_NOT_ON_OR_AFTER = Duration.ofMinutes(5);

  /** The default time that an assertion is valid before it was issued, 10 seconds. */
  public static final Duration DEFAULT_NOT_BEFORE = Duration.ofSeconds(10);

  /** The issuer, the entityID of the Identity Provider. */
  private final String issuer;

  /** The signing credential. */
  private final OpenSamlCredential signingCredential;

  /** Decides which attributes are released. */
  private final AttributeReleaseManager attributeReleaseManager;

  /** Maps the released attributes to SAML attributes. */
  private final SamlAttributeMapping attributeMapping;

  /** How long the assertion is valid after it was issued. */
  private Duration notOnOrAfter = DEFAULT_NOT_ON_OR_AFTER;

  /** How long before it was issued the assertion is valid. */
  private Duration notBefore = DEFAULT_NOT_BEFORE;

  /** For customizing the assertion before it is signed. */
  private Customizer<Assertion> assertionCustomizer = Customizer.withDefaults();

  /** Generates assertion IDs. */
  private IdentifierGenerationStrategy idGenerator = new RandomIdentifierGenerationStrategy();

  /**
   * Constructor.
   *
   * @param issuer the entityID of the Identity Provider
   * @param signingCredential the signing credential
   * @param attributeReleaseManager decides which attributes are released
   * @param attributeMapping maps the released attributes to SAML attributes
   */
  public Saml2AssertionBuilder(final @Nonnull String issuer, final @Nonnull PkiCredential signingCredential,
      final @Nonnull AttributeReleaseManager attributeReleaseManager,
      final @Nonnull SamlAttributeMapping attributeMapping) {
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.signingCredential =
        new OpenSamlCredential(Objects.requireNonNull(signingCredential, "signingCredential must not be null"));
    this.attributeReleaseManager =
        Objects.requireNonNull(attributeReleaseManager, "attributeReleaseManager must not be null");
    this.attributeMapping = Objects.requireNonNull(attributeMapping, "attributeMapping must not be null");
  }

  /**
   * Builds the assertion.
   *
   * @param authentication the authentication, carrying the requirements of the request being answered
   * @param requestData the SAML data of the request
   * @param requester the Service Provider
   * @return the assertion
   * @throws AuthenticationErrorException if the attribute release fails in a way that is reported to the Service
   *     Provider
   * @throws UnrecoverableErrorException if the assertion cannot be built or signed
   */
  public @Nonnull Assertion buildAssertion(final @Nonnull UserAuthentication authentication,
      final @Nonnull Saml2AuthnRequestData requestData, final @Nonnull Requester requester)
      throws AuthenticationErrorException, UnrecoverableErrorException {

    final AuthenticatedUser user = authentication.getAuthenticatedUser();
    final Saml2ResponseAttributes responseAttributes = requestData.responseAttributes();
    final Instant now = Instant.now();

    final Assertion assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
    assertion.setID(this.idGenerator.generateIdentifier());
    assertion.setIssueInstant(now);

    final Issuer assertionIssuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    assertionIssuer.setValue(this.issuer);
    assertion.setIssuer(assertionIssuer);

    // Subject
    //
    final Subject subject = (Subject) XMLObjectSupport.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
    subject.setNameID(requestData.nameIdGenerator().getNameID(user, requester));
    subject.getSubjectConfirmations().add(this.createSubjectConfirmation(requestData, user, now));
    assertion.setSubject(subject);

    // Conditions
    //
    final Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
    conditions.setNotBefore(now.minus(this.notBefore));
    conditions.setNotOnOrAfter(now.plus(this.notOnOrAfter));
    final AudienceRestriction audienceRestriction =
        (AudienceRestriction) XMLObjectSupport.buildXMLObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
    final Audience audience = (Audience) XMLObjectSupport.buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
    audience.setURI(responseAttributes.getEntityId());
    audienceRestriction.getAudiences().add(audience);
    conditions.getAudienceRestrictions().add(audienceRestriction);
    assertion.setConditions(conditions);

    // AuthnStatement
    //
    final AuthnStatement authnStatement =
        (AuthnStatement) XMLObjectSupport.buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
    authnStatement.setAuthnInstant(user.getAuthnInstant());
    authnStatement.setSessionIndex(assertion.getID());
    final SubjectLocality subjectLocality =
        (SubjectLocality) XMLObjectSupport.buildXMLObject(SubjectLocality.DEFAULT_ELEMENT_NAME);
    subjectLocality.setAddress(user.getClientIpAddress());
    authnStatement.setSubjectLocality(subjectLocality);
    final AuthnContext authnContext = (AuthnContext) XMLObjectSupport.buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
    final AuthnContextClassRef authnContextClassRef =
        (AuthnContextClassRef) XMLObjectSupport.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    authnContextClassRef.setURI(user.getAuthnContextUri());
    authnContext.setAuthnContextClassRef(authnContextClassRef);
    final GenericAttribute<?> authenticationProvider = user.getAttribute(AttributeIdentifiers.AUTHENTICATION_PROVIDER);
    if (authenticationProvider != null) {
      for (final Object value : authenticationProvider.getValues()) {
        final AuthenticatingAuthority authority =
            (AuthenticatingAuthority) XMLObjectSupport.buildXMLObject(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
        authority.setURI(String.valueOf(value));
        authnContext.getAuthenticatingAuthorities().add(authority);
      }
    }
    authnStatement.setAuthnContext(authnContext);
    assertion.getAuthnStatements().add(authnStatement);

    // AttributeStatement
    //
    final AttributeStatement attributeStatement =
        (AttributeStatement) XMLObjectSupport.buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
    attributeStatement.getAttributes().addAll(this.releaseAttributes(authentication));
    assertion.getAttributeStatements().add(attributeStatement);

    this.assertionCustomizer.customize(assertion);

    final SPSSODescriptor descriptor =
        responseAttributes.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (requestData.holderOfKey() || descriptor != null && Boolean.TRUE.equals(descriptor.getWantAssertionsSigned())) {
      this.signAssertion(assertion, requestData, authentication);
    }
    return assertion;
  }

  /**
   * Releases the attributes and maps them to SAML attributes.
   *
   * @param authentication the authentication
   * @return the SAML attributes
   */
  private @Nonnull List<Attribute> releaseAttributes(final @Nonnull UserAuthentication authentication) {
    final List<GenericAttribute<? extends Serializable>> released =
        this.attributeReleaseManager.releaseAttributes(authentication);
    final AuthenticationRequirements requirements = authentication.getAuthnRequirements();
    return this.attributeMapping.toSaml(released, requirements != null ? requirements.getRequestedAttributes() : null);
  }

  /**
   * Creates the subject confirmation, {@code bearer} or {@code holder-of-key}.
   *
   * @param requestData the SAML data of the request
   * @param user the authenticated user
   * @param now the issue instant
   * @return a {@link SubjectConfirmation}
   */
  private @Nonnull SubjectConfirmation createSubjectConfirmation(final @Nonnull Saml2AuthnRequestData requestData,
      final @Nonnull AuthenticatedUser user, final @Nonnull Instant now) {

    final SubjectConfirmation subjectConfirmation =
        (SubjectConfirmation) XMLObjectSupport.buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    final SubjectConfirmationData data;
    if (requestData.holderOfKey()) {
      subjectConfirmation.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
      data = (SubjectConfirmationData) XMLObjectSupport.getBuilder(KeyInfoConfirmationDataType.TYPE_NAME)
          .buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME, KeyInfoConfirmationDataType.TYPE_NAME);
      final KeyInfo keyInfo = (KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
      try {
        KeyInfoSupport.addCertificate(keyInfo, Objects.requireNonNull(requestData.holderOfKeyCertificate()));
      }
      catch (final CertificateEncodingException e) {
        throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
            "Failed to encode the Holder-of-key certificate", e);
      }
      ((KeyInfoConfirmationDataType) data).getKeyInfos().add(keyInfo);
    }
    else {
      subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
      data = (SubjectConfirmationData) XMLObjectSupport.buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
    }
    data.setAddress(user.getClientIpAddress());
    data.setInResponseTo(requestData.responseAttributes().inResponseTo());
    data.setRecipient(requestData.responseAttributes().destination());
    data.setNotOnOrAfter(now.plus(this.notOnOrAfter));
    subjectConfirmation.setSubjectConfirmationData(data);
    return subjectConfirmation;
  }

  /**
   * Signs the assertion with the algorithms that the Service Provider metadata prefers.
   *
   * @param assertion the assertion
   * @param requestData the SAML data of the request
   * @param authentication the authentication, for logging
   * @throws UnrecoverableErrorException if the assertion cannot be signed
   */
  private void signAssertion(final @Nonnull Assertion assertion, final @Nonnull Saml2AuthnRequestData requestData,
      final @Nonnull UserAuthentication authentication) throws UnrecoverableErrorException {
    try {
      SAMLObjectSigner.sign(assertion, this.signingCredential,
          SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(),
          requestData.responseAttributes().getPeerMetadata());
      log.debug("Assertion successfully signed [{}]", authentication.getLogString());
    }
    catch (final SignatureException e) {
      log.error("Failed to sign Assertion - {} [{}]", e.getMessage(), authentication.getLogString(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to sign Assertion", e);
    }
  }

  /**
   * Assigns how long the assertion is valid after it was issued. Defaults to {@link #DEFAULT_NOT_ON_OR_AFTER}.
   *
   * @param notOnOrAfter the duration
   */
  public void setNotOnOrAfter(final @Nonnull Duration notOnOrAfter) {
    this.notOnOrAfter = Objects.requireNonNull(notOnOrAfter, "notOnOrAfter must not be null");
  }

  /**
   * Assigns how long before it was issued the assertion is valid. Defaults to {@link #DEFAULT_NOT_BEFORE}.
   *
   * @param notBefore the duration
   */
  public void setNotBefore(final @Nonnull Duration notBefore) {
    this.notBefore = Objects.requireNonNull(notBefore, "notBefore must not be null");
  }

  /**
   * Assigns a customizer that gets the assertion when it has been built, before it is signed.
   *
   * @param assertionCustomizer the customizer
   */
  public void setAssertionCustomizer(final @Nullable Customizer<Assertion> assertionCustomizer) {
    this.assertionCustomizer = assertionCustomizer != null ? assertionCustomizer : Customizer.withDefaults();
  }

  /**
   * Assigns the generator of assertion IDs. The default is a {@link RandomIdentifierGenerationStrategy}.
   *
   * @param idGenerator the generator
   */
  public void setIdGenerator(final @Nonnull IdentifierGenerationStrategy idGenerator) {
    this.idGenerator = Objects.requireNonNull(idGenerator, "idGenerator must not be null");
  }

}
