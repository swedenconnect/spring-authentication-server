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

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.security.config.Customizer;
import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Builds and signs SAML responses: a success response carrying the assertion, encrypted for the Service Provider when
 * assertions are to be encrypted, and error responses.
 *
 * @author Martin Lindström
 */
public class Saml2ResponseBuilder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2ResponseBuilder.class);

  /** The issuer of the responses, the entityID of the Identity Provider. */
  private final String issuer;

  /** The signing credential. */
  private final OpenSamlCredential signingCredential;

  /** For customizing the response before it is signed. */
  private Customizer<Response> responseCustomizer = Customizer.withDefaults();

  /** Generates message IDs. */
  private IdentifierGenerationStrategy idGenerator = new RandomIdentifierGenerationStrategy();

  /** Whether assertions are encrypted. */
  private boolean encryptAssertions = false;

  /** Encrypts assertions, created when assertions are to be encrypted. */
  private SAMLObjectEncrypter encrypter;

  /** For resolving status messages, may be {@code null}. */
  private MessageSource messageSource;

  /**
   * Constructor.
   *
   * @param issuer the entityID of the Identity Provider
   * @param signingCredential the signing credential
   */
  public Saml2ResponseBuilder(final @Nonnull String issuer, final @Nonnull PkiCredential signingCredential) {
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.signingCredential =
        new OpenSamlCredential(Objects.requireNonNull(signingCredential, "signingCredential must not be null"));
  }

  /**
   * Builds a signed error response.
   * <p>
   * The status message is resolved from the message code of the error, if a {@link MessageSource} has been assigned,
   * and is otherwise the description of the error.
   * </p>
   *
   * @param responseAttributes where and how the response is sent
   * @param error the error
   * @return a signed {@link Response}
   * @throws UnrecoverableErrorException if the response cannot be built or signed
   */
  public @Nonnull Response buildErrorResponse(final @Nonnull Saml2ResponseAttributes responseAttributes,
      final @Nonnull SamlErrorStatusException error) throws UnrecoverableErrorException {

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode statusCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(error.getStatus().statusCode());
    final StatusCode subStatusCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    subStatusCode.setValue(error.getStatus().subStatusCode());
    statusCode.setStatusCode(subStatusCode);
    status.setStatusCode(statusCode);

    final String message = this.resolveStatusMessage(error);
    if (StringUtils.hasText(message)) {
      final StatusMessage statusMessage =
          (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
      statusMessage.setValue(message);
      status.setStatusMessage(statusMessage);
    }

    final Response response = this.createResponse(responseAttributes, status);
    this.responseCustomizer.customize(response);
    this.signResponse(response, responseAttributes);
    return response;
  }

  /**
   * Builds a signed success response holding the assertion. When assertions are encrypted, the assertion is encrypted
   * for the Service Provider, with a key and the algorithms from its metadata.
   *
   * @param responseAttributes where and how the response is sent
   * @param assertion the assertion
   * @return a signed {@link Response}
   * @throws UnrecoverableErrorException if the response cannot be built, encrypted or signed
   */
  public @Nonnull Response buildResponse(final @Nonnull Saml2ResponseAttributes responseAttributes,
      final @Nonnull Assertion assertion) throws UnrecoverableErrorException {

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode statusCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(StatusCode.SUCCESS);
    status.setStatusCode(statusCode);

    final Response response = this.createResponse(responseAttributes, status);
    if (this.encryptAssertions) {
      response.getEncryptedAssertions().add(this.encryptAssertion(assertion, responseAttributes));
    }
    else {
      response.getAssertions().add(assertion);
    }
    this.responseCustomizer.customize(response);
    this.signResponse(response, responseAttributes);
    return response;
  }

  /**
   * Encrypts the assertion for the Service Provider.
   *
   * @param assertion the assertion
   * @param responseAttributes where and how the response is sent
   * @return an {@link EncryptedAssertion}
   * @throws UnrecoverableErrorException if the assertion cannot be encrypted
   */
  protected @Nonnull EncryptedAssertion encryptAssertion(final @Nonnull Assertion assertion,
      final @Nonnull Saml2ResponseAttributes responseAttributes) throws UnrecoverableErrorException {
    try {
      final EncryptedData encryptedData = this.getEncrypter().encrypt(assertion,
          new SAMLObjectEncrypter.Peer(responseAttributes.getPeerMetadata()));
      final EncryptedAssertion encryptedAssertion =
          (EncryptedAssertion) XMLObjectSupport.buildXMLObject(EncryptedAssertion.DEFAULT_ELEMENT_NAME);
      encryptedAssertion.setEncryptedData(encryptedData);
      return encryptedAssertion;
    }
    catch (final EncryptionException e) {
      log.error("Failed to encrypt Assertion - {} [entity-id: '{}', authn-request: '{}']", e.getMessage(),
          responseAttributes.getEntityId(), responseAttributes.inResponseTo(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to encrypt Assertion", e);
    }
  }

  /**
   * Creates a response holding the supplied status.
   *
   * @param responseAttributes where and how the response is sent
   * @param status the status
   * @return a {@link Response}
   */
  protected @Nonnull Response createResponse(final @Nonnull Saml2ResponseAttributes responseAttributes,
      final @Nonnull Status status) {

    final Response response = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
    response.setID(this.idGenerator.generateIdentifier());
    response.setDestination(responseAttributes.destination());
    response.setInResponseTo(responseAttributes.inResponseTo());
    response.setIssueInstant(Instant.now());
    final Issuer responseIssuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    responseIssuer.setValue(this.issuer);
    response.setIssuer(responseIssuer);
    response.setStatus(status);
    return response;
  }

  /**
   * Signs the response, with the algorithms that the Service Provider metadata prefers.
   *
   * @param response the response
   * @param responseAttributes where and how the response is sent
   * @throws UnrecoverableErrorException if the response cannot be signed
   */
  protected void signResponse(final @Nonnull Response response,
      final @Nonnull Saml2ResponseAttributes responseAttributes) throws UnrecoverableErrorException {
    try {
      SAMLObjectSigner.sign(response, this.signingCredential,
          SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), responseAttributes.getPeerMetadata());
      log.debug("Response message successfully signed [entity-id: '{}', authn-request: '{}']",
          responseAttributes.getEntityId(), responseAttributes.inResponseTo());
    }
    catch (final SignatureException e) {
      log.error("Failed to sign Response message - {} [entity-id: '{}', authn-request: '{}']",
          e.getMessage(), responseAttributes.getEntityId(), responseAttributes.inResponseTo(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to sign Response message", e);
    }
  }

  /**
   * Resolves the status message of an error.
   *
   * @param error the error
   * @return the status message
   */
  private @Nullable String resolveStatusMessage(final @Nonnull SamlErrorStatusException error) {
    if (this.messageSource != null) {
      final String message =
          this.messageSource.getMessage(error.getStatusMessageCode(), null, null, Locale.ENGLISH);
      if (message != null) {
        return message;
      }
    }
    return error.getDescription();
  }

  /**
   * Assigns whether assertions are encrypted. Defaults to {@code false}.
   *
   * @param encryptAssertions whether assertions are encrypted
   */
  public void setEncryptAssertions(final boolean encryptAssertions) {
    this.encryptAssertions = encryptAssertions;
  }

  /**
   * Gets the encrypter, creating it the first time.
   *
   * @return the encrypter
   */
  private @Nonnull SAMLObjectEncrypter getEncrypter() {
    if (this.encrypter == null) {
      try {
        this.encrypter = new SAMLObjectEncrypter();
      }
      catch (final ComponentInitializationException e) {
        throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to initialize encrypter", e);
      }
    }
    return this.encrypter;
  }

  /**
   * Assigns a customizer that gets the response before it is signed.
   *
   * @param responseCustomizer the customizer
   */
  public void setResponseCustomizer(final @Nonnull Customizer<Response> responseCustomizer) {
    this.responseCustomizer = Objects.requireNonNull(responseCustomizer, "responseCustomizer must not be null");
  }

  /**
   * Assigns the generator of message IDs. The default is a {@link RandomIdentifierGenerationStrategy}.
   *
   * @param idGenerator the generator
   */
  public void setIdGenerator(final @Nonnull IdentifierGenerationStrategy idGenerator) {
    this.idGenerator = Objects.requireNonNull(idGenerator, "idGenerator must not be null");
  }

  /**
   * Assigns the message source that status messages are resolved against.
   *
   * @param messageSource the message source, or {@code null}
   */
  public void setMessageSource(final @Nullable MessageSource messageSource) {
    this.messageSource = messageSource;
  }

}
