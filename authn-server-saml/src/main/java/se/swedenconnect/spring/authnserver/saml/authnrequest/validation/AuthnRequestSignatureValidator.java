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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCriterion;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;

/**
 * Validates the signature of an authentication request, for the redirect binding (the signature is a query parameter)
 * as well as the POST binding (the signature is in the message). The signature is validated against the signing keys
 * of the Service Provider metadata.
 * <p>
 * A request must be signed if the Identity Provider requires signed requests, or if the Service Provider metadata
 * states that its requests are signed ({@code AuthnRequestsSigned}). An unsigned request is otherwise accepted.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthnRequestSignatureValidator implements AuthnRequestValidator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnRequestSignatureValidator.class);

  /** Whether the Identity Provider requires signed requests. */
  private final boolean requireSignedRequests;

  /** For resolving the credentials of KeyInfo elements. */
  private final KeyInfoCredentialResolver keyInfoCredentialResolver =
      DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();

  /**
   * Constructor.
   *
   * @param requireSignedRequests whether the Identity Provider requires signed requests
   */
  public AuthnRequestSignatureValidator(final boolean requireSignedRequests) {
    this.requireSignedRequests = requireSignedRequests;
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final @Nonnull Saml2AuthnRequestAuthenticationToken token) {
    final HttpServletRequest request = Objects.requireNonNull(token.getHttpServletRequest(), "No HTTP request");
    final MessageContext messageContext = Objects.requireNonNull(token.getMessageContext(), "No message context");
    final EntityDescriptor peerMetadata = Objects.requireNonNull(token.getPeerMetadata(), "No peer metadata");
    final boolean redirect = SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(token.getBindingUri());

    final boolean signed = redirect
        ? StringUtils.hasText(request.getParameter("Signature"))
        : token.getAuthnRequest().isSigned();

    if (!signed) {
      if (this.isSignedAuthnRequestRequired(peerMetadata)) {
        log.info("Authentication request is required to be signed, but is not [{}]", token.getLogString());
        throw new UnrecoverableErrorException(SamlUnrecoverableError.MISSING_AUTHNREQUEST_SIGNATURE);
      }
      log.debug("Authentication request is not signed, and that is accepted [{}]", token.getLogString());
      return;
    }

    messageContext.addSubcontext(this.createSecurityParametersContext(peerMetadata));

    try {
      if (redirect) {
        final SAML2HTTPRedirectDeflateSignatureSecurityHandler handler =
            new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
        handler.setHttpServletRequestSupplier(() -> request);
        handler.initialize();
        handler.invoke(messageContext);
      }
      else {
        final SAMLProtocolMessageXMLSignatureSecurityHandler handler =
            new SAMLProtocolMessageXMLSignatureSecurityHandler();
        handler.initialize();
        handler.invoke(messageContext);
      }
    }
    catch (final MessageHandlerException e) {
      log.info("Authentication request signature validation failed - {} [{}]", e.getMessage(), token.getLogString());
      log.debug("", e);
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_AUTHNREQUEST_SIGNATURE,
          "Authentication request signature validation failed - " + e.getMessage(), e);
    }
    catch (final ComponentInitializationException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Failed to initialize signature security handler", e);
    }
    log.debug("Authentication request signature validation was successful [{}]", token.getLogString());
  }

  /**
   * Tells whether the request must be signed.
   *
   * @param peerMetadata the Service Provider metadata
   * @return {@code true} if the request must be signed and {@code false} otherwise
   */
  protected boolean isSignedAuthnRequestRequired(final @Nonnull EntityDescriptor peerMetadata) {
    return this.requireSignedRequests
        || Boolean.TRUE.equals(peerMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS).isAuthnRequestsSigned());
  }

  /**
   * Creates the security parameters for the signature validation, with a trust engine holding the signing keys of the
   * Service Provider metadata.
   *
   * @param peerMetadata the Service Provider metadata
   * @return a {@link SecurityParametersContext}
   */
  private @Nonnull SecurityParametersContext createSecurityParametersContext(
      final @Nonnull EntityDescriptor peerMetadata) {

    final SignatureValidationConfiguration globalConfig =
        ConfigurationService.get(SignatureValidationConfiguration.class);

    final SignatureValidationParameters parameters = new SignatureValidationParameters();
    if (globalConfig != null) {
      parameters.setExcludedAlgorithms(globalConfig.getExcludedAlgorithms());
      parameters.setIncludedAlgorithms(globalConfig.getIncludedAlgorithms());
    }
    parameters.setSignatureTrustEngine(this.createTrustEngine(peerMetadata));

    final SecurityParametersContext context = new SecurityParametersContext();
    context.setSignatureValidationParameters(parameters);
    return context;
  }

  /**
   * Creates a trust engine that trusts the signing keys of the Service Provider metadata.
   *
   * @param peerMetadata the Service Provider metadata
   * @return a {@link SignatureTrustEngine}
   */
  private @Nonnull SignatureTrustEngine createTrustEngine(final @Nonnull EntityDescriptor peerMetadata) {
    final SPSSODescriptor descriptor = peerMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    final List<Credential> credentials = new ArrayList<>();
    for (final KeyDescriptor kd : descriptor.getKeyDescriptors()) {
      if (kd.getKeyInfo() == null || UsageType.ENCRYPTION == kd.getUse()) {
        continue;
      }
      try {
        this.keyInfoCredentialResolver.resolve(new CriteriaSet(new KeyInfoCriterion(kd.getKeyInfo())))
            .forEach(credentials::add);
      }
      catch (final ResolverException e) {
        log.debug("Failed to resolve credential from KeyInfo of '{}' - {}", peerMetadata.getEntityID(),
            e.getMessage());
      }
    }
    return new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(credentials),
        this.keyInfoCredentialResolver);
  }

}
