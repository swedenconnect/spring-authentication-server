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

import java.util.Objects;

import net.shibboleth.shared.net.URIComparator;
import net.shibboleth.shared.net.URIException;
import net.shibboleth.shared.net.impl.BasicURLComparator;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;

/**
 * Establishes the assertion consumer service that the response is sent to, from the {@code AuthnRequest} and the
 * Service Provider metadata. When the request gives none, the default assertion consumer service of the metadata is
 * used. The URL is assigned to the token.
 *
 * @author Martin Lindström
 */
public class AssertionConsumerServiceValidator implements AuthnRequestValidator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AssertionConsumerServiceValidator.class);

  /** For comparing URLs. */
  private URIComparator uriComparator = new BasicURLComparator();

  /**
   * Assigns the comparator used to compare the requested URL with those of the metadata. The default is a
   * {@link BasicURLComparator}.
   *
   * @param uriComparator the comparator
   */
  public void setUriComparator(final @Nonnull URIComparator uriComparator) {
    this.uriComparator = Objects.requireNonNull(uriComparator, "uriComparator must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final @Nonnull Saml2AuthnRequestAuthenticationToken token) {
    final AuthnRequest authnRequest = token.getAuthnRequest();
    final SPSSODescriptor ssoDesc =
        Objects.requireNonNull(token.getPeerMetadata()).getSPSSODescriptor(SAMLConstants.SAML20P_NS);

    final String assertionConsumerServiceUrl = authnRequest.getAssertionConsumerServiceURL();
    final Integer assertionConsumerServiceIndex = authnRequest.getAssertionConsumerServiceIndex();
    final String protocolBinding = authnRequest.getProtocolBinding();

    // According to SAML Core, Section 3.4.1, AssertionConsumerServiceIndex is mutually exclusive with
    // AssertionConsumerServiceURL and ProtocolBinding.
    //
    if (assertionConsumerServiceIndex != null && (assertionConsumerServiceUrl != null || protocolBinding != null)) {
      final String combinedWith;
      if (assertionConsumerServiceUrl != null && protocolBinding != null) {
        combinedWith = "AssertionConsumerServiceURL and ProtocolBinding";
      }
      else if (assertionConsumerServiceUrl != null) {
        combinedWith = "AssertionConsumerServiceURL";
      }
      else {
        combinedWith = "ProtocolBinding";
      }
      final String msg = "AssertionConsumerServiceIndex in AuthnRequest must not be combined with " + combinedWith;
      log.info("{} [{}]", msg, token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_ASSERTION_CONSUMER_SERVICE, msg);
    }

    if (assertionConsumerServiceUrl == null && assertionConsumerServiceIndex == null) {
      log.debug("No AssertionConsumerService information provided in AuthnRequest - will use default from metadata "
          + "[{}]", token.getLogString());

      final AssertionConsumerService acs = ssoDesc.getDefaultAssertionConsumerService();
      if (acs == null || acs.getLocation() == null) {
        final String msg = "No AssertionConsumerService given in AuthnRequest"
            + " and no valid AssertionConsumerService found in metadata";
        log.info("{} [{}]", msg, token.getLogString());
        throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_ASSERTION_CONSUMER_SERVICE, msg);
      }
      token.setAssertionConsumerServiceUrl(acs.getLocation());
    }
    else {
      for (final AssertionConsumerService acs : ssoDesc.getAssertionConsumerServices()) {
        if (acs.getLocation() == null) {
          continue;
        }
        if (assertionConsumerServiceIndex != null) {
          if (acs.getIndex() != null && assertionConsumerServiceIndex.intValue() == acs.getIndex().intValue()) {
            token.setAssertionConsumerServiceUrl(acs.getLocation());
            break;
          }
        }
        else {
          try {
            if (this.uriComparator.compare(acs.getLocation(), assertionConsumerServiceUrl)) {
              token.setAssertionConsumerServiceUrl(acs.getLocation());
              break;
            }
          }
          catch (final URIException ignored) {
            // Not a match
          }
        }
      }
    }
    if (token.getAssertionConsumerServiceUrl() == null) {
      final String msg = "AssertionConsumerService given in AuthnRequest does not appear in metadata";
      log.info("{} [{}]", msg, token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_ASSERTION_CONSUMER_SERVICE, msg);
    }
    log.debug("Using AssertionConsumerServiceURL: {} [{}]",
        token.getAssertionConsumerServiceUrl(), token.getLogString());
  }

}
