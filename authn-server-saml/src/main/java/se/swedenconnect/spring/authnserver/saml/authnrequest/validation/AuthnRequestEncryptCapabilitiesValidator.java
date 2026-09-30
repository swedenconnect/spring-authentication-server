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

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * When assertions are encrypted, checks that the Service Provider metadata has a key that they can be encrypted for.
 *
 * @author Martin Lindström
 */
public class AuthnRequestEncryptCapabilitiesValidator implements AuthnRequestValidator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnRequestEncryptCapabilitiesValidator.class);

  /** Whether assertions are encrypted. */
  private final boolean encryptAssertions;

  /**
   * Constructor.
   *
   * @param encryptAssertions whether assertions are encrypted
   */
  public AuthnRequestEncryptCapabilitiesValidator(final boolean encryptAssertions) {
    this.encryptAssertions = encryptAssertions;
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final @NonNull Saml2AuthnRequestAuthenticationToken token) throws SamlErrorStatusException {
    if (!this.encryptAssertions) {
      return;
    }
    final SPSSODescriptor descriptor =
        Objects.requireNonNull(token.getPeerMetadata()).getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    for (final KeyDescriptor kd : descriptor.getKeyDescriptors()) {
      if ((kd.getUse() == null || UsageType.ENCRYPTION == kd.getUse() || UsageType.UNSPECIFIED == kd.getUse())
          && kd.getKeyInfo() != null) {
        return;
      }
    }
    log.info("SP does not have a KeyDescriptor that can be used for encryption of assertions [{}]",
        token.getLogString());
    throw new SamlErrorStatusException(SamlErrorStatus.ENCRYPT_NOT_POSSIBLE,
        SamlErrorStatus.ENCRYPT_NOT_POSSIBLE_MESSAGE_CODE, "Missing key descriptor for encryption");
  }

}
