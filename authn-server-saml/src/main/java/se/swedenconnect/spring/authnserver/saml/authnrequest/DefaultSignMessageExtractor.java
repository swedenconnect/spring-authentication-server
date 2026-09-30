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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * The default {@link SignMessageExtractor}.
 * <p>
 * Only Service Providers that declare the signature service entity category may send a {@code SignMessage}; for all
 * others the extension is ignored. A {@code SignMessage} whose {@code DisplayEntity} is not the Identity Provider is
 * also ignored. An encrypted message is decrypted with the Identity Provider's encryption credentials.
 * </p>
 *
 * @author Martin Lindström
 */
public class DefaultSignMessageExtractor implements SignMessageExtractor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(DefaultSignMessageExtractor.class);

  /** The entityID of the Identity Provider. */
  private final String entityId;

  /** The decrypter, or {@code null} if no decryption credentials are available. */
  private final SAMLObjectDecrypter decrypter;

  /**
   * Constructor.
   *
   * @param entityId the entityID of the Identity Provider
   * @param decryptionCredentials the credentials for decrypting encrypted messages, the current one first
   */
  public DefaultSignMessageExtractor(final @NonNull String entityId,
      final @NonNull List<PkiCredential> decryptionCredentials) {
    this.entityId = Objects.requireNonNull(entityId, "entityId must not be null");
    if (!Objects.requireNonNull(decryptionCredentials, "decryptionCredentials must not be null").isEmpty()) {
      final List<Credential> credentials = decryptionCredentials.stream()
          .map(OpenSamlCredential::new)
          .map(Credential.class::cast)
          .toList();
      this.decrypter = new SAMLObjectDecrypter(credentials);
      this.decrypter.setPkcs11Workaround(decryptionCredentials.stream().anyMatch(PkiCredential::isHardwareCredential));
    }
    else {
      log.warn("No decryption credentials available - encrypted SignMessage elements are not supported");
      this.decrypter = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable GenericSignMessage extract(final @NonNull Saml2AuthnRequestAuthenticationToken token)
      throws SamlErrorStatusException {

    final SignMessage signMessage = Optional.ofNullable(token.getAuthnRequest().getExtensions())
        .map(e -> e.getUnknownXMLObjects(SignMessage.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(list -> list.get(0))
        .filter(SignMessage.class::isInstance)
        .map(SignMessage.class::cast)
        .orElse(null);
    if (signMessage == null) {
      return null;
    }

    // Only Service Providers registered as signature services may send SignMessage extensions. For all others the
    // extension is ignored.
    //
    if (!token.isSignatureServicePeer()) {
      log.info("AuthnRequest contains SignMessage extension, but SP is not a signature service - ignoring [{}]",
          token.getLogString());
      return null;
    }
    if (signMessage.getDisplayEntity() != null && !signMessage.getDisplayEntity().equalsIgnoreCase(this.entityId)) {
      log.info("DisplayEntity of SignMessage ('{}') does not correspond with the IdP entityID - ignoring [{}]",
          signMessage.getDisplayEntity(), token.getLogString());
      return null;
    }

    final Message clearTextMessage;
    if (signMessage.getEncryptedMessage() != null) {
      if (this.decrypter == null) {
        throw error("Encrypted SignMessage received, but no decryption credentials are available", token, null);
      }
      try {
        clearTextMessage = this.decrypter.decrypt(signMessage.getEncryptedMessage(), Message.class);
      }
      catch (final DecryptionException e) {
        throw error("Failed to decrypt SignMessage - " + e.getMessage(), token, e);
      }
    }
    else {
      clearTextMessage = signMessage.getMessage();
    }
    if (clearTextMessage == null || !StringUtils.hasText(clearTextMessage.getValue())) {
      throw error("Invalid SignMessage - missing data to display", token, null);
    }
    try {
      final String message = clearTextMessage.getValue().replaceAll("\\s", "");
      return new GenericSignMessage(List.of(new LocalizedMessage(null, message)),
          MessageMimeType.parse(signMessage.getMimeType()), Boolean.TRUE.equals(signMessage.isMustShow()), null);
    }
    catch (final IllegalArgumentException e) {
      throw error("Invalid SignMessage - " + e.getMessage(), token, e);
    }
  }

  /**
   * Creates the exception for an invalid sign message, and logs it.
   *
   * @param msg the message
   * @param token the authentication request token
   * @param cause the cause, or {@code null}
   * @return a {@link SamlErrorStatusException}
   */
  private static @NonNull SamlErrorStatusException error(final @NonNull String msg,
      final @NonNull Saml2AuthnRequestAuthenticationToken token, final @Nullable Throwable cause) {
    log.info("{} [{}]", msg, token.getLogString());
    return new SamlErrorStatusException(SamlErrorStatus.SIGN_MESSAGE_ERROR,
        SamlErrorStatus.SIGN_MESSAGE_ERROR_MESSAGE_CODE, msg, cause);
  }

}
