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
package se.swedenconnect.spring.authnserver.saml.nameid;

import java.util.List;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGeneratorFactory;

/**
 * A {@link NameIDGeneratorFactory} that implements the requirements on {@code NameID}s of the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 * <p>
 * The format is taken from the {@code NameIDPolicy} of the authentication request. When the request says nothing, the
 * first persistent or transient format declared in the Service Provider metadata is used, and when the metadata says
 * nothing either, the configured default format is used. The unspecified format means the default format. Any other
 * format is reported back to the Service Provider as an invalid {@code NameIDPolicy}.
 * </p>
 * <p>
 * The {@code AllowCreate} flag of the {@code NameIDPolicy} is ignored, since all user IDs are known to the Identity
 * Provider.
 * </p>
 *
 * @author Martin Lindström
 */
public class DefaultNameIDGeneratorFactory extends AbstractSubjectIdentifierGeneratorFactory
    implements NameIDGeneratorFactory {

  /** The message code for the status message of an invalid {@code NameIDPolicy}. */
  public static final String INVALID_NAMEID_POLICY_MESSAGE_CODE = "authn-server.error.saml.invalid-nameid-policy";

  /** The default {@code NameID} format. */
  private String defaultFormat = NameID.PERSISTENT;

  /**
   * Constructor.
   *
   * @param idpEntityId the Identity Provider entityID, which becomes the {@code NameQualifier}
   */
  public DefaultNameIDGeneratorFactory(final @NonNull String idpEntityId) {
    super(idpEntityId);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull NameIDGenerator getNameIDGenerator(final @NonNull AuthnRequest authnRequest,
      final @NonNull EntityDescriptor peerMetadata) throws SamlErrorStatusException {

    final NameIDPolicy policy = authnRequest.getNameIDPolicy();

    final String spNameQualifier = Optional.ofNullable(policy)
        .map(NameIDPolicy::getSPNameQualifier)
        .filter(StringUtils::hasText)
        .orElseGet(peerMetadata::getEntityID);

    // The format asked for in the request comes first. Else, the preferred format of the Service Provider metadata.
    //
    final String format = Optional.ofNullable(policy)
        .map(NameIDPolicy::getFormat)
        .filter(StringUtils::hasText)
        .orElseGet(() -> this.getFormatFromMetadata(peerMetadata));

    return this.createNameIDGenerator(format, spNameQualifier);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getSupportedFormats() {
    return NameID.PERSISTENT.equals(this.defaultFormat)
        ? List.of(NameID.PERSISTENT, NameID.TRANSIENT)
        : List.of(NameID.TRANSIENT, NameID.PERSISTENT);
  }

  /**
   * Assigns the default {@code NameID} format, used when neither the request nor the Service Provider metadata asks for
   * a format. The default is {@value NameID#PERSISTENT}.
   *
   * @param format the {@code NameID} format
   */
  public void setDefaultFormat(final @NonNull String format) {
    if (!this.isSupported(format)) {
      throw new IllegalArgumentException("Unsupported NameID format - " + format);
    }
    this.defaultFormat = format;
  }

  /**
   * Creates the generator for the supplied format.
   *
   * @param format the requested {@code NameID} format, or {@code null} if no format was asked for
   * @param spNameQualifier the SP name qualifier
   * @return a {@link NameIDGenerator}
   * @throws SamlErrorStatusException if the format is not supported
   */
  protected @NonNull NameIDGenerator createNameIDGenerator(final @Nullable String format,
      final @NonNull String spNameQualifier) throws SamlErrorStatusException {

    final String nameIDFormat = format == null || NameID.UNSPECIFIED.equals(format)
        ? this.defaultFormat
        : format;

    if (NameID.PERSISTENT.equals(nameIDFormat)) {
      return this.configure(new PersistentNameIDGenerator(this.getIssuerQualifier(), spNameQualifier));
    }
    if (NameID.TRANSIENT.equals(nameIDFormat)) {
      return this.configure(new TransientNameIDGenerator(this.getIssuerQualifier(), spNameQualifier));
    }
    throw new SamlErrorStatusException(SamlErrorStatus.INVALID_NAMEID_POLICY, INVALID_NAMEID_POLICY_MESSAGE_CODE,
        "Unsupported NameID format requested - " + nameIDFormat);
  }

  /**
   * Predicate telling whether the supplied {@code NameID} format is supported.
   *
   * @param format the format to test
   * @return {@code true} if the format is supported and {@code false} otherwise
   */
  protected boolean isSupported(final @Nullable String format) {
    return NameID.PERSISTENT.equals(format) || NameID.TRANSIENT.equals(format);
  }

  /**
   * Gets the first persistent or transient format declared in the Service Provider metadata.
   *
   * @param peerMetadata the metadata of the Service Provider
   * @return the format, or {@code null} if the metadata declares no format that is supported
   */
  private @Nullable String getFormatFromMetadata(final @NonNull EntityDescriptor peerMetadata) {
    final SPSSODescriptor ssoDescriptor = peerMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (ssoDescriptor == null) {
      return null;
    }
    return ssoDescriptor.getNameIDFormats().stream()
        .map(NameIDFormat::getURI)
        .filter(this::isSupported)
        .findFirst()
        .orElse(null);
  }

}
