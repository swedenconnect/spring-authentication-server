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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.NameID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGenerator;

/**
 * Base class for the {@link NameIDGenerator} implementations. It builds the {@code NameID} from the identifier that the
 * {@link AbstractSubjectIdentifierGenerator} computes, and assigns the name qualifiers.
 *
 * @author Martin Lindström
 */
public abstract class AbstractNameIDGenerator extends AbstractSubjectIdentifierGenerator
    implements NameIDGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractNameIDGenerator.class);

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   */
  protected AbstractNameIDGenerator(final @Nonnull String nameQualifier) {
    super(nameQualifier);
  }

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   * @param spNameQualifier the SP name qualifier, may be {@code null}
   */
  protected AbstractNameIDGenerator(final @Nonnull String nameQualifier, final @Nullable String spNameQualifier) {
    super(nameQualifier, spNameQualifier);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull NameID getNameID(final @Nonnull AuthenticatedUser user, final @Nonnull Requester requester)
      throws UnrecoverableErrorException {

    final NameID nameID = (NameID) XMLObjectSupport.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
    nameID.setValue(this.getSubjectIdentifier(user, requester));
    nameID.setFormat(this.getFormat());
    nameID.setNameQualifier(this.getNameQualifier());
    if (this.getSpNameQualifier() != null) {
      nameID.setSPNameQualifier(this.getSpNameQualifier());
    }
    log.debug("Generated NameID with Format '{}' [requester: '{}']", this.getFormat(), requester.identifier());

    return nameID;
  }

  /**
   * Gets the name qualifier, normally the IdP entityID.
   *
   * @return the name qualifier
   */
  protected @Nonnull String getNameQualifier() {
    return this.getIssuerQualifier();
  }

  /**
   * Gets the SP name qualifier.
   *
   * @return the SP name qualifier, or {@code null} if it is not assigned
   */
  protected @Nullable String getSpNameQualifier() {
    return this.getRequesterQualifier();
  }

}
