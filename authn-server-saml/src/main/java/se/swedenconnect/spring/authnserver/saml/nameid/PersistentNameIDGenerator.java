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

import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A {@link NameIDGenerator} that produces persistent {@code NameID}s. The value is stable for the same user and the
 * same Service Provider.
 *
 * @author Martin Lindström
 */
public class PersistentNameIDGenerator extends AbstractNameIDGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   */
  public PersistentNameIDGenerator(final @Nonnull String nameQualifier) {
    super(nameQualifier);
  }

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   * @param spNameQualifier the SP name qualifier, may be {@code null}
   */
  public PersistentNameIDGenerator(final @Nonnull String nameQualifier, final @Nullable String spNameQualifier) {
    super(nameQualifier, spNameQualifier);
  }

  /**
   * Returns {@value NameID#PERSISTENT}.
   */
  @Override
  public @Nonnull String getFormat() {
    return NameID.PERSISTENT;
  }

}
