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

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * A {@link NameIDGenerator} that produces transient {@code NameID}s. The value is random, and a new one is produced
 * every time.
 *
 * @author Martin Lindström
 */
public class TransientNameIDGenerator extends AbstractNameIDGenerator {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   */
  public TransientNameIDGenerator(final @NonNull String nameQualifier) {
    super(nameQualifier);
  }

  /**
   * Constructor.
   *
   * @param nameQualifier the name qualifier, normally the IdP entityID
   * @param spNameQualifier the SP name qualifier, may be {@code null}
   */
  public TransientNameIDGenerator(final @NonNull String nameQualifier, final @Nullable String spNameQualifier) {
    super(nameQualifier, spNameQualifier);
  }

  /**
   * Returns a new random identifier. The user and the requester are not used.
   */
  @Override
  public @NonNull String getSubjectIdentifier(final @NonNull AuthenticatedUser user,
      final @NonNull Requester requester) {
    return Base64.getEncoder()
        .encodeToString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Returns {@value NameID#TRANSIENT}.
   */
  @Override
  public @NonNull String getFormat() {
    return NameID.TRANSIENT;
  }

}
