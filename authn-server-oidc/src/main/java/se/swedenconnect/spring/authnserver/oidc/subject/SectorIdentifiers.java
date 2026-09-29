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
package se.swedenconnect.spring.authnserver.oidc.subject;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.nimbusds.openid.connect.sdk.id.SectorID;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;

/**
 * Works out the sector identifier of a client, as OpenID Connect Core, Section 8.1, describes it.
 * <p>
 * When the client has registered a {@code sector_identifier_uri}, the host component of that URI is the sector
 * identifier. Otherwise it is the host component of the client's redirect URI. A client whose redirect URIs have more
 * than one host must register a {@code sector_identifier_uri}, and a pairwise {@code sub} can not be produced for it
 * until it does. Falling back to another value, such as the {@code client_id}, is not an option: it would give the
 * client a {@code sub} that changes as soon as it registers the URI it should have registered from the start.
 * </p>
 *
 * @author Martin Lindström
 */
public final class SectorIdentifiers {

  /**
   * Works out the sector identifier of a client.
   *
   * @param sectorIdentifierUri the {@code sector_identifier_uri} of the client, or {@code null} if it has not
   *     registered one
   * @param redirectUris the redirect URIs of the client, used when there is no {@code sector_identifier_uri}
   * @return the sector identifier
   * @throws UnrecoverableErrorException if the client is registered in a way that leaves the sector identifier
   *     undetermined
   */
  public static @Nonnull SectorID resolve(final @Nullable URI sectorIdentifierUri,
      final @Nullable Collection<URI> redirectUris) throws UnrecoverableErrorException {

    if (sectorIdentifierUri != null) {
      return sectorId(sectorIdentifierUri, "sector_identifier_uri '%s' has no host component"
          .formatted(sectorIdentifierUri));
    }
    final List<String> hosts = (redirectUris != null ? redirectUris : List.<URI> of()).stream()
        .filter(Objects::nonNull)
        .map(URI::getHost)
        .filter(Objects::nonNull)
        .distinct()
        .toList();
    if (hosts.isEmpty()) {
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "Can not work out the sector identifier - the client has no redirect URI with a host component and no "
              + "sector_identifier_uri");
    }
    if (hosts.size() > 1) {
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "Can not work out the sector identifier - the redirect URIs of the client have %d different hosts, so it "
              + "must register a sector_identifier_uri".formatted(hosts.size()));
    }
    return new SectorID(hosts.getFirst());
  }

  /**
   * Creates the sector identifier from the host component of the supplied URI.
   *
   * @param uri the URI
   * @param message the message of the error to throw if the URI has no host component
   * @return the sector identifier
   * @throws UnrecoverableErrorException if the URI has no host component
   */
  private static @Nonnull SectorID sectorId(final @Nonnull URI uri, final @Nonnull String message)
      throws UnrecoverableErrorException {
    try {
      return new SectorID(uri);
    }
    catch (final IllegalArgumentException e) {
      throw new UnrecoverableErrorException(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION,
          "Can not work out the sector identifier - " + message, e);
    }
  }

  // Hidden constructor
  private SectorIdentifiers() {
  }

}
