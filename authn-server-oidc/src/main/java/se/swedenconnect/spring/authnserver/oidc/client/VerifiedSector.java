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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;

/**
 * A successful check of the document at the {@code sector_identifier_uri} of a client: the document listed all the
 * redirect URIs. It is kept with the client's cache entry, so that the document is fetched again only when the
 * combination changes.
 *
 * @param sectorIdentifierUri the {@code sector_identifier_uri}
 * @param redirectUris the redirect URIs that the document listed
 * @author Martin Lindström
 */
public record VerifiedSector(@NonNull String sectorIdentifierUri, @NonNull Set<String> redirectUris) {

  /**
   * Constructor.
   *
   * @param sectorIdentifierUri the {@code sector_identifier_uri}
   * @param redirectUris the redirect URIs that the document listed
   */
  public VerifiedSector {
    Objects.requireNonNull(sectorIdentifierUri, "sectorIdentifierUri must not be null");
    redirectUris = Set.copyOf(Objects.requireNonNull(redirectUris, "redirectUris must not be null"));
  }

  /**
   * Tells whether the check covers a combination of {@code sector_identifier_uri} and redirect URIs.
   *
   * @param sectorIdentifierUri the {@code sector_identifier_uri}
   * @param redirectUris the redirect URIs
   * @return {@code true} if the check covers the combination and {@code false} otherwise
   */
  public boolean covers(final @NonNull String sectorIdentifierUri, final @NonNull Set<String> redirectUris) {
    return this.sectorIdentifierUri.equals(sectorIdentifierUri) && this.redirectUris.equals(redirectUris);
  }

}
