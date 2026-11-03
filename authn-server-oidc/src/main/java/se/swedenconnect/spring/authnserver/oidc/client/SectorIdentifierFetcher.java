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

import java.io.IOException;
import java.net.URI;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Fetches the document at the {@code sector_identifier_uri} of a client, which is a JSON array of redirect URIs, see
 * <a href="https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation">OpenID Connect
 * Dynamic Client Registration 1.0, Section 5</a>.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface SectorIdentifierFetcher {

  /**
   * Fetches the document at a {@code sector_identifier_uri}.
   *
   * @param sectorIdentifierUri the URI
   * @return the strings of the JSON array, or {@code null} if the document was fetched and is JSON, but not an array
   *     of strings
   * @throws IOException if the document cannot be fetched: the host cannot be reached, the answer is not a 2xx answer,
   *     or the body cannot be read as JSON
   */
  @Nullable List<String> fetch(final @NonNull URI sectorIdentifierUri) throws IOException;

}
