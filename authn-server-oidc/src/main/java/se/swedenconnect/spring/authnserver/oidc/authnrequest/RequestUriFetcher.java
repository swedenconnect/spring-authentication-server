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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import java.io.IOException;
import java.net.URI;

import org.jspecify.annotations.NonNull;

/**
 * Fetches a request object from a {@code request_uri}. It is only asked for URIs that the client has registered.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface RequestUriFetcher {

  /**
   * Fetches the request object.
   *
   * @param requestUri the URI, without any fragment
   * @return the request object, a JWT
   * @throws IOException if the request object cannot be fetched
   */
  @NonNull String fetch(final @NonNull URI requestUri) throws IOException;

}
