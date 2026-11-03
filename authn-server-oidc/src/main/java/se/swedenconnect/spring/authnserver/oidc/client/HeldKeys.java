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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * The keys of a client that were fetched from its {@code jwks_uri} or {@code signed_jwks_uri} when the client was
 * validated. They are kept with the client, in the cache entry of a federation client and in the
 * {@link ClientValidationStore} for other clients, so that a request does not cause a fetch.
 *
 * @param uri the URI that the keys were fetched from
 * @param signed whether the URI is a {@code signed_jwks_uri}
 * @param keys the public keys
 * @param entityKeys the client's Federation Entity Keys, that a signed JWK Set is verified with, or {@code null} when
 *     the keys come from a {@code jwks_uri}
 * @author Martin Lindström
 */
public record HeldKeys(@NonNull String uri, boolean signed, @NonNull JWKSet keys, @Nullable JWKSet entityKeys) {

  /**
   * Constructor.
   *
   * @param uri the URI that the keys were fetched from
   * @param signed whether the URI is a {@code signed_jwks_uri}
   * @param keys the public keys
   * @param entityKeys the client's Federation Entity Keys, or {@code null}
   */
  public HeldKeys {
    Objects.requireNonNull(uri, "uri must not be null");
    keys = Objects.requireNonNull(keys, "keys must not be null").toPublicJWKSet();
    if (entityKeys != null) {
      entityKeys = entityKeys.toPublicJWKSet();
    }
  }

  /**
   * Tells whether the keys come from a URI.
   *
   * @param uri the URI
   * @param signed whether the URI is a {@code signed_jwks_uri}
   * @return {@code true} if the keys were fetched from the URI and {@code false} otherwise
   */
  public boolean isFrom(final @NonNull String uri, final boolean signed) {
    return this.uri.equals(uri) && this.signed == signed;
  }

}
