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

import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * The default {@link ClientKeyResolver}. It uses the keys of the client metadata: {@code jwks} when present, and
 * otherwise the keys published at {@code jwks_uri}, which are fetched and cached.
 *
 * @author Martin Lindström
 */
public class DefaultClientKeyResolver implements ClientKeyResolver {

  /** The key sources for {@code jwks_uri}, by URI. */
  private final Map<URI, JWKSource<SecurityContext>> remoteSources = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public @NonNull List<JWK> resolve(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWSHeader header) throws KeySourceException {

    final JWKSelector selector = new JWKSelector(JWKMatcher.forJWSHeader(header));
    if (metadata.getJWKSet() != null) {
      return selector.select(metadata.getJWKSet());
    }
    if (metadata.getJWKSetURI() != null) {
      return this.getRemoteSource(metadata.getJWKSetURI()).get(selector, null);
    }
    return List.of();
  }

  /**
   * Gets the key source for a {@code jwks_uri}, creating it the first time.
   *
   * @param jwksUri the URI
   * @return the key source
   * @throws KeySourceException for an invalid URI
   */
  private @NonNull JWKSource<SecurityContext> getRemoteSource(final @NonNull URI jwksUri) throws KeySourceException {
    try {
      final JWKSource<SecurityContext> source = this.remoteSources.get(jwksUri);
      if (source != null) {
        return source;
      }
      final JWKSource<SecurityContext> created = JWKSourceBuilder.create(jwksUri.toURL()).build();
      final JWKSource<SecurityContext> existing = this.remoteSources.putIfAbsent(jwksUri, created);
      return existing != null ? existing : created;
    }
    catch (final MalformedURLException | IllegalArgumentException e) {
      throw new KeySourceException("Invalid jwks_uri - " + e.getMessage(), e);
    }
  }

}
