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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;

/**
 * A {@link ClientKeyResolver} that gives the keys that clients hold, see {@link ClientKeyHolder}, so that a request
 * does not cause a fetch of a key that is held. The backends are asked in the order of the client registry, and the
 * first that holds the client answers. A client of a backend that holds no keys, such as a backend of the
 * application's own, gets its keys from another resolver.
 *
 * @author Martin Lindström
 */
public class HeldKeysClientKeyResolver implements ClientKeyResolver {

  /** The backends whose clients hold keys. */
  private final List<ClientKeyHolder> holders;

  /** The resolver for other clients. */
  private final ClientKeyResolver delegate;

  /**
   * Constructor.
   *
   * @param holders the backends whose clients hold keys, in the order of the client registry
   * @param delegate the resolver for other clients
   */
  public HeldKeysClientKeyResolver(final @NonNull List<? extends ClientKeyHolder> holders,
      final @NonNull ClientKeyResolver delegate) {
    this.holders = List.copyOf(Objects.requireNonNull(holders, "holders must not be null"));
    this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<JWK> resolve(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher) throws KeySourceException {
    for (final ClientKeyHolder holder : this.holders) {
      final List<JWK> keys = holder.resolveKeys(clientId, metadata, matcher);
      if (keys != null) {
        return keys;
      }
    }
    return this.delegate.resolve(clientId, metadata, matcher);
  }

  /**
   * Gets the resolver for other clients.
   *
   * @return the resolver
   */
  public @NonNull ClientKeyResolver getDelegate() {
    return this.delegate;
  }

}
