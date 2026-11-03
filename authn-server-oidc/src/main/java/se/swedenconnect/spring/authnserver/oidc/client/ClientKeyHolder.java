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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * A client registry backend whose clients hold their keys, so that a request does not cause a fetch of a key that is
 * held. See {@link HeldKeysClientKeyResolver}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface ClientKeyHolder {

  /**
   * Finds the keys of a client that match a matcher.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param matcher the matcher
   * @return the matching keys, possibly empty, or {@code null} if the client is not one whose keys the backend holds
   */
  @Nullable List<JWK> resolveKeys(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull JWKMatcher matcher);

}
