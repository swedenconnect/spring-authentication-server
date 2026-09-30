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
package se.swedenconnect.spring.authnserver.oidc.web;

import jakarta.annotation.Nonnull;

import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * A filter that publishes the discovery document of the OpenID Provider, as described in OpenID Connect Discovery,
 * Section 4.
 *
 * @author Martin Lindström
 */
public class OidcDiscoveryEndpointFilter extends JsonDocumentEndpointFilter {

  /**
   * Constructor.
   *
   * @param metadata the OpenID Provider metadata
   * @param requestMatcher the request matcher for the discovery endpoint
   */
  public OidcDiscoveryEndpointFilter(final @Nonnull OIDCProviderMetadata metadata,
      final @Nonnull RequestMatcher requestMatcher) {
    super(requestMatcher, metadata.toJSONObject().toJSONString(), "discovery document");
  }

}
