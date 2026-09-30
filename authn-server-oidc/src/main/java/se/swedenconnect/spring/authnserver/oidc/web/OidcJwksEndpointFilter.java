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

import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;

/**
 * A filter that publishes the JWKS of the OpenID Provider: the active and future signing keys and the active decryption
 * keys, without private key material.
 *
 * @author Martin Lindström
 */
public class OidcJwksEndpointFilter extends JsonDocumentEndpointFilter {

  /**
   * Constructor.
   *
   * @param keys the keys of the OpenID Provider
   * @param requestMatcher the request matcher for the JWKS endpoint
   */
  public OidcJwksEndpointFilter(final @Nonnull OidcKeys keys, final @Nonnull RequestMatcher requestMatcher) {
    super(requestMatcher, keys.getPublishedKeys().toString(true), "JWKS");
  }

}
