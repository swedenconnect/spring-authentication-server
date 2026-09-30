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
package se.swedenconnect.spring.authnserver.oidc.scope;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.List;

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;

/**
 * An authentication provider that only declares what it supports.
 *
 * @param name the name
 * @param authnContextUris the authentication context URIs
 * @param attributes the attribute identifiers
 * @param scopes the scopes
 * @author Martin Lindström
 */
public record TestAuthenticationProvider(String name, List<String> authnContextUris, List<String> attributes,
    List<String> scopes) implements UserAuthenticationProvider {

  @Override
  public @Nonnull String getName() {
    return this.name;
  }

  @Override
  public @Nonnull List<String> getSupportedAuthnContextUris() {
    return this.authnContextUris;
  }

  @Override
  public @Nonnull List<String> getSupportedAttributes() {
    return this.attributes;
  }

  @Override
  public @Nonnull List<String> getSupportedScopes() {
    return this.scopes;
  }

  @Override
  public @Nullable Authentication authenticateUser(final @Nonnull UserAuthenticationInputToken token) {
    throw new UnsupportedOperationException();
  }

}
