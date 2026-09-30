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

import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.oidc.nimbus.claims.OidcScopeValue;

/**
 * A registry of the scopes that the OpenID Provider knows about.
 * <p>
 * A scope states which claims it asks for, whether each of them is essential, and where each of them is delivered by
 * default. The library ships the scopes of OpenID Connect Core and of the Swedish and Sweden Connect profiles, see
 * {@link BuiltInScopes}. An application that offers scopes of its own registers them here.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ScopeRegistry {

  /**
   * Gets the scope having the supplied value.
   *
   * @param value the scope value, for example {@code profile}
   * @return an {@link OidcScopeValue}, or {@code null} if no scope has been registered for the value
   */
  @Nullable OidcScopeValue getScope(final @NonNull String value);

  /**
   * Gets all registered scopes.
   *
   * @return all {@link OidcScopeValue}s
   */
  @NonNull Collection<OidcScopeValue> getScopes();

  /**
   * Registers a scope. A scope whose value is already registered replaces the previous one.
   *
   * @param scope the scope to register
   */
  void register(final @NonNull OidcScopeValue scope);

}
