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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.oidc.nimbus.claims.OidcScopeValue;

/**
 * The default {@link ScopeRegistry}, holding the built-in scopes unless told otherwise.
 *
 * @author Martin Lindström
 */
public class DefaultScopeRegistry implements ScopeRegistry {

  /** The scopes, keyed by their values. */
  private final Map<String, OidcScopeValue> scopes = new LinkedHashMap<>();

  /**
   * Default constructor registering the built-in scopes, see {@link BuiltInScopes}.
   */
  public DefaultScopeRegistry() {
    this(true);
  }

  /**
   * Constructor.
   *
   * @param registerBuiltInScopes whether to register the built-in scopes
   */
  public DefaultScopeRegistry(final boolean registerBuiltInScopes) {
    if (registerBuiltInScopes) {
      BuiltInScopes.getBuiltInScopes().forEach(this::register);
    }
  }

  /**
   * Constructor registering the supplied scopes and nothing else.
   *
   * @param scopes the scopes to register
   */
  public DefaultScopeRegistry(final @NonNull Collection<OidcScopeValue> scopes) {
    Objects.requireNonNull(scopes, "scopes must not be null").forEach(this::register);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable OidcScopeValue getScope(final @NonNull String value) {
    return this.scopes.get(Objects.requireNonNull(value, "value must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<OidcScopeValue> getScopes() {
    return Collections.unmodifiableCollection(this.scopes.values());
  }

  /** {@inheritDoc} */
  @Override
  public void register(final @NonNull OidcScopeValue scope) {
    Objects.requireNonNull(scope, "scope must not be null");
    this.scopes.put(scope.getValue(), scope);
  }

}
