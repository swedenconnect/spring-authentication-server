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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import se.oidc.nimbus.claims.ClaimConstants;
import se.oidc.nimbus.claims.OidcScopeValue;
import se.oidc.nimbus.claims.OidcScopeValue.ClaimRequirement;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;

/**
 * The scopes that the OpenID Provider offers and the claims that it supports, worked out from the authentication
 * providers.
 * <p>
 * The claims of a provider are its {@link UserAuthenticationProvider#getSupportedAttributes() attributes} mapped to
 * claims. The scopes of a provider are the {@link UserAuthenticationProvider#getSupportedScopes() scopes it declares}.
 * When it declares none, they are derived from its claims, the configured claims and the {@link #PROTOCOL_CLAIMS}: a
 * scope of the {@link ScopeRegistry} is offered when all its essential claims are among them. A scope that has no
 * essential claims is offered when at least one of its claims is among them, and a scope without claims is only
 * offered when it is declared or configured. The {@link #EXPLICIT_SCOPES}, the sign and sign approval scopes, are
 * never derived.
 * </p>
 * <p>
 * The OpenID Provider offers the union over all providers, or the configured scopes when they are set. The
 * {@code openid} scope is always offered. The supported claims are the {@link #PROTOCOL_CLAIMS}, the claims of the
 * providers and the configured claims. The claims of the offered scopes are not added, so an offered scope may have
 * claims that are not supported. A claim that the providers do not deliver, but that should be published, is
 * configured.
 * </p>
 * <p>
 * A warning is logged when an offered scope has claims and none of them is supported, and when the sign scope is
 * offered and the user signature claim is not supported.
 * </p>
 *
 * @param scopes the offered scopes
 * @param claims the supported claims
 * @author Martin Lindström
 */
public record SupportedScopesAndClaims(@NonNull List<String> scopes, @NonNull List<String> claims) {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SupportedScopesAndClaims.class);

  /**
   * The claims that the OpenID Provider itself puts in every ID token and that a relying party may request,
   * {@code sub}, {@code auth_time} and {@code acr}. They are always supported, and count as available when scopes are
   * derived.
   */
  public static final List<String> PROTOCOL_CLAIMS = List.of(IDTokenClaimsSet.SUB_CLAIM_NAME,
      IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME, IDTokenClaimsSet.ACR_CLAIM_NAME);

  /**
   * The scopes that are never derived, but only offered when a provider declares them or they are configured: the
   * sign scope and the sign approval scope of the Signature Extension for OpenID Connect.
   */
  public static final List<String> EXPLICIT_SCOPES =
      List.of(ScopeConstants.SIGN.getValue(), ScopeConstants.SIGN_APPROVAL.getValue());

  /**
   * Constructor.
   *
   * @param scopes the offered scopes
   * @param claims the supported claims
   */
  public SupportedScopesAndClaims {
    scopes = List.copyOf(Objects.requireNonNull(scopes, "scopes must not be null"));
    claims = List.copyOf(Objects.requireNonNull(claims, "claims must not be null"));
  }

  /**
   * Works out the offered scopes and the supported claims.
   *
   * @param providers the authentication providers
   * @param attributeMapping the attribute mapping, giving the claims of the providers
   * @param scopeRegistry the scope registry
   * @param configuredScopes the configured scopes, which replace the derived ones, or {@code null}
   * @param configuredClaims the configured claims, which are added to those of the providers, or {@code null}
   * @return the scopes and claims
   * @throws IllegalArgumentException if a declared or configured scope is not in the scope registry
   */
  public static @NonNull SupportedScopesAndClaims resolve(
      final @NonNull Collection<? extends UserAuthenticationProvider> providers,
      final @NonNull OidcAttributeMapping attributeMapping, final @NonNull ScopeRegistry scopeRegistry,
      final @Nullable List<String> configuredScopes, final @Nullable List<String> configuredClaims) {

    final List<String> addedClaims = configuredClaims != null ? configuredClaims : List.of();

    final Set<String> claims = new LinkedHashSet<>(PROTOCOL_CLAIMS);
    final Set<String> derivedScopes = new LinkedHashSet<>();
    derivedScopes.add(OidcScopeValue.OPENID.getValue());

    for (final UserAuthenticationProvider provider : providers) {
      final List<String> providerClaims = attributeMapping.getClaimNames(provider.getSupportedAttributes());
      claims.addAll(providerClaims);

      if (!provider.getSupportedScopes().isEmpty()) {
        for (final String scope : provider.getSupportedScopes()) {
          getScope(scopeRegistry, scope, "declared by the authentication provider " + provider.getName());
          derivedScopes.add(scope);
        }
      }
      else {
        final Set<String> available = new LinkedHashSet<>(providerClaims);
        available.addAll(addedClaims);
        available.addAll(PROTOCOL_CLAIMS);
        for (final OidcScopeValue scope : scopeRegistry.getScopes()) {
          if (!EXPLICIT_SCOPES.contains(scope.getValue()) && isOffered(scope, available)) {
            derivedScopes.add(scope.getValue());
          }
        }
      }
    }
    claims.addAll(addedClaims);

    final Set<String> scopes;
    if (configuredScopes != null) {
      scopes = new LinkedHashSet<>();
      scopes.add(OidcScopeValue.OPENID.getValue());
      for (final String scope : configuredScopes) {
        getScope(scopeRegistry, scope, "configured for the OpenID Provider");
        scopes.add(scope);
      }
    }
    else {
      scopes = derivedScopes;
    }

    for (final String scope : scopes) {
      checkDeliverable(scopeRegistry.getScope(scope), claims);
    }

    return new SupportedScopesAndClaims(List.copyOf(scopes), List.copyOf(claims));
  }

  /**
   * Logs a warning if an offered scope cannot be delivered: a scope that has claims, none of which is supported, or
   * the sign scope without the user signature claim.
   *
   * @param scope the offered scope
   * @param claims the supported claims
   */
  private static void checkDeliverable(final @Nullable OidcScopeValue scope, final @NonNull Set<String> claims) {
    if (scope == null) {
      return;
    }
    final Set<ClaimRequirement> requirements = scope.getClaimRequirements();
    if (requirements != null && !requirements.isEmpty()
        && requirements.stream().noneMatch(r -> claims.contains(r.name()))) {
      log.warn("The scope '{}' is offered, but none of its claims {} is supported",
          scope.getValue(), requirements.stream().map(ClaimRequirement::name).toList());
    }
    if (ScopeConstants.SIGN.getValue().equals(scope.getValue())
        && !claims.contains(ClaimConstants.USER_SIGNATURE_CLAIM_NAME)) {
      log.warn("The scope '{}' is offered, but the claim '{}' is not supported, so no user signature can be delivered",
          scope.getValue(), ClaimConstants.USER_SIGNATURE_CLAIM_NAME);
    }
  }

  /**
   * Tells whether a scope is offered for a set of available claims.
   *
   * @param scope the scope
   * @param available the available claims
   * @return {@code true} if the scope is offered and {@code false} otherwise
   */
  private static boolean isOffered(final @NonNull OidcScopeValue scope, final @NonNull Set<String> available) {
    final Set<ClaimRequirement> requirements = scope.getClaimRequirements();
    if (requirements == null || requirements.isEmpty()) {
      return false;
    }
    final List<ClaimRequirement> essential = requirements.stream().filter(ClaimRequirement::essential).toList();
    if (essential.isEmpty()) {
      return requirements.stream().anyMatch(r -> available.contains(r.name()));
    }
    return essential.stream().allMatch(r -> available.contains(r.name()));
  }

  /**
   * Gets a scope from the registry.
   *
   * @param registry the scope registry
   * @param value the scope value
   * @param origin where the scope comes from, for the error message
   * @return the scope
   * @throws IllegalArgumentException if the scope is not registered
   */
  private static @NonNull OidcScopeValue getScope(final @NonNull ScopeRegistry registry, final @NonNull String value,
      final @NonNull String origin) {
    final OidcScopeValue scope = registry.getScope(value);
    if (scope == null) {
      throw new IllegalArgumentException("The scope '%s' %s is not in the scope registry".formatted(value, origin));
    }
    return scope;
  }

}
