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
package se.swedenconnect.spring.authnserver.oidc.attributes.requested;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;

import se.oidc.nimbus.claims.OidcScopeValue;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.oidc.attributes.ClaimDeliveryTarget;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.attributes.RequestedClaim;
import se.swedenconnect.spring.authnserver.oidc.scope.DefaultScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry;

/**
 * Works out everything an OpenID Connect authentication request asks for, and gives it in the protocol-neutral form.
 * <p>
 * A requester asks for claims in two ways, by the scopes it requests and by the claims request parameter. The scopes
 * are expanded into the claims they stand for, the claims request parameter is merged in, and the result is mapped
 * into generic requested attributes by {@link OidcAttributeMapping}.
 * </p>
 * <p>
 * Where a claim is delivered follows Section 4.2 of the Swedish OpenID Connect Profile. A claim of the claims request
 * parameter is delivered where the parameter says, a claim of a scope where the scope definition says, and any other
 * claim from the UserInfo endpoint. When more than one source asks for the same claim the delivery targets are
 * combined, so a claim asked for in the ID token by the claims request parameter is also delivered from the UserInfo
 * endpoint when a requested scope covers it. The target is carried as protocol data, see {@link ClaimDeliveryTarget}.
 * </p>
 * <p>
 * A claim is essential if any source says so. Requested values are essential when the claims request entry that
 * carries them is, or when a requested scope marks the claim as essential. Claims that are not user attributes, such as {@code sub} and
 * {@code auth_time}, have no mapping and are left out.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcRequestedAttributeResolver {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcRequestedAttributeResolver.class);

  /** The mapping between claims and the generic attribute model. */
  private final OidcAttributeMapping attributeMapping;

  /** The scopes that the OpenID Provider knows about. */
  private final ScopeRegistry scopeRegistry;

  /**
   * Default constructor using the built-in attribute mapping and the built-in scopes.
   */
  public OidcRequestedAttributeResolver() {
    this(new OidcAttributeMapping(), new DefaultScopeRegistry());
  }

  /**
   * Constructor.
   *
   * @param attributeMapping the mapping between claims and the generic attribute model
   * @param scopeRegistry the scopes that the OpenID Provider knows about
   */
  public OidcRequestedAttributeResolver(final @NonNull OidcAttributeMapping attributeMapping,
      final @NonNull ScopeRegistry scopeRegistry) {
    this.attributeMapping = Objects.requireNonNull(attributeMapping, "attributeMapping must not be null");
    this.scopeRegistry = Objects.requireNonNull(scopeRegistry, "scopeRegistry must not be null");
  }

  /**
   * Works out what the request asks for.
   *
   * @param scope the requested scopes, may be {@code null}
   * @param claimsRequest the claims request parameter, may be {@code null}
   * @param logString the log string of the request
   * @return the generic requested attributes, possibly empty
   */
  public @NonNull List<GenericRequestedAttribute> resolve(final @Nullable Scope scope,
      final @Nullable OIDCClaimsRequest claimsRequest, final @NonNull String logString) {

    final List<GenericRequestedAttribute> attributes =
        this.attributeMapping.toGeneric(this.getRequestedClaims(scope, claimsRequest, logString));

    log.debug("Requested attributes: {} [{}]", attributes, logString);

    return attributes;
  }

  /**
   * Works out which claims the request asks for, before they are mapped into the generic form. A claim that more than
   * one source asks for appears once per source.
   *
   * @param scope the requested scopes, may be {@code null}
   * @param claimsRequest the claims request parameter, may be {@code null}
   * @param logString the log string of the request
   * @return the requested claims, possibly empty
   */
  public @NonNull List<RequestedClaim> getRequestedClaims(final @Nullable Scope scope,
      final @Nullable OIDCClaimsRequest claimsRequest, final @NonNull String logString) {

    final List<RequestedClaim> requestedClaims = new ArrayList<>();
    this.addScopeClaims(requestedClaims, scope, logString);
    addClaimsRequestEntries(requestedClaims, claimsRequest);
    return requestedClaims;
  }

  /**
   * Gets the registry of scopes. Use it to register scopes of your own.
   *
   * @return a {@link ScopeRegistry}
   */
  public @NonNull ScopeRegistry getScopeRegistry() {
    return this.scopeRegistry;
  }

  /**
   * Gets the mapping between claims and the generic attribute model. Use it to register mappers of your own.
   *
   * @return an {@link OidcAttributeMapping}
   */
  public @NonNull OidcAttributeMapping getAttributeMapping() {
    return this.attributeMapping;
  }

  /**
   * Expands the requested scopes into the claims they stand for.
   *
   * @param requestedClaims the list to add to
   * @param scope the requested scopes, may be {@code null}
   * @param logString the log string of the request
   */
  private void addScopeClaims(final @NonNull List<RequestedClaim> requestedClaims, final @Nullable Scope scope,
      final @NonNull String logString) {

    if (scope == null) {
      return;
    }
    for (final Scope.Value value : scope) {
      final OidcScopeValue scopeValue = this.scopeRegistry.getScope(value.getValue());
      if (scopeValue == null) {
        log.debug("Scope '{}' is not registered - no claims are requested by it [{}]", value.getValue(), logString);
        continue;
      }
      if (scopeValue.getClaimRequirements() == null) {
        continue;
      }
      for (final OidcScopeValue.ClaimRequirement requirement : scopeValue.getClaimRequirements()) {
        final ClaimDeliveryTarget target = ClaimDeliveryTarget.of(
            requirement.defaultIdTokenDelivery(), requirement.defaultUserInfoDelivery());
        ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry(requirement.name());
        if (requirement.essential()) {
          entry = entry.withClaimRequirement(ClaimRequirement.ESSENTIAL);
        }
        requestedClaims.add(new RequestedClaim(entry, target, true));
      }
    }
  }

  /**
   * Adds the entries of the claims request parameter, each with the delivery target of the section it was found in.
   *
   * @param requestedClaims the list to add to
   * @param claimsRequest the claims request parameter, may be {@code null}
   */
  private static void addClaimsRequestEntries(final @NonNull List<RequestedClaim> requestedClaims,
      final @Nullable OIDCClaimsRequest claimsRequest) {

    if (claimsRequest == null) {
      return;
    }
    addEntries(requestedClaims, claimsRequest.getIDTokenClaimsRequest(), ClaimDeliveryTarget.ID_TOKEN);
    addEntries(requestedClaims, claimsRequest.getUserInfoClaimsRequest(), ClaimDeliveryTarget.USER_INFO);
  }

  /**
   * Adds the entries of one section of the claims request parameter.
   *
   * @param requestedClaims the list to add to
   * @param claimsSetRequest the claims set request, may be {@code null}
   * @param target the delivery target
   */
  private static void addEntries(final @NonNull List<RequestedClaim> requestedClaims,
      final @Nullable ClaimsSetRequest claimsSetRequest, final @NonNull ClaimDeliveryTarget target) {

    if (claimsSetRequest == null) {
      return;
    }
    for (final ClaimsSetRequest.Entry entry : claimsSetRequest.getEntries()) {
      requestedClaims.add(new RequestedClaim(entry, target));
    }
  }

}
