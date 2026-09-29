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

import java.util.List;

import se.oidc.nimbus.claims.OidcScopeValue;
import se.oidc.nimbus.claims.OidcScopeValue.ClaimRequirement;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcClaimConstants;

/**
 * The scopes that the library knows about, and the ones that neither Nimbus nor the OIDC Sweden Nimbus extensions
 * define.
 * <p>
 * The scopes of OpenID Connect Core are found in {@link OidcScopeValue} and the scopes of the Claims and Scopes
 * Specification for the Swedish OpenID Connect Profile in {@link ScopeConstants}.
 * </p>
 *
 * @author Martin Lindström
 */
public class BuiltInScopes {

  /** The prefix for scopes defined by Sweden Connect. */
  public static final String SWEDEN_CONNECT_SCOPE_PREFIX = "https://id.swedenconnect.se/scope/";

  /**
   * The signature approval scope of the Signature Extension for OpenID Connect. It tells the OpenID Provider that the
   * request is a request for signature approval, and asks for no claims of its own.
   */
  public static final OidcScopeValue SIGN_APPROVAL =
      new OidcScopeValue("https://id.oidc.se/scope/signApproval", null);

  /**
   * The eIDAS natural person identity scope of the OpenID Connect Claims and Scopes Specification for Sweden Connect.
   */
  public static final OidcScopeValue EIDAS_NATURAL_PERSON_IDENTITY =
      new OidcScopeValue(SWEDEN_CONNECT_SCOPE_PREFIX + "eidasNaturalPersonIdentity", new ClaimRequirement[] {
          ClaimRequirement.of(OidcClaimConstants.PRID_CLAIM_NAME, true, true, true),
          ClaimRequirement.of(OidcClaimConstants.PRID_PERSISTENCE_CLAIM_NAME, true, true, true),
          ClaimRequirement.of(OidcClaimConstants.EIDAS_PERSON_IDENTIFIER_CLAIM_NAME, true, false, true) });

  /**
   * The scope asking for the Swedish identity that the Identity Binding Service holds for a user authenticated
   * through eIDAS, defined by the OpenID Connect Claims and Scopes Specification for Sweden Connect.
   */
  public static final OidcScopeValue EIDAS_SWEDISH_IDENTITY =
      new OidcScopeValue(SWEDEN_CONNECT_SCOPE_PREFIX + "eidasSwedishIdentity", new ClaimRequirement[] {
          ClaimRequirement.of(OidcClaimConstants.MAPPED_PERSONAL_IDENTITY_NUMBER_CLAIM_NAME),
          ClaimRequirement.of(OidcClaimConstants.MAPPED_COORDINATION_NUMBER_CLAIM_NAME),
          ClaimRequirement.of(OidcClaimConstants.IDENTITY_BINDING_CLAIM_NAME) });

  /**
   * Gets the built-in scopes: the scopes of OpenID Connect Core, of the Swedish OpenID Connect Profile, of the
   * Signature Extension for OpenID Connect and of the OpenID Connect Claims and Scopes Specification for Sweden
   * Connect.
   *
   * @return the built-in scopes
   */
  public static @Nonnull List<OidcScopeValue> getBuiltInScopes() {
    return List.of(
        OidcScopeValue.OPENID,
        OidcScopeValue.PROFILE,
        OidcScopeValue.EMAIL,
        OidcScopeValue.ADDRESS,
        OidcScopeValue.PHONE,
        ScopeConstants.NATURAL_PERSON_INFO,
        ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER,
        ScopeConstants.NATURAL_PERSON_ORGANIZATIONAL_IDENTITY,
        ScopeConstants.SIGN,
        SIGN_APPROVAL,
        EIDAS_NATURAL_PERSON_IDENTITY,
        EIDAS_SWEDISH_IDENTITY);
  }

  // Hidden constructor
  private BuiltInScopes() {
  }

}
