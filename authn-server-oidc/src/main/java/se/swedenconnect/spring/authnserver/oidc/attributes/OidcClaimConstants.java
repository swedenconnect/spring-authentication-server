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
package se.swedenconnect.spring.authnserver.oidc.attributes;

/**
 * Claim names that are not available as constants from Nimbus or from the OIDC Sweden Nimbus extensions.
 * <p>
 * These are the claims of the {@value #SWEDEN_CONNECT_CLAIMS_PREFIX} namespace, defined by the OpenID Connect Claims
 * and Scopes Specification for Sweden Connect, and the {@code txn} claim of RFC 8417.
 * </p>
 * <p>
 * The claims of the {@code https://id.oidc.se/claim/} namespace are found in
 * {@link se.oidc.nimbus.claims.ClaimConstants} and the OpenID Connect standard claims in
 * {@link com.nimbusds.openid.connect.sdk.claims.PersonClaims}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcClaimConstants {

  /** The prefix for claims defined by Sweden Connect. */
  public static final String SWEDEN_CONNECT_CLAIMS_PREFIX = "https://id.swedenconnect.se/claim/";

  /** Provisional identifier issued by the Swedish eIDAS connector. */
  public static final String PRID_CLAIM_NAME = SWEDEN_CONNECT_CLAIMS_PREFIX + "prid";

  /** Expected persistence of the provisional identifier. */
  public static final String PRID_PERSISTENCE_CLAIM_NAME = SWEDEN_CONNECT_CLAIMS_PREFIX + "pridPersistence";

  /** A Swedish personal identity number obtained by binding an eIDAS identity to a Swedish identity. */
  public static final String MAPPED_PERSONAL_IDENTITY_NUMBER_CLAIM_NAME =
      SWEDEN_CONNECT_CLAIMS_PREFIX + "mappedPersonalIdentityNumber";

  /** A Swedish coordination number obtained by binding an eIDAS identity to a Swedish identity. */
  public static final String MAPPED_COORDINATION_NUMBER_CLAIM_NAME =
      SWEDEN_CONNECT_CLAIMS_PREFIX + "mappedCoordinationNumber";

  /** The binding processes used to obtain a mapped identity number. */
  public static final String IDENTITY_BINDING_CLAIM_NAME = SWEDEN_CONNECT_CLAIMS_PREFIX + "identityBinding";

  /** The eIDAS person identifier issued by the foreign eIDAS node. */
  public static final String EIDAS_PERSON_IDENTIFIER_CLAIM_NAME =
      SWEDEN_CONNECT_CLAIMS_PREFIX + "eidasPersonIdentifier";

  /** The eIDAS member state that provided the identity of the user. */
  public static final String EIDAS_COUNTRY_CLAIM_NAME = SWEDEN_CONNECT_CLAIMS_PREFIX + "eidasCountry";

  /** Transaction identifier, defined by RFC 8417. */
  public static final String TXN_CLAIM_NAME = "txn";

  // Hidden constructor
  private OidcClaimConstants() {
  }

}
