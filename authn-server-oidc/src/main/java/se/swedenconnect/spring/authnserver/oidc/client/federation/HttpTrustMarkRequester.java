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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * A {@link TrustMarkRequester} that asks the trust mark endpoint of the issuer, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.6">OpenID Federation 1.0, Section 8.6</a>.
 * <p>
 * A trust mark type that has no configured issuer is never asked for. A trust mark that is received is verified
 * before it is accepted: its type, its signature against the issuer's keys, that it was issued to the client, and
 * that it has not expired.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpTrustMarkRequester implements TrustMarkRequester {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(HttpTrustMarkRequester.class);

  /** The explicit type of a trust mark. */
  public static final String TRUST_MARK_TYPE = "trust-mark+jwt";

  /** The settings of the federation. */
  private final FederationSettings settings;

  /** The client making the call. */
  private final FederationClient federationClient;

  /**
   * Constructor using an {@link HttpFederationClient} with the default settings.
   *
   * @param settings the settings of the federation
   */
  public HttpTrustMarkRequester(final @NonNull FederationSettings settings) {
    this(settings, new HttpFederationClient());
  }

  /**
   * Constructor.
   *
   * @param settings the settings of the federation
   * @param federationClient the client making the call
   */
  public HttpTrustMarkRequester(
      final @NonNull FederationSettings settings, final @NonNull FederationClient federationClient) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable TrustMark request(final @NonNull String clientId, final @NonNull String trustMarkType)
      throws ClientRegistryException {

    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(trustMarkType, "trustMarkType must not be null");

    final FederationSettings.TrustMarkIssuer issuer = this.settings.getTrustMarkIssuer(trustMarkType);
    if (issuer == null) {
      log.debug("No trust mark issuer is configured for '{}' - it is not asked for", trustMarkType);
      return null;
    }
    final TrustMarkRequest request = new TrustMarkRequest(
        new EntityID(clientId), new EntityID(issuer.entityId()), new EntityID(trustMarkType));
    final SignedJWT response = this.federationClient.trustMark(new FederationRequest<>(request,
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, issuer.endpoint().toString())));

    if (response == null) {
      log.debug("The issuer {} has not issued a trust mark of type '{}' to '{}'",
          issuer.entityId(), trustMarkType, clientId);
      return null;
    }
    final JWTClaimsSet claims = FederationJwtVerifier.verify(response, TRUST_MARK_TYPE,
        this.settings.getTrustMarkIssuerKeys(issuer), issuer.entityId(), clientId, Set.of("iat", "trust_mark_type"));

    final String type;
    try {
      type = claims.getStringClaim("trust_mark_type");
    }
    catch (final java.text.ParseException e) {
      throw new ClientRegistryException(
          "The trust_mark_type claim of the trust mark for '%s' could not be read".formatted(clientId), e);
    }
    if (!trustMarkType.equals(type)) {
      throw new ClientRegistryException(
          "The issuer %s answered with a trust mark of type '%s' when '%s' was asked for".formatted(
              issuer.entityId(), type, trustMarkType));
    }
    log.debug("The issuer {} issued a trust mark of type '{}' to '{}'", issuer.entityId(), trustMarkType, clientId);
    return new TrustMark(trustMarkType,
        Optional.ofNullable(claims.getExpirationTime()).map(Date::toInstant).orElse(null));
  }

}
