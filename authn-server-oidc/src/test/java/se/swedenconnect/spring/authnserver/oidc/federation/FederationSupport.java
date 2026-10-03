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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationTrustMarkStatusRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FetchRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.SubordinateListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.trustmark.TrustMarkStatusResponse;
import se.swedenconnect.spring.authnserver.oidc.client.federation.EntityConfigurationEndpoints;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationClient;

/**
 * Support for the tests of the OpenID Provider's federation membership.
 *
 * @author Martin Lindström
 */
public final class FederationSupport {

  /** The entity identifier of the OpenID Provider of the tests. */
  public static final String ENTITY_ID = "https://op.example.com";

  /** The trust mark issuer of the tests. */
  public static final String ISSUER = "https://tmi.example.com";

  /** The trust mark endpoint of the issuer. */
  public static final URI ENDPOINT = URI.create("https://tmi.example.com/trust_mark");

  /** A trust mark type. */
  public static final String LOA3 = "https://id.swedenconnect.se/loa/loa3";

  /** Another trust mark type. */
  public static final String CONTRACT = "https://id.swedenconnect.se/contract/sc/eid-authorization-system";

  /**
   * Creates an EC key.
   *
   * @param keyId the key ID
   * @return the key
   */
  public static ECKey key(final String keyId) {
    try {
      return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates a trust mark.
   *
   * @param key the key to sign with
   * @param type the value of the {@code typ} header
   * @param issuer the issuer
   * @param subject the subject
   * @param trustMarkType the trust mark type
   * @param issuedAt when it was issued
   * @param expiresAt when it expires, or {@code null}
   * @return the trust mark
   */
  public static SignedJWT trustMark(final ECKey key, final String type, final String issuer, final String subject,
      final String trustMarkType, final Instant issuedAt, final Instant expiresAt) {
    try {
      final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
          .issuer(issuer)
          .subject(subject)
          .issueTime(Date.from(issuedAt))
          .claim("trust_mark_type", trustMarkType);
      if (expiresAt != null) {
        claims.expirationTime(Date.from(expiresAt));
      }
      final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
          .type(new JOSEObjectType(type)).keyID(key.getKeyID()).build(), claims.build());
      jwt.sign(new ECDSASigner(key));
      return jwt;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates a valid trust mark for the OpenID Provider.
   *
   * @param key the key to sign with
   * @param trustMarkType the trust mark type
   * @param issuedAt when it was issued
   * @param expiresAt when it expires, or {@code null}
   * @return the trust mark
   */
  public static SignedJWT trustMark(final ECKey key, final String trustMarkType, final Instant issuedAt,
      final Instant expiresAt) {
    return trustMark(key, "trust-mark+jwt", ISSUER, ENTITY_ID, trustMarkType, issuedAt, expiresAt);
  }

  /**
   * Creates an entity configuration.
   *
   * @param key the key to sign with
   * @param entityId the entity identifier, the issuer and subject
   * @param federationEntity the {@code federation_entity} metadata
   * @param expiresAt when it expires
   * @return the entity configuration
   */
  public static SignedJWT entityConfiguration(final ECKey key, final String entityId,
      final Map<String, Object> federationEntity, final Instant expiresAt) {
    try {
      final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
          .type(new JOSEObjectType(EntityConfigurationEndpoints.ENTITY_CONFIGURATION_TYPE))
          .keyID(key.getKeyID()).build(),
          new JWTClaimsSet.Builder()
              .issuer(entityId)
              .subject(entityId)
              .issueTime(new Date())
              .expirationTime(Date.from(expiresAt))
              .claim("metadata", Map.of("federation_entity", federationEntity))
              .build());
      jwt.sign(new ECDSASigner(key));
      return jwt;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates a trust mark source.
   *
   * @param trustMarkType the trust mark type
   * @param key the key of the issuer
   * @return the source
   */
  public static TrustMarkSource source(final String trustMarkType, final ECKey key) {
    return new TrustMarkSource(trustMarkType, ISSUER, ENDPOINT, new JWKSet(key.toPublicJWK()));
  }

  /**
   * A federation client whose trust mark call answers with what the test has put in it.
   */
  public static class StubFederationClient implements FederationClient {

    /** The answers, used in order; the last one is repeated. */
    public final List<Object> answers = new ArrayList<>();

    /** The trust mark requests made. */
    public final List<TrustMarkRequest> requests = new ArrayList<>();

    /** The trust mark endpoints of the requests made. */
    public final List<Object> endpoints = new ArrayList<>();

    /** The entity configuration that is answered, or {@code null} to fail as unreachable. */
    public SignedJWT entityConfiguration;

    /**
     * Adds an answer: a {@link SignedJWT}, {@code null} for nothing, or a {@link RuntimeException} to throw.
     *
     * @param answer the answer
     * @return this client
     */
    public StubFederationClient answer(final Object answer) {
      this.answers.add(answer);
      return this;
    }

    @Override
    public SignedJWT trustMark(final FederationRequest<TrustMarkRequest> request) {
      this.requests.add(request.parameters());
      this.endpoints.add(request.federationEntityMetadata().get(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT));
      if (this.answers.isEmpty()) {
        return null;
      }
      final Object answer = this.answers.size() > 1 ? this.answers.removeFirst() : this.answers.getFirst();
      if (answer instanceof final RuntimeException e) {
        throw e;
      }
      return (SignedJWT) answer;
    }

    @Override
    public SignedJWT resolve(final FederationRequest<ResolveRequest> request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SignedJWT entityConfiguration(final FederationRequest<EntityConfigurationRequest> request) {
      if (this.entityConfiguration == null) {
        throw new IllegalStateException("%s could not be reached".formatted(request.parameters().entityID()));
      }
      return this.entityConfiguration;
    }

    @Override
    public SignedJWT fetch(final FederationRequest<FetchRequest> request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<String> subordinateListing(final FederationRequest<SubordinateListingRequest> request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<String> trustMarkedListing(final FederationRequest<TrustMarkListingRequest> request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public TrustMarkStatusResponse trustMarkStatus(final FederationRequest<FederationTrustMarkStatusRequest> request) {
      throw new UnsupportedOperationException();
    }

  }

  /**
   * A clock that the test moves forward itself.
   */
  public static class TestClock extends Clock {

    /** The current time. */
    private Instant instant = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    /**
     * Moves the clock forward.
     *
     * @param duration how far to move it
     */
    public void advance(final Duration duration) {
      this.instant = this.instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return this.instant;
    }

  }

  // Hidden constructor
  private FederationSupport() {
  }

}
