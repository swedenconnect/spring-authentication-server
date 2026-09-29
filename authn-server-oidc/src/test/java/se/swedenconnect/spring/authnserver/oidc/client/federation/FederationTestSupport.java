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

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

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

/**
 * Support for the OpenID Federation tests: keys, client metadata and the signed JWTs that the federation endpoints
 * answer with.
 *
 * @author Martin Lindström
 */
abstract class FederationTestSupport {

  /** The entity identifier of the trust anchor of the tests. */
  static final String TRUST_ANCHOR = "https://ta.example.com";

  /** The entity identifier of the resolver of the tests. */
  static final String RESOLVER = "https://resolver.example.com";

  /** The entity identifier of the trust mark issuer of the tests. */
  static final String TRUST_MARK_ISSUER = "https://tmi.example.com";

  /** The {@code client_id} of the client of the tests. */
  static final String CLIENT_ID = "https://client.example.com";

  /** A trust mark type. */
  static final String MARK_ONE = "https://example.com/mark-one";

  /** Another trust mark type. */
  static final String MARK_TWO = "https://example.com/mark-two";

  /**
   * Creates a key for signing.
   *
   * @param keyId the key identifier
   * @return an {@link ECKey}
   */
  static ECKey key(final String keyId) {
    try {
      return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates the JWK set holding the public part of the supplied keys.
   *
   * @param keys the keys
   * @return a {@link JWKSet}
   */
  static JWKSet publicKeys(final ECKey... keys) {
    return new JWKSet(List.of(keys).stream().map(ECKey::toPublicJWK).map(k -> (com.nimbusds.jose.jwk.JWK) k).toList());
  }

  /**
   * Creates client metadata with the supplied name.
   *
   * @param name the {@code client_name}
   * @return an {@link OIDCClientMetadata}
   */
  static OIDCClientMetadata clientMetadata(final String name) {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setName(name);
    metadata.setRedirectionURI(URI.create("https://client.example.com/callback"));
    return metadata;
  }

  /**
   * Creates a signed resolve response.
   *
   * @param key the key to sign with
   * @param issuer the entity identifier of the issuer
   * @param subject the entity identifier of the subject
   * @param metadata the resolved relying party metadata, or {@code null} to leave the entity type out
   * @param trustMarkTypes the trust mark types of the response
   * @param expiresAt when the resolution is no longer valid
   * @return a {@link SignedJWT}
   */
  static SignedJWT resolveResponse(final ECKey key, final String issuer, final String subject,
      final OIDCClientMetadata metadata, final Set<String> trustMarkTypes, final Instant expiresAt) {
    final Map<String, Object> resolved = metadata != null
        ? Map.of(EntityType.OPENID_RELYING_PARTY.getValue(), metadata.toJSONObject())
        : Map.of(EntityType.OPENID_PROVIDER.getValue(), Map.of("issuer", subject));
    final List<Object> trustMarks = new ArrayList<>();
    trustMarkTypes.forEach(type -> trustMarks.add(Map.of("trust_mark_type", type, "trust_mark", "a.b.c")));

    final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .issueTime(new Date())
        .expirationTime(Date.from(expiresAt))
        .claim("metadata", resolved);
    if (!trustMarks.isEmpty()) {
      claims.claim("trust_marks", trustMarks);
    }
    return sign(key, HttpFederationResolver.RESOLVE_RESPONSE_TYPE, claims.build());
  }

  /**
   * Creates a signed trust mark.
   *
   * @param key the key to sign with
   * @param issuer the entity identifier of the issuer
   * @param subject the entity identifier of the subject
   * @param type the trust mark type, which may be another one than what was asked for
   * @param expiresAt when the trust mark is no longer valid, or {@code null} if it does not expire
   * @return a {@link SignedJWT}
   */
  static SignedJWT trustMark(final ECKey key, final String issuer, final String subject, final String type,
      final Instant expiresAt) {
    final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(subject)
        .issueTime(new Date())
        .claim("trust_mark_type", type);
    if (expiresAt != null) {
      claims.expirationTime(Date.from(expiresAt));
    }
    return sign(key, HttpTrustMarkRequester.TRUST_MARK_TYPE, claims.build());
  }

  /**
   * Signs a JWT.
   *
   * @param key the key to sign with
   * @param type the value of the {@code typ} header
   * @param claims the claims of the JWT
   * @return a {@link SignedJWT}
   */
  static SignedJWT sign(final ECKey key, final String type, final JWTClaimsSet claims) {
    try {
      final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
          .type(new JOSEObjectType(type))
          .keyID(key.getKeyID())
          .build(), claims);
      jwt.sign(new ECDSASigner(key));
      return jwt;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }


  /**
   * A federation client that answers with what the test has put in it and records what it was asked.
   */
  static class StubFederationClient implements FederationClient {

    /** What the resolve call answers with, or {@code null} for nothing. */
    SignedJWT resolveResponse;

    /** What the trust mark call answers with, or {@code null} for nothing. */
    SignedJWT trustMarkResponse;

    /** The number of resolve calls made. */
    int resolveCalls;

    /** The number of trust mark calls made. */
    int trustMarkCalls;

    /** The last resolve request. */
    ResolveRequest lastResolveRequest;

    /** The last trust mark request. */
    TrustMarkRequest lastTrustMarkRequest;

    @Override
    public SignedJWT resolve(final FederationRequest<ResolveRequest> request) {
      this.resolveCalls++;
      this.lastResolveRequest = request.parameters();
      return this.resolveResponse;
    }

    @Override
    public SignedJWT trustMark(final FederationRequest<TrustMarkRequest> request) {
      this.trustMarkCalls++;
      this.lastTrustMarkRequest = request.parameters();
      return this.trustMarkResponse;
    }

    @Override
    public SignedJWT entityConfiguration(final FederationRequest<EntityConfigurationRequest> request) {
      throw new UnsupportedOperationException();
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
  static class TestClock extends Clock {

    /** The current time. */
    private Instant instant;

    /**
     * Constructor starting at the current time.
     */
    TestClock() {
      this(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    }

    /**
     * Constructor.
     *
     * @param instant the time to start at
     */
    TestClock(final Instant instant) {
      this.instant = instant;
    }

    /**
     * Moves the clock forward.
     *
     * @param duration how far to move it
     */
    void advance(final Duration duration) {
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

}
