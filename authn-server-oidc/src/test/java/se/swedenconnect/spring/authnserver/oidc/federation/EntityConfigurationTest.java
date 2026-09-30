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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKeys;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;

/**
 * Tests for {@link EntityConfigurationBuilder} and {@link EntityConfigurationContainer}.
 *
 * @author Martin Lindström
 */
class EntityConfigurationTest {

  private static final String ENTITY_ID = FederationSupport.ENTITY_ID;

  private static final String AUTHORITY = "https://intermediate.example.com";

  private static final FederationKey ACTIVE = FederationKey.active(KeyTestSupport.ec("ec-active", "secp256r1"));

  private static final FederationKey FUTURE = FederationKey.future(KeyTestSupport.ec("ec-future", "secp256r1"));

  private final AtomicReference<FederationKeys> keys = new AtomicReference<>(
      new FederationKeys(List.of(FUTURE, ACTIVE)));

  private final List<TrustMarkEntry> trustMarks = new ArrayList<>();

  private final FederationSupport.TestClock clock = new FederationSupport.TestClock();

  @Test
  void theEntityConfigurationHoldsTheClaimsAndIsSignedWithTheActiveKey() throws Exception {
    this.trustMarks.add(new TrustMarkEntry(FederationSupport.LOA3, "a.b.c"));
    final Instant now = this.clock.instant();

    final SignedJWT jwt = this.builder().build(now);

    assertThat(jwt.getHeader().getType().getType()).isEqualTo("entity-statement+jwt");
    assertThat(jwt.getHeader().getKeyID()).isEqualTo(ACTIVE.getKeyId());
    final JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertThat(claims.getIssuer()).isEqualTo(ENTITY_ID);
    assertThat(claims.getSubject()).isEqualTo(ENTITY_ID);
    assertThat(claims.getIssueTime().toInstant()).isEqualTo(now);
    assertThat(claims.getExpirationTime().toInstant()).isEqualTo(now.plus(Duration.ofDays(1)));
    assertThat(claims.getStringListClaim("authority_hints")).containsExactly(AUTHORITY);
    assertThat(claims.getListClaim("trust_marks"))
        .containsExactly(Map.of("trust_mark_type", FederationSupport.LOA3, "trust_mark", "a.b.c"));
    assertThat(claims.getJSONObjectClaim("metadata")).containsOnlyKeys("openid_provider");
    assertThat(claims.getJSONObjectClaim("metadata").get("openid_provider"))
        .isEqualTo(Map.of("issuer", ENTITY_ID));

    final JWKSet published = JWKSet.parse(claims.getJSONObjectClaim("jwks"));
    assertThat(published.getKeys()).hasSize(2).noneMatch(k -> k.isPrivate());
    assertThat(published.getKeyByKeyId(FUTURE.getKeyId())).isNotNull();
    assertThat(jwt.verify(new ECDSAVerifier((ECKey) published.getKeyByKeyId(ACTIVE.getKeyId())))).isTrue();
    assertThat(jwt.verify(new ECDSAVerifier((ECKey) published.getKeyByKeyId(FUTURE.getKeyId())))).isFalse();
  }

  @Test
  void withoutTrustMarksTheClaimIsLeftOut() throws Exception {
    assertThat(this.builder().build(this.clock.instant()).getJWTClaimsSet().getClaim("trust_marks")).isNull();
  }

  @Test
  void theAdditionalParametersAndTheCustomizerAreApplied() throws Exception {
    final EntityConfigurationBuilder builder = this.builder();
    builder.setAdditionalParameters(Map.of(
        "trust_anchor_hints", List.of("https://ta.example.com"),
        "metadata", Map.of("openid_provider", Map.of("federation_only", "yes"))));
    builder.setCustomizer(claims -> {
      @SuppressWarnings("unchecked")
      final Map<String, Object> op =
          (Map<String, Object>) ((Map<String, Object>) claims.get("metadata")).get("openid_provider");
      op.put("customized", true);
      claims.put("iss", "https://evil.example.com");
      claims.put("exp", 0);
    });

    final JWTClaimsSet claims = builder.build(this.clock.instant()).getJWTClaimsSet();

    assertThat(claims.getStringListClaim("trust_anchor_hints")).containsExactly("https://ta.example.com");
    assertThat(claims.getJSONObjectClaim("metadata").get("openid_provider"))
        .isEqualTo(Map.of("issuer", ENTITY_ID, "federation_only", "yes", "customized", true));
    assertThat(claims.getIssuer()).isEqualTo(ENTITY_ID);
    assertThat(claims.getExpirationTime()).isAfter(claims.getIssueTime());
  }

  @Test
  void federationEntityMetadataIsRejected() {
    final EntityConfigurationBuilder builder = this.builder();
    builder.setAdditionalParameters(Map.of("metadata", Map.of("federation_entity", Map.of("contacts", "x"))));
    assertThatThrownBy(() -> builder.build(this.clock.instant()))
        .isInstanceOf(IllegalStateException.class).hasMessageContaining("federation_entity");
  }

  @Test
  void authorityHintsAreRequired() {
    assertThatThrownBy(() -> new EntityConfigurationBuilder(ENTITY_ID, List.of(), this.keys::get,
        () -> this.trustMarks, Map.of(), Duration.ofDays(1)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new EntityConfigurationBuilder(ENTITY_ID, List.of(AUTHORITY), this.keys::get,
        () -> this.trustMarks, Map.of(), Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theEntityConfigurationIsServedFromTheCacheUntilThreeQuartersOfItsLifetimeHavePassed() {
    final EntityConfigurationContainer container = new EntityConfigurationContainer(this.builder(), this.clock);

    final SignedJWT first = container.getEntityConfiguration();
    this.clock.advance(Duration.ofHours(17));
    assertThat(container.getEntityConfiguration()).isSameAs(first);

    this.clock.advance(Duration.ofHours(1));
    final SignedJWT second = container.getEntityConfiguration();
    assertThat(second).isNotSameAs(first);
    assertThat(container.getEntityConfiguration()).isSameAs(second);
  }

  @Test
  void theEntityConfigurationIsRebuiltWhenATrustMarkChanges() throws Exception {
    final EntityConfigurationContainer container = new EntityConfigurationContainer(this.builder(), this.clock);
    final SignedJWT first = container.getEntityConfiguration();

    this.trustMarks.add(new TrustMarkEntry(FederationSupport.LOA3, "a.b.c"));
    final SignedJWT second = container.getEntityConfiguration();
    assertThat(second).isNotSameAs(first);
    assertThat(second.getJWTClaimsSet().getListClaim("trust_marks")).hasSize(1);

    this.trustMarks.set(0, new TrustMarkEntry(FederationSupport.LOA3, "d.e.f"));
    assertThat(container.getEntityConfiguration()).isNotSameAs(second);
  }

  @Test
  void theEntityConfigurationIsRebuiltWhenAKeyChangesState() {
    final EntityConfigurationContainer container = new EntityConfigurationContainer(this.builder(), this.clock);
    final SignedJWT first = container.getEntityConfiguration();
    assertThat(first.getHeader().getKeyID()).isEqualTo(ACTIVE.getKeyId());

    this.keys.set(new FederationKeys(List.of(FederationKey.active(KeyTestSupport.ec("ec-future", "secp256r1")))));
    final SignedJWT second = container.getEntityConfiguration();

    assertThat(second).isNotSameAs(first);
    assertThat(second.getHeader().getKeyID()).isEqualTo(FUTURE.getKeyId());
  }

  private EntityConfigurationBuilder builder() {
    return new EntityConfigurationBuilder(ENTITY_ID, List.of(AUTHORITY), this.keys::get,
        () -> List.copyOf(this.trustMarks), Map.of("issuer", ENTITY_ID), Duration.ofDays(1));
  }

}
