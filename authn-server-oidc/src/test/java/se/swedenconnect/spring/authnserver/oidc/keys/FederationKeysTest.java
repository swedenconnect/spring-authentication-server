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
package se.swedenconnect.spring.authnserver.oidc.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Tests for {@link FederationKey} and {@link FederationKeys}.
 *
 * @author Martin Lindström
 */
class FederationKeysTest {

  @Test
  void theAlgorithmFollowsTheKey() {
    assertThat(FederationKey.active(KeyTestSupport.rsa("fed-rsa", 2048)).getAlgorithm())
        .isEqualTo(JWSAlgorithm.RS256);
    assertThat(FederationKey.active(KeyTestSupport.ec("fed-p256", "secp256r1")).getAlgorithm())
        .isEqualTo(JWSAlgorithm.ES256);
    assertThat(FederationKey.active(KeyTestSupport.ec("fed-p384", "secp384r1")).getAlgorithm())
        .isEqualTo(JWSAlgorithm.ES384);
    assertThat(FederationKey.active(KeyTestSupport.ec("fed-p521", "secp521r1")).getAlgorithm())
        .isEqualTo(JWSAlgorithm.ES512);
  }

  @Test
  void weakKeysAreRejected() {
    assertThatThrownBy(() -> FederationKey.active(KeyTestSupport.rsa("fed-weak", 1024)))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("federation");
    assertThatThrownBy(() -> FederationKey.active(KeyTestSupport.ed25519("fed-ed")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void allKeysArePublishedAndTheFirstActiveKeySigns() throws Exception {
    final FederationKey future = FederationKey.future(KeyTestSupport.ec("fed-future", "secp256r1"));
    final FederationKey active = FederationKey.active(KeyTestSupport.ec("fed-active", "secp256r1"));
    final FederationKey second = FederationKey.active(KeyTestSupport.rsa("fed-second", 2048));
    final FederationKeys keys = new FederationKeys(List.of(future, active, second));

    assertThat(keys.getPublishedKeys().getKeys()).extracting(JWK::getKeyID)
        .containsExactly(future.getKeyId(), active.getKeyId(), second.getKeyId());
    assertThat(keys.getPublishedKeys().getKeys()).noneMatch(JWK::isPrivate);
    assertThat(keys.getSigningKey()).isSameAs(active);
    assertThat(keys.getKeyStates()).containsExactly(
        future.getKeyId() + ":FUTURE", active.getKeyId() + ":ACTIVE", second.getKeyId() + ":ACTIVE");

    final SignedJWT jwt = keys.getSigningKey().sign(new JWTClaimsSet.Builder().subject("x").build(),
        new JOSEObjectType("entity-statement+jwt"));
    assertThat(jwt.getHeader().getKeyID()).isEqualTo(active.getKeyId());
    assertThat(jwt.getHeader().getType().getType()).isEqualTo("entity-statement+jwt");
    assertThat(jwt.verify(new ECDSAVerifier(
        (ECKey) keys.getPublishedKeys().getKeyByKeyId(active.getKeyId())))).isTrue();
  }

  @Test
  void theRulesAreChecked() {
    assertThatThrownBy(() -> new FederationKeys(List.of()))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("No OpenID Federation keys");
    assertThatThrownBy(() -> new FederationKeys(
        List.of(FederationKey.future(KeyTestSupport.ec("fed-only-future", "secp256r1")))))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("active");
    assertThatThrownBy(() -> new FederationKeys(List.of(
        FederationKey.active(KeyTestSupport.ec("fed-dup", "secp256r1")),
        FederationKey.future(KeyTestSupport.ec("fed-dup", "secp256r1")))))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("key ID");
  }

}
