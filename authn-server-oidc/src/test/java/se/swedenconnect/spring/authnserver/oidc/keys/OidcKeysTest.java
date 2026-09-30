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

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * Tests for {@link OidcKeys}.
 *
 * @author Martin Lindström
 */
class OidcKeysTest {

  private final SigningKey rsa = SigningKey.activeDefault(KeyTestSupport.rsa("rsa", 2048));

  private final SigningKey ec = SigningKey.active(KeyTestSupport.ec("ec", "secp256r1"));

  private final SigningKey future = SigningKey.future(KeyTestSupport.ec("future", "secp384r1"));

  private final DecryptionKey decryption = DecryptionKey.active(KeyTestSupport.rsa("enc", 2048));

  private final DecryptionKey previous = DecryptionKey.previous(KeyTestSupport.rsa("prev", 2048));

  @Test
  void theJwksHoldsTheActiveAndFutureSigningKeysAndTheActiveDecryptionKeys() {
    final OidcKeys keys =
        new OidcKeys(List.of(this.rsa, this.ec, this.future), List.of(this.decryption, this.previous));

    final JWKSet published = keys.getPublishedKeys();
    assertThat(published.getKeys()).extracting(JWK::getKeyID).containsExactly(this.rsa.getKeyId(),
        this.ec.getKeyId(), this.future.getKeyId(), this.decryption.getKeyId());
    assertThat(published.getKeys()).noneMatch(JWK::isPrivate);
    assertThat(published.getKeys()).allMatch(k -> k.getKeyUse() != null && k.getKeyID() != null);
  }

  @Test
  void aPreviousDecryptionKeyIsNotPublishedButStillDecrypts() {
    final OidcKeys keys = new OidcKeys(List.of(this.rsa), List.of(this.decryption, this.previous));

    assertThat(keys.getPublishedKeys().getKeyByKeyId(this.previous.getKeyId())).isNull();
    assertThat(keys.getDecryptionKeys()).containsExactly(this.decryption, this.previous);
    assertThat(keys.getDecryptionAlgorithms()).containsExactly(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP);
  }

  @Test
  void withOnlyAPreviousDecryptionKeyNoEncryptionAlgorithmIsOffered() {
    final OidcKeys keys = new OidcKeys(List.of(this.rsa), List.of(this.previous));

    assertThat(keys.getDecryptionAlgorithms()).isEmpty();
    assertThat(keys.getDecryptionKeys()).containsExactly(this.previous);
  }

  @Test
  void theSigningAlgorithmsAreThoseOfTheActiveKeysTheDefaultKeyFirst() {
    final OidcKeys keys = new OidcKeys(List.of(this.ec, this.future, this.rsa), null);

    assertThat(keys.getActiveSigningKeys()).containsExactly(this.rsa, this.ec);
    assertThat(keys.getSigningAlgorithms()).startsWith(JWSAlgorithm.RS256)
        .contains(JWSAlgorithm.ES256)
        .doesNotContain(JWSAlgorithm.ES384);
  }

  @Test
  void aSingleActiveKeyIsTheDefaultKey() {
    final SigningKey single = SigningKey.active(KeyTestSupport.ec("ec", "secp256r1"));
    final OidcKeys keys = new OidcKeys(List.of(single, this.future), List.of());

    assertThat(keys.getDefaultSigningKey()).isSameAs(single);
  }

  @Test
  void anActiveSigningKeyIsRequired() {
    assertThatThrownBy(() -> new OidcKeys(List.of(this.future), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("no active signing key");
  }

  @Test
  void severalActiveKeysNeedOneDefault() {
    assertThatThrownBy(() -> new OidcKeys(List.of(SigningKey.active(KeyTestSupport.rsa("rsa", 2048)), this.ec), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("none is marked as default");
  }

  @Test
  void onlyOneKeyMayBeTheDefault() {
    final SigningKey otherDefault = SigningKey.activeDefault(KeyTestSupport.ec("ec", "secp256r1"));

    assertThatThrownBy(() -> new OidcKeys(List.of(this.rsa, otherDefault), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Several OIDC signing keys are marked as default");
  }

  @Test
  void keyIdsMustBeUnique() {
    assertThatThrownBy(() -> new OidcKeys(
        List.of(this.rsa, SigningKey.future(KeyTestSupport.rsa("rsa", 2048))), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(this.rsa.getKeyId());
  }

}
