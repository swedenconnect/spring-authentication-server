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

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkMetadataProperties;

/**
 * Tests for {@link SigningKey} and {@link DecryptionKey}.
 *
 * @author Martin Lindström
 */
class SigningAndDecryptionKeyTest {

  @Test
  void anRsaKeyProducesTheRsaAlgorithmsWithRs256Preferred() {
    final SigningKey key = SigningKey.active(KeyTestSupport.rsa("rsa", 2048));

    assertThat(key.getAlgorithms()).containsExactly(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
        JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);
    assertThat(key.getPreferredAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    assertThat(key.supports(JWSAlgorithm.ES256)).isFalse();
  }

  @Test
  void anEcKeyProducesTheAlgorithmOfItsCurve() {
    assertThat(SigningKey.active(KeyTestSupport.ec("ec", "secp256r1")).getAlgorithms())
        .containsExactly(JWSAlgorithm.ES256);
    assertThat(SigningKey.active(KeyTestSupport.ec("ec", "secp384r1")).getAlgorithms())
        .containsExactly(JWSAlgorithm.ES384);
    assertThat(SigningKey.active(KeyTestSupport.ec("ec", "secp521r1")).getAlgorithms())
        .containsExactly(JWSAlgorithm.ES512);
  }

  @Test
  void anAssignedAlgorithmRestrictsTheKey() {
    final PkiCredential credential = KeyTestSupport.rsa("rsa", 2048);
    JwkMetadataProperties.setJoseAlgorithm(credential.getMetadata(), "PS256");

    assertThat(SigningKey.active(credential).getAlgorithms()).containsExactly(JWSAlgorithm.PS256);
  }

  @Test
  void anAssignedAlgorithmThatTheKeyCannotProduceIsRejected() {
    final PkiCredential credential = KeyTestSupport.rsa("rsa", 2048);
    JwkMetadataProperties.setJoseAlgorithm(credential.getMetadata(), "ES256");

    assertThatThrownBy(() -> SigningKey.active(credential))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("ES256");
  }

  @Test
  void anRsaKeyOf2048BitsIsTheShortestAccepted() {
    assertThat(SigningKey.active(KeyTestSupport.rsa("rsa", 2048))).isNotNull();
    assertThatThrownBy(() -> SigningKey.active(KeyTestSupport.rsa("short", 2040)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("2040 bits")
        .hasMessageContaining("at least 2048");
    assertThatThrownBy(() -> DecryptionKey.active(KeyTestSupport.rsa("short", 1024)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("decryption");
  }

  @Test
  void aKeyThatIsNeitherRsaNorEcIsRejected() {
    assertThatThrownBy(() -> SigningKey.active(KeyTestSupport.ed25519("ed")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("RSA or EC is required");
  }

  @Test
  void aFutureKeyCannotBeTheDefaultKey() {
    assertThatThrownBy(() -> new SigningKey(KeyTestSupport.rsa("rsa", 2048), SigningKey.State.FUTURE, true))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not active");
  }

  @Test
  void theKeyIdIsTheThumbprintAndStaysTheSame() throws Exception {
    final SigningKey first = SigningKey.active(KeyTestSupport.rsa("rsa", 2048));
    final SigningKey second = SigningKey.future(KeyTestSupport.rsa("rsa", 2048));

    assertThat(first.getKeyId()).isEqualTo(second.getKeyId())
        .isEqualTo(first.getPublicJwk().computeThumbprint().toString());
  }

  @Test
  void theKeyIdOfTheCredentialMetadataIsUsed() {
    final PkiCredential credential = KeyTestSupport.rsa("rsa", 2048);
    credential.getMetadata().setKeyId("sign-2026");

    assertThat(SigningKey.active(credential).getKeyId()).isEqualTo("sign-2026");
  }

  @Test
  void theJwkIsPublicAndHasItsUse() {
    final SigningKey signing = SigningKey.active(KeyTestSupport.rsa("rsa", 2048));
    final DecryptionKey decryption = DecryptionKey.active(KeyTestSupport.ec("ec", "secp256r1"));

    assertThat(signing.getPublicJwk().isPrivate()).isFalse();
    assertThat(signing.getPublicJwk().getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
    assertThat(decryption.getPublicJwk().isPrivate()).isFalse();
    assertThat(decryption.getPublicJwk().getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
  }

  @Test
  void theDecryptionAlgorithmsFollowTheKeyType() {
    assertThat(DecryptionKey.active(KeyTestSupport.rsa("rsa", 2048)).getAlgorithms())
        .extracting(a -> a.getName())
        .containsExactly("RSA-OAEP-256", "RSA-OAEP");
    assertThat(DecryptionKey.previous(KeyTestSupport.ec("ec", "secp256r1")).getAlgorithms())
        .extracting(a -> a.getName())
        .containsExactly("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW");
  }

}
