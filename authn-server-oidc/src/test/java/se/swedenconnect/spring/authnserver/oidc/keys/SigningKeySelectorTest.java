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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;

import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector.SelectedSigningKey;

/**
 * Tests for {@link SigningKeySelector}.
 *
 * @author Martin Lindström
 */
class SigningKeySelectorTest {

  /** The default key, RSA. */
  private final SigningKey rsa = SigningKey.activeDefault(KeyTestSupport.rsa("rsa", 2048));

  /** Another active key, EC P-256. */
  private final SigningKey ec = SigningKey.active(KeyTestSupport.ec("ec", "secp256r1"));

  /** A future key, EC P-384. */
  private final SigningKey future = SigningKey.future(KeyTestSupport.ec("future", "secp384r1"));

  private final SigningKeySelector selector =
      new SigningKeySelector(new OidcKeys(List.of(this.ec, this.future, this.rsa), null));

  @Test
  void aClientDeclaringNothingGetsTheDefaultKeyAndItsPreferredAlgorithm() {
    final SelectedSigningKey selected = this.selector.select(null, null);

    assertThat(selected.key()).isSameAs(this.rsa);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.RS256);
  }

  @Test
  void theRegistrationDefaultIsNotAppliedForAnEcDefaultKey() {
    final SigningKey ecDefault = SigningKey.activeDefault(KeyTestSupport.ec("ec", "secp256r1"));
    final SigningKeySelector ecSelector = new SigningKeySelector(new OidcKeys(List.of(this.rsa(), ecDefault), null));

    final SelectedSigningKey selected = ecSelector.selectForIdToken(new OIDCClientMetadata());

    assertThat(selected.key()).isSameAs(ecDefault);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.ES256);
  }

  @Test
  void aDeclaredAlgorithmPrefersTheDefaultKey() {
    final SelectedSigningKey selected = this.selector.select(JWSAlgorithm.PS384, null);

    assertThat(selected.key()).isSameAs(this.rsa);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.PS384);
  }

  @Test
  void aDeclaredAlgorithmThatOnlyAnotherKeyProducesGivesThatKey() {
    final SelectedSigningKey selected = this.selector.select(JWSAlgorithm.ES256, null);

    assertThat(selected.key()).isSameAs(this.ec);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.ES256);
  }

  @Test
  void aDeclaredAlgorithmWinsOverTheList() {
    final SelectedSigningKey selected = this.selector.select(JWSAlgorithm.ES256, List.of(JWSAlgorithm.RS256));

    assertThat(selected.key()).isSameAs(this.ec);
  }

  @Test
  void aListGivesTheDefaultKeyWhenItCanProduceOneOfTheAlgorithms() {
    final SelectedSigningKey selected =
        this.selector.select(null, List.of(JWSAlgorithm.ES256, JWSAlgorithm.RS512, JWSAlgorithm.PS256));

    assertThat(selected.key()).isSameAs(this.rsa);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.RS512);
  }

  @Test
  void aListGivesAnotherActiveKeyWhenTheDefaultKeyCannot() {
    final SelectedSigningKey selected = this.selector.select(null, List.of(JWSAlgorithm.ES512, JWSAlgorithm.ES256));

    assertThat(selected.key()).isSameAs(this.ec);
    assertThat(selected.algorithm()).isEqualTo(JWSAlgorithm.ES256);
  }

  @Test
  void aFutureKeyIsNeverUsed() {
    assertThatThrownBy(() -> this.selector.select(JWSAlgorithm.ES384, null))
        .isInstanceOfSatisfying(UnrecoverableErrorException.class,
            e -> assertThat(e.getError()).isEqualTo(OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION))
        .hasMessageContaining("ES384");
    assertThatThrownBy(() -> this.selector.select(null, List.of(JWSAlgorithm.ES384)))
        .isInstanceOf(UnrecoverableErrorException.class)
        .hasMessageContaining("ES384");
  }

  @Test
  void anEmptyListAcceptsNothing() {
    assertThatThrownBy(() -> this.selector.select(null, List.of()))
        .isInstanceOf(UnrecoverableErrorException.class);
  }

  @Test
  void theIdTokenParametersOfTheClientMetadataAreUsed() throws Exception {
    final OIDCClientMetadata single = OIDCClientMetadata.parse(new JSONObject(JSONObjectUtils.parse(
        "{\"id_token_signed_response_alg\":\"ES256\",\"userinfo_signed_response_alg\":\"PS256\"}")));
    assertThat(this.selector.selectForIdToken(single).algorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(this.selector.selectForUserInfo(single).algorithm()).isEqualTo(JWSAlgorithm.PS256);

    final OIDCClientMetadata list = OIDCClientMetadata.parse(new JSONObject(JSONObjectUtils.parse(
        "{\"id_token_signing_alg_values_supported\":[\"none\",\"ES256\"],"
            + "\"userinfo_signing_alg_values_supported\":[\"ES512\",\"RS384\"]}")));
    assertThat(this.selector.selectForIdToken(list).key()).isSameAs(this.ec);
    assertThat(this.selector.selectForUserInfo(list).algorithm()).isEqualTo(JWSAlgorithm.RS384);
  }

  @Test
  void aListHoldingOnlyNoneAcceptsNothing() throws Exception {
    final OIDCClientMetadata client = OIDCClientMetadata.parse(new JSONObject(JSONObjectUtils.parse(
        "{\"id_token_signing_alg_values_supported\":[\"none\"]}")));

    assertThatThrownBy(() -> this.selector.selectForIdToken(client)).isInstanceOf(UnrecoverableErrorException.class);
  }

  private SigningKey rsa() {
    return SigningKey.active(KeyTestSupport.rsa("rsa", 2048));
  }

}
