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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.ECKey;

import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link HttpTrustMarkRequester}.
 *
 * @author Martin Lindström
 */
class HttpTrustMarkRequesterTest extends FederationTestSupport {

  private static final URI RESOLVE_ENDPOINT = URI.create("https://resolver.example.com/resolve");

  private static final URI TRUST_MARK_ENDPOINT = URI.create("https://tmi.example.com/trust_mark");

  @Test
  void aVerifiedTrustMarkIsAccepted() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));
    final Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, expiresAt);

    final TrustMarkRequester.TrustMark trustMark =
        new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE);

    assertThat(trustMark).isNotNull();
    assertThat(trustMark.type()).isEqualTo(MARK_ONE);
    assertThat(trustMark.expiresAt()).isEqualTo(expiresAt);
    assertThat(trustMark.trustMark()).isEqualTo(client.trustMarkResponse.serialize());
    assertThat(client.lastTrustMarkRequest.subject().getValue()).isEqualTo(CLIENT_ID);
    assertThat(client.lastTrustMarkRequest.trustMarkType().getValue()).isEqualTo(MARK_ONE);
    assertThat(client.lastTrustMarkRequest.trustMarkIssuer().getValue()).isEqualTo(TRUST_MARK_ISSUER);
  }

  @Test
  void aTrustMarkWithoutExpiryIsAccepted() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null);

    final TrustMarkRequester.TrustMark trustMark =
        new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE);

    assertThat(trustMark).isNotNull();
    assertThat(trustMark.expiresAt()).isNull();
  }

  @Test
  void aTypeWithoutAConfiguredIssuerIsNotAskedFor() {
    final FederationSettings settings = settings(null);
    final StubFederationClient client = new StubFederationClient();

    assertThat(new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE)).isNull();
    assertThat(client.trustMarkCalls).isZero();
  }

  @Test
  void anIssuerThatHasNotIssuedTheTrustMarkGivesNothing() {
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(key("tmi"))));

    final StubFederationClient client = new StubFederationClient();

    assertThat(new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE)).isNull();
    assertThat(client.trustMarkCalls).isEqualTo(1);
  }

  @Test
  void aTrustMarkWithABadSignatureIsRejected() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(key("other"), TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null);

    assertThatThrownBy(() -> new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aTrustMarkIssuedToAnotherClientIsRejected() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse =
        trustMark(issuerKey, TRUST_MARK_ISSUER, "https://other.example.com", MARK_ONE, null);

    assertThatThrownBy(() -> new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void aTrustMarkOfAnotherTypeIsRejected() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_TWO, null);

    assertThatThrownBy(() -> new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining(MARK_TWO);
  }

  @Test
  void aTrustMarkThatHasExpiredIsRejected() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, publicKeys(issuerKey)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE,
        Instant.now().minus(1, ChronoUnit.HOURS));

    assertThatThrownBy(() -> new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void theTrustAnchorKeysAreUsedWhenTheIssuerIsTheTrustAnchor() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = new FederationSettings(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null),
        Map.of(MARK_ONE, new FederationSettings.TrustMarkIssuer(TRUST_ANCHOR, TRUST_MARK_ENDPOINT, null)));

    final StubFederationClient client = new StubFederationClient();
    client.trustMarkResponse = trustMark(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID, MARK_ONE, null);

    assertThat(new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE)).isNotNull();
  }

  @Test
  void keysAreRequiredForAnIssuerThatIsNotTheTrustAnchor() {
    assertThatThrownBy(() -> new FederationSettings(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null),
        Map.of(MARK_ONE, new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, TRUST_MARK_ENDPOINT, null))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(TRUST_MARK_ISSUER);
  }

  /**
   * Creates the settings of the test.
   *
   * @param issuer the trust mark issuer for {@link #MARK_ONE}, or {@code null} for none
   * @return a {@link FederationSettings}
   */
  private static FederationSettings settings(final FederationSettings.TrustMarkIssuer issuer) {
    return new FederationSettings(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null),
        issuer != null ? Map.of(MARK_ONE, issuer) : Map.of());
  }

  @Test
  void anIssuerWithoutAnEndpointUsesThePublishedOne() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, null, publicKeys(issuerKey)));
    final StubFederationClient client = new StubFederationClient();
    client.entityConfigurations.put(TRUST_MARK_ISSUER, entityConfiguration(issuerKey, TRUST_MARK_ISSUER,
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, "https://tmi.example.com/published"),
        Instant.now().plus(1, ChronoUnit.HOURS)));
    client.trustMarkResponse = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null);

    assertThat(new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE)).isNotNull();
    assertThat(client.lastTrustMarkEndpoint).isEqualTo("https://tmi.example.com/published");
  }

  @Test
  void theTrustAnchorAsIssuerIsLookedUpWithTheTrustAnchorKeys() {
    final ECKey trustAnchorKey = key("ta");
    final FederationSettings settings = new FederationSettings(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(trustAnchorKey)),
        new FederationSettings.Resolver(TRUST_ANCHOR, RESOLVE_ENDPOINT, null),
        Map.of(MARK_ONE, new FederationSettings.TrustMarkIssuer(TRUST_ANCHOR, null, null)));
    final StubFederationClient client = new StubFederationClient();
    client.entityConfigurations.put(TRUST_ANCHOR, entityConfiguration(trustAnchorKey, TRUST_ANCHOR,
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, "https://ta.example.com/trust_mark"),
        Instant.now().plus(1, ChronoUnit.HOURS)));
    client.trustMarkResponse = trustMark(trustAnchorKey, TRUST_ANCHOR, CLIENT_ID, MARK_ONE, null);

    assertThat(new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE)).isNotNull();
    assertThat(client.lastTrustMarkEndpoint).isEqualTo("https://ta.example.com/trust_mark");
  }

  @Test
  void anIssuerThatDoesNotPublishAnEndpointGivesNoTrustMark() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = settings(
        new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER, null, publicKeys(issuerKey)));
    final StubFederationClient client = new StubFederationClient();
    client.entityConfigurations.put(TRUST_MARK_ISSUER,
        entityConfiguration(issuerKey, TRUST_MARK_ISSUER, Map.of(), Instant.now().plus(1, ChronoUnit.HOURS)));

    assertThatThrownBy(() -> new HttpTrustMarkRequester(settings, client).request(CLIENT_ID, MARK_ONE))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("federation_trust_mark_endpoint");
    assertThat(client.trustMarkCalls).isZero();
  }

}
