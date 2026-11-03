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
package se.swedenconnect.spring.authnserver.oidc.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.spring.authnserver.oidc.client.federation.ResolvedClient;

/**
 * Tests for the rules of {@link ClientMetadataValidator} that apply to clients from the configuration or a client
 * repository. The rules for federation clients are tested in
 * {@code se.swedenconnect.spring.authnserver.oidc.client.federation.ClientMetadataValidatorFederationTest}.
 *
 * @author Martin Lindström
 */
class ClientMetadataValidatorTest extends ClientTestSupport {

  private final StubKeysFetcher fetcher = new StubKeysFetcher();

  private final List<URI> sectorFetches = new ArrayList<>();

  private final ClientMetadataValidator validator = new ClientMetadataValidator(
      new PairwiseClientCheck(uri -> {
        this.sectorFetches.add(uri);
        return List.of(REDIRECT_URI);
      }), this.fetcher);

  private ClientMetadataValidator.Outcome validate(final OIDCClientMetadata metadata) {
    return this.validator.validate(OidcClientRecord.of(CLIENT_ID, metadata), null);
  }

  // Client secrets

  enum SecretMethod {
    CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, CLIENT_SECRET_JWT;

    ClientAuthenticationMethod method() {
      return ClientAuthenticationMethod.parse(this.name().toLowerCase());
    }
  }

  @ParameterizedTest
  @EnumSource(SecretMethod.class)
  void aMethodThatNeedsASecretIsAcceptedWithASecret(final SecretMethod method) {
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(method.method());
    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "a-secret");
    assertThat(this.validate(metadata).isValid()).isTrue();
  }

  @ParameterizedTest
  @EnumSource(SecretMethod.class)
  void aMethodThatNeedsASecretIsAFaultWithoutASecret(final SecretMethod method) {
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(method.method());
    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);
    assertThat(outcome.invalidReason()).isEqualTo(
        "the token_endpoint_auth_method %s needs a client secret, which the client does not have"
            .formatted(method.method()));
    assertThat(outcome.temporary()).isFalse();
  }

  @Test
  void theDefaultMethodNeedsASecret() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(null);
    assertThat(this.validate(metadata).invalidReason()).isEqualTo("there is no token_endpoint_auth_method, and the "
        + "default client_secret_basic needs a client secret, which the client does not have");

    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "a-secret");
    assertThat(this.validate(metadata).isValid()).isTrue();
  }

  @Test
  void aMethodWithASecretMustBeEnabledByTheProvider() {
    this.validator.setProviderMetadata(provider(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "a-secret");
    assertThat(this.validate(metadata).invalidReason())
        .isEqualTo("the token_endpoint_auth_method client_secret_basic is not supported");

    this.validator.setProviderMetadata(
        provider(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    assertThat(this.validate(metadata).isValid()).isTrue();
  }

  @Test
  void aFederationClientWithASecretMethodIsStillAFault() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    metadata.setCustomField(OidcClientRecord.CLIENT_SECRET, "a-secret");
    assertThat(this.validator.validate(new ResolvedClient(CLIENT_ID, metadata, Set.of(), Instant.now()), null)
        .invalidReason())
        .isEqualTo("the token_endpoint_auth_method client_secret_basic needs a client secret, which a federation "
            + "client never has");
  }

  // Keys

  @Test
  void aSignedJwksUriAloneIsAFault() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setSignedJWKSetURI(URI.create(CLIENT_ID + "/signed-jwks"));
    assertThat(this.validate(metadata).invalidReason()).isEqualTo("there is only a signed_jwks_uri, whose keys "
        + "cannot be verified since the client is not resolved through OpenID Federation and has no trust chain");
    assertThat(this.fetcher.signedCalls).isEmpty();
  }

  @Test
  void aSignedJwksUriIsIgnoredWithJwks() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setSignedJWKSetURI(URI.create("http://client.example.com/signed-jwks"));
    metadata.setJWKSet(keys(KEY, "key"));
    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);
    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isNull();
    assertThat(this.fetcher.signedCalls).isEmpty();
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void aSignedJwksUriIsIgnoredWithAJwksUri() {
    final OIDCClientMetadata metadata = jwksUriMetadata();
    metadata.setSignedJWKSetURI(URI.create(CLIENT_ID + "/signed-jwks"));
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);
    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isNotNull();
    assertThat(outcome.heldKeys().uri()).isEqualTo(JWKS_URI);
    assertThat(outcome.heldKeys().signed()).isFalse();
    assertThat(this.fetcher.signedCalls).isEmpty();
    assertThat(this.fetcher.calls).containsExactly(JWKS_URI);
  }

  @Test
  void theJwksUriMustUseHttps() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSetURI(URI.create("http://client.example.com/jwks"));
    assertThat(this.validate(metadata).invalidReason()).isEqualTo("the jwks_uri does not use https");
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void keysThatAreNeededMustBeThere() {
    assertThat(this.validate(metadata()).invalidReason())
        .isEqualTo("there is no jwks or jwks_uri, and keys are needed for private_key_jwt");
  }

  @Test
  void keysThatCannotBeReadGiveATemporaryMark() {
    final ClientMetadataValidator.Outcome outcome = this.validate(jwksUriMetadata());
    assertThat(outcome.invalidReason()).isEqualTo("the keys at the jwks_uri cannot be fetched - HTTP status 503");
    assertThat(outcome.temporary()).isTrue();
  }

  @Test
  void keysHeldFromTheSameUriAreKeptWhenTheyCannotBeRead() {
    final HeldKeys earlier = new HeldKeys(JWKS_URI, false, keys(KEY, "key"), null);
    final ClientMetadataValidator.Outcome outcome =
        this.validator.validate(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()), earlier);
    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys().keys().getKeyByKeyId("key")).isNotNull();
  }

  @Test
  void keysHeldFromAnotherUriAreNotKept() {
    final HeldKeys earlier = new HeldKeys(OTHER_JWKS_URI, false, keys(KEY, "key"), null);
    final ClientMetadataValidator.Outcome outcome =
        this.validator.validate(OidcClientRecord.of(CLIENT_ID, jwksUriMetadata()), earlier);
    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isTrue();
    assertThat(outcome.heldKeys()).isNull();
  }

  @Test
  void keysThatHoldNoUsableKeyAreAFault() {
    final OIDCClientMetadata metadata = jwksUriMetadata();
    metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256);
    this.fetcher.jwks.put(JWKS_URI, keys(KEY, "key"));
    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);
    assertThat(outcome.invalidReason()).isEqualTo("the keys of the jwks_uri hold no usable key for private_key_jwt");
    assertThat(outcome.temporary()).isFalse();
  }

  // Pairwise

  @Test
  void aPairwiseClientWithSeveralRedirectHostsAndNoSectorIdentifierUriIsAFault() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSet(keys(KEY, "key"));
    metadata.setSubjectType(SubjectType.PAIRWISE);
    metadata.setRedirectionURIs(Set.of(URI.create(REDIRECT_URI), URI.create("https://other.example.com/cb")));
    assertThat(this.validate(metadata).invalidReason())
        .isEqualTo("the redirect_uris have 2 different hosts and there is no sector_identifier_uri");
  }

  @Test
  void theDocumentAtTheSectorIdentifierUriIsNeverFetched() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSet(keys(KEY, "key"));
    metadata.setSubjectType(SubjectType.PAIRWISE);
    metadata.setSectorIDURI(URI.create("https://sector.example.com/redirects.json"));
    metadata.setRedirectionURIs(Set.of(URI.create(REDIRECT_URI), URI.create("https://other.example.com/cb")));
    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);
    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.verifiedSector()).isNull();
    assertThat(this.sectorFetches).isEmpty();

    // The same metadata as a federation client is checked against the document
    this.validator.validate(new ResolvedClient(CLIENT_ID, metadata, Set.of(), Instant.now()), null);
    assertThat(this.sectorFetches).hasSize(1);
  }

  // Logging

  @Test
  void aFaultIsLoggedAtErrorLevelAndAFederationFaultAsAWarning() {
    final ListAppender<ILoggingEvent> appender = appender(ClientMetadataValidator.class);
    try {
      this.validate(metadata());
      assertThat(appender.list).singleElement().satisfies(e -> {
        assertThat(e.getLevel()).isEqualTo(Level.ERROR);
        assertThat(e.getFormattedMessage()).contains(CLIENT_ID).contains("keys are needed for private_key_jwt");
      });

      appender.list.clear();
      this.validator.validate(new ResolvedClient(CLIENT_ID, metadata(), Set.of(), Instant.now()), null);
      assertThat(appender.list).singleElement().satisfies(e -> assertThat(e.getLevel()).isEqualTo(Level.WARN));

      // A pairwise fault is logged the same way
      appender.list.clear();
      final OIDCClientMetadata pairwise = metadata();
      pairwise.setJWKSet(keys(KEY, "key"));
      pairwise.setSubjectType(SubjectType.PAIRWISE);
      pairwise.setRedirectionURIs(Set.of(URI.create(REDIRECT_URI), URI.create("https://other.example.com/cb")));
      this.validate(pairwise);
      assertThat(appender.list).singleElement().satisfies(e -> assertThat(e.getLevel()).isEqualTo(Level.ERROR));
    }
    finally {
      remove(ClientMetadataValidator.class, appender);
    }
  }

  private static OIDCProviderMetadata provider(final ClientAuthenticationMethod... methods) {
    final OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://op.example.com"),
        List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE), URI.create("https://op.example.com/jwks"));
    metadata.setTokenEndpointAuthMethods(List.of(methods));
    metadata.setTokenEndpointJWSAlgs(List.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
    return metadata;
  }

}
