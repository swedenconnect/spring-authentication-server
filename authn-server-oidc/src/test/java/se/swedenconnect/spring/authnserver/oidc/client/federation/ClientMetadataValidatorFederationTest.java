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

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.client.ClientMetadataValidator;
import se.swedenconnect.spring.authnserver.oidc.client.HeldKeys;
import se.swedenconnect.spring.authnserver.oidc.client.PairwiseClientCheck;

/**
 * Tests for {@link ClientMetadataValidator}.
 *
 * @author Martin Lindström
 */
class ClientMetadataValidatorFederationTest extends FederationTestSupport {

  private static final String JWKS_URI = "https://client.example.com/jwks";

  private static final String SIGNED_JWKS_URI = "https://client.example.com/signed-jwks";

  private static final ECKey ENTITY_KEY = key("entity-key");

  private static final RSAKey RSA_KEY = rsaKey("rsa-key", null);

  private static final RSAKey ENC_KEY = rsaKey("enc-key", KeyUse.ENCRYPTION);

  private final StubClientKeysFetcher fetcher = new StubClientKeysFetcher();

  private final StubSectorIdentifierFetcher sectorFetcher = new StubSectorIdentifierFetcher();

  private final ClientMetadataValidator validator =
      new ClientMetadataValidator(new PairwiseClientCheck(this.sectorFetcher), this.fetcher);

  // What is checked without keys

  @Test
  void aClientWithKeysAsJwksIsValidWithoutAnyFetch() {
    final ClientMetadataValidator.Outcome outcome = this.validate(clientMetadata("RP"));

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isNull();
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void metadataThatCannotBeParsedIsALastingFault() {
    final ClientMetadataValidator.Outcome outcome = this.validator.validate(new ResolvedClient(CLIENT_ID,
        new OIDCClientMetadata(), Set.of(), Instant.now().plusSeconds(3600), "Unexpected type of redirect_uris", null),
        null);

    assertThat(outcome.invalidReason()).isEqualTo("the metadata cannot be parsed - Unexpected type of redirect_uris");
    assertThat(outcome.temporary()).isFalse();
  }

  @Test
  void redirectUrisMustBePresentAndNotEmpty() {
    final OIDCClientMetadata missing = clientMetadata("RP");
    missing.setRedirectionURIs(null);
    assertThat(this.validate(missing).invalidReason()).isEqualTo("the metadata has no redirect_uris");

    final OIDCClientMetadata empty = clientMetadata("RP");
    empty.setRedirectionURIs(Set.of());
    assertThat(this.validate(empty).invalidReason()).isEqualTo("the metadata has no redirect_uris");
  }

  @Test
  void absentResponseAndGrantTypesDefaultToTheCodeFlow() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    assertThat(metadata.getResponseTypes()).isNull();
    assertThat(metadata.getGrantTypes()).isNull();
    assertThat(this.validate(metadata).isValid()).isTrue();
  }

  @Test
  void theResponseTypesMustAllowCodeAndTheGrantTypesAuthorizationCode() {
    final OIDCClientMetadata implicit = clientMetadata("RP");
    implicit.setResponseTypes(Set.of(ResponseType.IDTOKEN));
    assertThat(this.validate(implicit).invalidReason()).isEqualTo("the response_types do not include code");

    final OIDCClientMetadata noCode = clientMetadata("RP");
    noCode.setGrantTypes(Set.of(GrantType.IMPLICIT));
    assertThat(this.validate(noCode).invalidReason()).isEqualTo("the grant_types do not include authorization_code");

    final OIDCClientMetadata both = clientMetadata("RP");
    both.setResponseTypes(Set.of(ResponseType.CODE, ResponseType.IDTOKEN));
    both.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
    assertThat(this.validate(both).isValid()).isTrue();
  }

  @Test
  void anAbsentTokenEndpointAuthMethodDefaultsToAMethodThatNeedsASecret() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setTokenEndpointAuthMethod(null);

    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);

    assertThat(outcome.invalidReason()).contains("no token_endpoint_auth_method", "client_secret_basic",
        "client secret");
    assertThat(outcome.temporary()).isFalse();
  }

  @Test
  void aTokenEndpointAuthMethodThatNeedsASecretOrIsNoneOrUnsupportedIsAFault() {
    for (final ClientAuthenticationMethod method : List.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
      final OIDCClientMetadata metadata = clientMetadata("RP");
      metadata.setTokenEndpointAuthMethod(method);
      assertThat(this.validate(metadata).invalidReason())
          .isEqualTo("the token_endpoint_auth_method %s needs a client secret, which a federation client never has"
              .formatted(method));
    }

    final OIDCClientMetadata none = clientMetadata("RP");
    none.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
    assertThat(this.validate(none).invalidReason())
        .isEqualTo("the token_endpoint_auth_method is none, which is not supported");

    final OIDCClientMetadata tls = clientMetadata("RP");
    tls.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
    assertThat(this.validate(tls).invalidReason())
        .isEqualTo("the token_endpoint_auth_method tls_client_auth is not supported");
  }

  @Test
  void privateKeyJwtMustBeEnabledByTheProvider() {
    final OIDCProviderMetadata provider = provider();
    provider.setTokenEndpointAuthMethods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    this.validator.setProviderMetadata(provider);

    assertThat(this.validate(clientMetadata("RP")).invalidReason())
        .isEqualTo("the token_endpoint_auth_method private_key_jwt is not supported");
  }

  @Test
  void declaredSigningAlgorithmsMustBeSupported() {
    final OIDCClientMetadata assertion = clientMetadata("RP");
    assertion.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS256);
    assertThat(this.validate(assertion).invalidReason())
        .isEqualTo("the token_endpoint_auth_signing_alg HS256 is not supported");

    final OIDCClientMetadata requestObject = clientMetadata("RP");
    requestObject.setRequestObjectJWSAlg(JWSAlgorithm.EdDSA);
    assertThat(this.validate(requestObject).invalidReason())
        .isEqualTo("the request_object_signing_alg EdDSA is not supported");

    // Without the provider's discovery document the ID token and UserInfo algorithms are not checked
    final OIDCClientMetadata idToken = clientMetadata("RP");
    idToken.setIDTokenJWSAlg(JWSAlgorithm.ES512);
    idToken.setUserInfoJWSAlg(JWSAlgorithm.ES512);
    assertThat(this.validate(idToken).isValid()).isTrue();

    this.validator.setProviderMetadata(provider());
    assertThat(this.validate(idToken).invalidReason())
        .isEqualTo("the id_token_signed_response_alg ES512 is not supported");
    final OIDCClientMetadata userInfo = clientMetadata("RP");
    userInfo.setUserInfoJWSAlg(JWSAlgorithm.ES512);
    assertThat(this.validate(userInfo).invalidReason())
        .isEqualTo("the userinfo_signed_response_alg ES512 is not supported");

    final OIDCClientMetadata accepted = clientMetadata("RP");
    accepted.setCustomField("id_token_signing_alg_values_supported", List.of("ES512", "none"));
    assertThat(this.validate(accepted).invalidReason()).startsWith("none of the id_token_signing_alg_values_supported");
    accepted.setCustomField("id_token_signing_alg_values_supported", List.of("ES512", "RS256"));
    assertThat(this.validate(accepted).isValid()).isTrue();

    // No ID token signing algorithm is assumed when none is declared
    final OIDCProviderMetadata ecOnly = provider();
    ecOnly.setIDTokenJWSAlgs(List.of(JWSAlgorithm.ES256));
    this.validator.setProviderMetadata(ecOnly);
    assertThat(this.validate(clientMetadata("RP")).isValid()).isTrue();
  }

  @Test
  void declaredEncryptionMustBeSupportedWithTheDefaultContentEncryption() {
    final OIDCClientMetadata unsupported = encryptingClient();
    unsupported.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
    assertThat(this.validate(unsupported).invalidReason())
        .isEqualTo("the id_token_encrypted_response_alg RSA1_5 is not supported");

    final OIDCClientMetadata method = encryptingClient();
    method.setIDTokenJWEEnc(EncryptionMethod.A192GCM);
    assertThat(this.validate(method).invalidReason())
        .isEqualTo("the id_token_encrypted_response_enc A192GCM is not supported");

    // The default content encryption, A128CBC-HS256, is checked against the provider
    final OIDCProviderMetadata provider = provider();
    provider.setIDTokenJWEAlgs(List.of(JWEAlgorithm.RSA_OAEP_256));
    provider.setIDTokenJWEEncs(List.of(EncryptionMethod.A256GCM));
    this.validator.setProviderMetadata(provider);
    assertThat(this.validate(encryptingClient()).invalidReason())
        .isEqualTo("the id_token_encrypted_response_enc A128CBC-HS256 is not supported");
    this.validator.setProviderMetadata(null);

    final OIDCClientMetadata encWithoutAlg = clientMetadata("RP");
    encWithoutAlg.setUserInfoJWEEnc(EncryptionMethod.A128GCM);
    assertThat(this.validate(encWithoutAlg).invalidReason())
        .isEqualTo("the userinfo_encrypted_response_enc is given without userinfo_encrypted_response_alg");

    final OIDCClientMetadata userInfo = encryptingClient();
    userInfo.setIDTokenJWEAlg(null);
    userInfo.setUserInfoJWEAlg(JWEAlgorithm.ECDH_ES_A128KW);
    assertThat(this.validate(userInfo).invalidReason())
        .isEqualTo("the userinfo_encrypted_response_alg ECDH-ES+A128KW is not supported");

    assertThat(this.validate(encryptingClient()).isValid()).isTrue();
  }

  // Keys

  @Test
  void aClientThatNeedsKeysMustHaveThem() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setJWKSet(null);

    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);

    assertThat(outcome.invalidReason())
        .isEqualTo("there is no jwks, signed_jwks_uri or jwks_uri, and keys are needed for private_key_jwt");
    assertThat(outcome.temporary()).isFalse();
  }

  @Test
  void theKeysMustHoldAUsableKeyForEachDeclaredAlgorithm() {
    // The EC key of the client cannot sign RS256
    final OIDCClientMetadata assertion = clientMetadata("RP");
    assertion.setTokenEndpointAuthJWSAlg(JWSAlgorithm.RS256);
    assertThat(this.validate(assertion).invalidReason())
        .isEqualTo("the keys of the jwks hold no usable key for private_key_jwt");

    final OIDCClientMetadata requestObject = clientMetadata("RP");
    requestObject.setRequestObjectJWSAlg(JWSAlgorithm.ES384);
    assertThat(this.validate(requestObject).invalidReason())
        .isEqualTo("the keys of the jwks hold no usable key for request_object_signing_alg ES384");

    // A key for signing is not used for encryption
    final OIDCClientMetadata encryption = clientMetadata("RP");
    encryption.setJWKSet(new JWKSet(List.of(CLIENT_KEY.toPublicJWK(), rsaKey("sig", KeyUse.SIGNATURE))));
    encryption.setIDTokenJWEAlg(JWEAlgorithm.RSA_OAEP_256);
    assertThat(this.validate(encryption).invalidReason())
        .isEqualTo("the keys of the jwks hold no usable key for id_token_encrypted_response_alg RSA-OAEP-256");

    // "none" needs no key
    final OIDCClientMetadata none = clientMetadata("RP");
    none.setRequestObjectJWSAlg(new JWSAlgorithm("none"));
    assertThat(this.validate(none).isValid()).isTrue();
  }

  @Test
  void keyUrisMustUseHttps() {
    final OIDCClientMetadata jwksUri = uriClient(null);
    jwksUri.setJWKSetURI(URI.create("http://client.example.com/jwks"));
    assertThat(this.validate(jwksUri).invalidReason()).isEqualTo("the jwks_uri does not use https");

    final OIDCClientMetadata signed = uriClient(null);
    signed.setSignedJWKSetURI(URI.create("http://client.example.com/signed-jwks"));
    assertThat(this.validate(signed).invalidReason()).isEqualTo("the signed_jwks_uri does not use https");
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void theKeysAtTheJwksUriAreFetchedAndHeld() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));

    final ClientMetadataValidator.Outcome outcome = this.validate(uriClient(JWKS_URI));

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isNotNull().satisfies(h -> {
      assertThat(h.uri()).isEqualTo(JWKS_URI);
      assertThat(h.signed()).isFalse();
      assertThat(h.keys().getKeyByKeyId(CLIENT_KEY.getKeyID())).isNotNull();
      assertThat(h.entityKeys()).isNull();
    });
    assertThat(this.fetcher.calls).containsExactly(JWKS_URI);
  }

  @Test
  void onlyPublicKeysAreHeld() {
    this.fetcher.jwks.put(JWKS_URI, new JWKSet(CLIENT_KEY));

    final HeldKeys held = this.validate(uriClient(JWKS_URI)).heldKeys();

    assertThat(held).isNotNull();
    assertThat(held.keys().getKeys()).allSatisfy(k -> assertThat(k.isPrivate()).isFalse());
  }

  @Test
  void keysThatCannotBeFetchedTheFirstTimeGiveATemporaryMark() {
    final ClientMetadataValidator.Outcome outcome = this.validate(uriClient(JWKS_URI));

    assertThat(outcome.invalidReason()).isEqualTo("the keys at the jwks_uri cannot be fetched - HTTP status 503");
    assertThat(outcome.temporary()).isTrue();
    assertThat(outcome.heldKeys()).isNull();
  }

  @Test
  void heldKeysFromTheSameUriAreKeptWhenTheFetchFails() {
    final HeldKeys earlier = new HeldKeys(JWKS_URI, false, publicKeys(CLIENT_KEY), null);

    final ClientMetadataValidator.Outcome outcome = this.validate(uriClient(JWKS_URI), earlier);

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isEqualTo(earlier);
    assertThat(this.fetcher.calls).containsExactly(JWKS_URI);
  }

  @Test
  void aNewUriThatCannotBeFetchedGivesATemporaryMark() {
    final HeldKeys earlier = new HeldKeys("https://client.example.com/old-jwks", false, publicKeys(CLIENT_KEY), null);

    final ClientMetadataValidator.Outcome outcome = this.validate(uriClient(JWKS_URI), earlier);

    assertThat(outcome.isValid()).isFalse();
    assertThat(outcome.temporary()).isTrue();
  }

  @Test
  void keysThatAreFetchedButUnusableAreALastingFaultEvenWithHeldKeys() {
    this.fetcher.jwks.put(JWKS_URI, new JWKSet(RSA_KEY.toPublicJWK()));
    final OIDCClientMetadata metadata = uriClient(JWKS_URI);
    metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256);

    final ClientMetadataValidator.Outcome outcome =
        this.validate(metadata, new HeldKeys(JWKS_URI, false, publicKeys(CLIENT_KEY), null));

    assertThat(outcome.invalidReason()).isEqualTo("the keys of the jwks_uri hold no usable key for private_key_jwt");
    assertThat(outcome.temporary()).isFalse();
    assertThat(outcome.heldKeys()).isNull();
  }

  @Test
  void jwksIsUsedBeforeSignedJwksUriWhichIsUsedBeforeJwksUri() {
    this.fetcher.jwks.put(JWKS_URI, new JWKSet(RSA_KEY.toPublicJWK()));
    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)));

    final OIDCClientMetadata all = uriClient(JWKS_URI);
    all.setSignedJWKSetURI(URI.create(SIGNED_JWKS_URI));
    all.setJWKSet(publicKeys(CLIENT_KEY));
    assertThat(this.validateSigned(all).heldKeys()).isNull();
    assertThat(this.fetcher.calls).isEmpty();
    assertThat(ClientMetadataValidator.getKeysUri(all)).isNull();

    all.setJWKSet(null);
    assertThat(this.validateSigned(all).heldKeys()).isNotNull()
        .satisfies(h -> assertThat(h.uri()).isEqualTo(SIGNED_JWKS_URI));
    assertThat(this.fetcher.calls).containsExactly(SIGNED_JWKS_URI);
    assertThat(ClientMetadataValidator.getKeysUri(all)).isEqualTo(URI.create(SIGNED_JWKS_URI));

    all.setSignedJWKSetURI(null);
    assertThat(ClientMetadataValidator.getKeysUri(all)).isEqualTo(URI.create(JWKS_URI));
  }

  // signed_jwks_uri

  @Test
  void theKeysAtTheSignedJwksUriAreVerifiedWithTheFederationEntityKeys() {
    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)));

    final ClientMetadataValidator.Outcome outcome = this.validateSigned(signedClient());

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys()).isNotNull().satisfies(h -> {
      assertThat(h.signed()).isTrue();
      assertThat(h.keys().getKeyByKeyId(CLIENT_KEY.getKeyID())).isNotNull();
      assertThat(h.entityKeys().getKeyByKeyId(ENTITY_KEY.getKeyID())).isNotNull();
    });
  }

  @Test
  void aSignedJwkSetWithABadSignatureIsALastingFault() {
    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(key("other"), CLIENT_ID, publicKeys(CLIENT_KEY)));

    final ClientMetadataValidator.Outcome outcome = this.validateSigned(signedClient());

    assertThat(outcome.invalidReason()).startsWith("the signed JWK Set at the signed_jwks_uri does not verify");
    assertThat(outcome.temporary()).isFalse();
  }

  @Test
  void aSignedJwkSetMustHaveTheRightTypeIssuerAndKid() throws Exception {
    final JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(CLIENT_ID).subject(CLIENT_ID)
        .claim("keys", publicKeys(CLIENT_KEY).toJSONObject().get("keys")).build();

    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, sign(ENTITY_KEY, "JWT", claims));
    assertThat(this.validateSigned(signedClient()).invalidReason()).contains("does not verify");

    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(ENTITY_KEY, "https://other.example.com",
        publicKeys(CLIENT_KEY)));
    assertThat(this.validateSigned(signedClient()).invalidReason()).contains("does not verify");

    final SignedJWT noKid = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType(ClientMetadataValidator.SIGNED_JWKS_TYPE)).build(), claims);
    noKid.sign(new ECDSASigner(ENTITY_KEY));
    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, noKid);
    assertThat(this.validateSigned(signedClient()).invalidReason())
        .isEqualTo("the signed JWK Set at the signed_jwks_uri has no kid");
  }

  @Test
  void aSignedJwksUriCannotBeVerifiedWithoutATrustChain() {
    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(CLIENT_KEY)));

    final ClientMetadataValidator.Outcome outcome = this.validate(signedClient());

    assertThat(outcome.invalidReason()).isEqualTo("the keys at the signed_jwks_uri cannot be verified, since the "
        + "resolve response has no usable trust_chain");
    assertThat(outcome.temporary()).isFalse();
    assertThat(this.fetcher.calls).isEmpty();
  }

  @Test
  void aSignedJwksUriThatCannotBeFetchedKeepsHeldKeysWithTheNewEntityKeys() {
    final ECKey newEntityKey = key("new-entity-key");
    final HeldKeys earlier = new HeldKeys(SIGNED_JWKS_URI, true, publicKeys(CLIENT_KEY), publicKeys(ENTITY_KEY));

    final ClientMetadataValidator.Outcome outcome = this.validator.validate(new ResolvedClient(CLIENT_ID,
        signedClient(), Set.of(), Instant.now().plusSeconds(3600), null, publicKeys(newEntityKey)),
        this.earlier(earlier));

    assertThat(outcome.isValid()).isTrue();
    assertThat(outcome.heldKeys().keys()).isEqualTo(earlier.keys());
    assertThat(outcome.heldKeys().entityKeys().getKeyByKeyId(newEntityKey.getKeyID())).isNotNull();

    // Keys held from a jwks_uri with the same URI are not taken as signed keys
    final HeldKeys unsigned = new HeldKeys(SIGNED_JWKS_URI, false, publicKeys(CLIENT_KEY), null);
    assertThat(this.validator.validate(new ResolvedClient(CLIENT_ID, signedClient(), Set.of(),
        Instant.now().plusSeconds(3600), null, publicKeys(ENTITY_KEY)), this.earlier(unsigned)).temporary()).isTrue();
  }

  // Refresh

  @Test
  void keysAreFetchedAgainAndMustPassTheChecks() {
    final OIDCClientMetadata metadata = uriClient(JWKS_URI);
    final HeldKeys held = new HeldKeys(JWKS_URI, false, publicKeys(CLIENT_KEY), null);
    final ECKey rolled = key("rolled");

    assertThat(this.validator.refreshKeys(CLIENT_ID, metadata, held)).isNull();

    this.fetcher.jwks.put(JWKS_URI, new JWKSet(RSA_KEY.toPublicJWK()));
    metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.ES256);
    assertThat(this.validator.refreshKeys(CLIENT_ID, metadata, held)).isNull();

    this.fetcher.jwks.put(JWKS_URI, publicKeys(rolled));
    final HeldKeys refreshed = this.validator.refreshKeys(CLIENT_ID, metadata, held);
    assertThat(refreshed).isNotNull();
    assertThat(refreshed.keys().getKeyByKeyId(rolled.getKeyID())).isNotNull();
    assertThat(refreshed.uri()).isEqualTo(JWKS_URI);
  }

  @Test
  void signedKeysAreFetchedAgainAndVerifiedWithTheHeldEntityKeys() {
    final HeldKeys held = new HeldKeys(SIGNED_JWKS_URI, true, publicKeys(CLIENT_KEY), publicKeys(ENTITY_KEY));
    final ECKey rolled = key("rolled");

    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(key("other"), CLIENT_ID, publicKeys(rolled)));
    assertThat(this.validator.refreshKeys(CLIENT_ID, signedClient(), held)).isNull();

    this.fetcher.signedJwks.put(SIGNED_JWKS_URI, signedJwks(ENTITY_KEY, CLIENT_ID, publicKeys(rolled)));
    assertThat(this.validator.refreshKeys(CLIENT_ID, signedClient(), held)).isNotNull()
        .satisfies(h -> assertThat(h.keys().getKeyByKeyId(rolled.getKeyID())).isNotNull());
  }

  // The pairwise check

  @Test
  void thePairwiseCheckIsPartOfTheValidationAndKeepsTheKeys() {
    this.fetcher.jwks.put(JWKS_URI, publicKeys(CLIENT_KEY));
    final OIDCClientMetadata metadata = pairwiseMetadata("RP", null, "https://a.example.com/cb",
        "https://b.example.com/cb");
    metadata.setJWKSet(null);
    metadata.setJWKSetURI(URI.create(JWKS_URI));

    final ClientMetadataValidator.Outcome outcome = this.validate(metadata);

    assertThat(outcome.invalidReason()).contains("2 different hosts");
    assertThat(outcome.heldKeys()).isNotNull();
  }

  @Test
  void aFaultFoundBeforeThePairwiseCheckStopsIt() {
    final OIDCClientMetadata metadata = pairwiseMetadata("RP", "https://sector.example.com/r.json",
        "https://client.example.com/cb");
    metadata.setTokenEndpointAuthMethod(null);

    assertThat(this.validate(metadata).invalidReason()).contains("token_endpoint_auth_method");
    assertThat(this.sectorFetcher.calls).isEmpty();
  }

  private ClientMetadataValidator.Outcome validate(final OIDCClientMetadata metadata) {
    return this.validate(metadata, null);
  }

  private ClientMetadataValidator.Outcome validate(final OIDCClientMetadata metadata, final HeldKeys earlier) {
    return this.validator.validate(
        new ResolvedClient(CLIENT_ID, metadata, Set.of(), Instant.now().plusSeconds(3600)), this.earlier(earlier));
  }

  private ClientMetadataValidator.Outcome validateSigned(final OIDCClientMetadata metadata) {
    return this.validator.validate(new ResolvedClient(CLIENT_ID, metadata, Set.of(),
        Instant.now().plusSeconds(3600), null, publicKeys(ENTITY_KEY)), null);
  }

  private CachedClientRecord earlier(final HeldKeys heldKeys) {
    return heldKeys == null ? null : new CachedClientRecord(CLIENT_ID, clientMetadata("RP"), Set.of(), Map.of(),
        Instant.now().plusSeconds(3600), null, null, heldKeys);
  }

  private static OIDCClientMetadata uriClient(final String jwksUri) {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setJWKSet(null);
    if (jwksUri != null) {
      metadata.setJWKSetURI(URI.create(jwksUri));
    }
    return metadata;
  }

  private static OIDCClientMetadata signedClient() {
    final OIDCClientMetadata metadata = uriClient(null);
    metadata.setSignedJWKSetURI(URI.create(SIGNED_JWKS_URI));
    return metadata;
  }

  private static OIDCClientMetadata encryptingClient() {
    final OIDCClientMetadata metadata = clientMetadata("RP");
    metadata.setJWKSet(new JWKSet(List.of(CLIENT_KEY.toPublicJWK(), ENC_KEY.toPublicJWK())));
    metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA_OAEP_256);
    return metadata;
  }

  private static OIDCProviderMetadata provider() {
    final OIDCProviderMetadata provider = new OIDCProviderMetadata(new Issuer("https://op.example.com"),
        List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE), URI.create("https://op.example.com/jwks"));
    provider.setTokenEndpointAuthMethods(List.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
    provider.setTokenEndpointJWSAlgs(List.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
    provider.setRequestObjectJWSAlgs(List.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
    provider.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));
    provider.setUserInfoJWSAlgs(List.of(JWSAlgorithm.RS256));
    provider.setIDTokenJWEAlgs(List.of(JWEAlgorithm.RSA_OAEP_256));
    provider.setIDTokenJWEEncs(List.of(EncryptionMethod.A128CBC_HS256));
    provider.setUserInfoJWEAlgs(List.of(JWEAlgorithm.RSA_OAEP_256));
    provider.setUserInfoJWEEncs(List.of(EncryptionMethod.A128CBC_HS256));
    return provider;
  }

  private static RSAKey rsaKey(final String keyId, final KeyUse use) {
    try {
      return new RSAKeyGenerator(2048).keyID(keyId).keyUse(use).generate();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
