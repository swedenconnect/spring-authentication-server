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

import java.io.IOException;
import java.io.Serial;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestObjectDecoder;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector;
import se.swedenconnect.spring.authnserver.oidc.token.ClientEncryption;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Checks the metadata of a federation client each time the client is resolved, so that a fault is found at once and
 * not when a request hits it. A client that fails is marked as invalid, see {@link Outcome}.
 * <p>
 * Only what the OpenID Provider needs to serve the client is checked. A parameter that is absent has the default value
 * of <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">OpenID Connect Dynamic
 * Client Registration 1.0, Section 2</a>, except that {@code RS256} is not assumed for ID token signing, see
 * {@link SigningKeySelector}. The client has a fault when:
 * </p>
 * <ul>
 * <li>its metadata cannot be parsed, or it has no {@code redirect_uris};</li>
 * <li>its {@code response_types} do not include {@code code}, or its {@code grant_types} do not include
 * {@code authorization_code};</li>
 * <li>its {@code token_endpoint_auth_method} is {@code none}, needs a client secret, which a federation client never
 * has, or is not supported and enabled by the OpenID Provider. The default, {@code client_secret_basic}, needs a client
 * secret;</li>
 * <li>a signing or encryption algorithm that it declares is not supported by the OpenID Provider;</li>
 * <li>{@code jwks_uri} or {@code signed_jwks_uri} does not use {@code https};</li>
 * <li>it needs keys, for {@code private_key_jwt}, a {@code request_object_signing_alg} or encryption of ID tokens or
 * UserInfo responses, and has none, or its keys hold no usable key for a declared algorithm;</li>
 * <li>the keys at its {@code signed_jwks_uri} cannot be verified with its Federation Entity Keys, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">OpenID Federation 1.0, Section
 * 5.2.1</a>;</li>
 * <li>its {@code subject_type} is {@code pairwise} and its registration fails the {@link PairwiseClientCheck}.</li>
 * </ul>
 * <p>
 * The keys are taken from {@code jwks}, {@code signed_jwks_uri} or {@code jwks_uri}, in that order. Keys at a URI are
 * fetched each time the client is resolved, and held with the client, see {@link HeldKeys}. When they cannot be
 * fetched or read, the mark is {@link Outcome#temporary() temporary}, unless the client already holds keys from the
 * same URI. Then it keeps them and stays valid. Every other fault lasts until the client is next resolved.
 * </p>
 * <p>
 * The algorithms and client authentication methods that the OpenID Provider supports are taken from its discovery
 * document, see {@link #setProviderMetadata(OIDCProviderMetadata)}. Without one, the algorithms and methods that the
 * library supports are used, with {@code private_key_jwt} as the only method, and the ID token and UserInfo signing
 * algorithms are not checked.
 * </p>
 *
 * @author Martin Lindström
 */
public class FederationClientValidator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FederationClientValidator.class);

  /** The explicit type of a signed JWK Set. */
  public static final String SIGNED_JWKS_TYPE = "jwk-set+jwt";

  /** The {@code none} algorithm. */
  private static final String NONE = "none";

  /** Fetches the keys at a {@code jwks_uri} or {@code signed_jwks_uri}. */
  private final ClientKeysFetcher keysFetcher;

  /** Checks the registration of pairwise clients. */
  private volatile PairwiseClientCheck pairwiseClientCheck;

  /** The discovery document of the OpenID Provider, or {@code null}. */
  private volatile OIDCProviderMetadata providerMetadata;

  /**
   * Constructor.
   *
   * @param pairwiseClientCheck checks the registration of pairwise clients
   * @param keysFetcher fetches the keys at a {@code jwks_uri} or {@code signed_jwks_uri}
   */
  public FederationClientValidator(final @NonNull PairwiseClientCheck pairwiseClientCheck,
      final @NonNull ClientKeysFetcher keysFetcher) {
    this.pairwiseClientCheck = Objects.requireNonNull(pairwiseClientCheck, "pairwiseClientCheck must not be null");
    this.keysFetcher = Objects.requireNonNull(keysFetcher, "keysFetcher must not be null");
  }

  /**
   * Assigns the check of pairwise clients.
   *
   * @param pairwiseClientCheck the check
   */
  public void setPairwiseClientCheck(final @NonNull PairwiseClientCheck pairwiseClientCheck) {
    this.pairwiseClientCheck = Objects.requireNonNull(pairwiseClientCheck, "pairwiseClientCheck must not be null");
  }

  /**
   * Gets the check of pairwise clients.
   *
   * @return the check
   */
  public @NonNull PairwiseClientCheck getPairwiseClientCheck() {
    return this.pairwiseClientCheck;
  }

  /**
   * Gets what fetches the keys at a {@code jwks_uri} or {@code signed_jwks_uri}.
   *
   * @return the fetcher
   */
  public @NonNull ClientKeysFetcher getKeysFetcher() {
    return this.keysFetcher;
  }

  /**
   * Assigns the discovery document of the OpenID Provider, which tells the supported algorithms and the enabled client
   * authentication methods. The OpenID Provider assigns it when it is set up.
   *
   * @param providerMetadata the discovery document, or {@code null} to use what the library supports
   */
  public void setProviderMetadata(final @Nullable OIDCProviderMetadata providerMetadata) {
    this.providerMetadata = providerMetadata;
  }

  /**
   * Validates a resolved client.
   *
   * @param client the resolved client
   * @param earlier the earlier cache entry of the client, whose held keys and remembered check are used, or
   *     {@code null}
   * @return the outcome
   */
  public @NonNull Outcome validate(final @NonNull ResolvedClient client, final @Nullable CachedClientRecord earlier) {
    Objects.requireNonNull(client, "client must not be null");
    final String clientId = client.clientId();
    if (client.metadataError() != null) {
      return invalid(clientId, "the metadata cannot be parsed - " + client.metadataError(), false, null);
    }
    final OIDCClientMetadata metadata = client.metadata();
    final String fault = this.checkMetadata(metadata);
    if (fault != null) {
      return invalid(clientId, fault, false, null);
    }
    final KeysOutcome keys = this.checkKeys(client, earlier != null ? earlier.heldKeys() : null);
    if (keys.fault() != null) {
      return invalid(clientId, keys.fault(), keys.temporary(), null);
    }
    final PairwiseClientCheck.Outcome pairwise = this.pairwiseClientCheck.check(clientId, metadata,
        earlier != null ? earlier.verifiedSector() : null);
    return new Outcome(pairwise.invalidReason(), pairwise.temporary(), pairwise.verifiedSector(), keys.held());
  }

  /**
   * Fetches the keys of a client again, for example since a JWT names a key that the held keys do not hold. The new
   * keys must pass the same checks as when the client is resolved.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param held the keys that the client holds
   * @return the new keys, or {@code null} if they cannot be fetched or do not pass the checks
   */
  public @Nullable HeldKeys refreshKeys(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @NonNull HeldKeys held) {
    final JWKSet keys;
    try {
      keys = this.fetch(clientId, URI.create(held.uri()), held.signed(), held.entityKeys());
    }
    catch (final IOException e) {
      log.warn("The keys at {} of the client '{}' cannot be fetched again - the held keys are kept: {}", held.uri(),
          clientId, e.getMessage());
      return null;
    }
    catch (final InvalidKeysException e) {
      log.warn("The keys at {} of the client '{}' were fetched again but are not used - the held keys are kept: {}",
          held.uri(), clientId, e.getMessage());
      return null;
    }
    final String unusable = this.checkUsable(metadata, keys, held.signed() ? "signed_jwks_uri" : "jwks_uri");
    if (unusable != null) {
      log.warn("The keys at {} of the client '{}' were fetched again but are not used - the held keys are kept: {}",
          held.uri(), clientId, unusable);
      return null;
    }
    log.debug("The keys at {} of the client '{}' were fetched again", held.uri(), clientId);
    return new HeldKeys(held.uri(), held.signed(), keys, held.entityKeys());
  }

  /**
   * Gets the URI that the keys of a client are fetched from: its {@code signed_jwks_uri}, or else its
   * {@code jwks_uri}. A client with {@code jwks} has none, since {@code jwks} is used first.
   *
   * @param metadata the client metadata
   * @return the URI, or {@code null} if the keys are not fetched
   */
  public static @Nullable URI getKeysUri(final @NonNull OIDCClientMetadata metadata) {
    if (metadata.getJWKSet() != null) {
      return null;
    }
    final URI signed = metadata.getSignedJWKSetURI();
    return signed != null ? signed : metadata.getJWKSetURI();
  }

  /**
   * Checks what can be checked without keys.
   *
   * @param metadata the client metadata
   * @return the fault, or {@code null} if there is none
   */
  private @Nullable String checkMetadata(final @NonNull OIDCClientMetadata metadata) {
    if (metadata.getRedirectionURIs() == null || metadata.getRedirectionURIs().isEmpty()) {
      return "the metadata has no redirect_uris";
    }
    if (metadata.getResponseTypes() != null && !metadata.getResponseTypes().contains(ResponseType.CODE)) {
      return "the response_types do not include code";
    }
    if (metadata.getGrantTypes() != null && !metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
      return "the grant_types do not include authorization_code";
    }

    final ClientAuthenticationMethod method = metadata.getTokenEndpointAuthMethod();
    final ClientAuthenticationMethod effective =
        Objects.requireNonNullElse(method, ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    if (ClientAuthenticationMethod.NONE.equals(effective)) {
      return "the token_endpoint_auth_method is none, which is not supported";
    }
    if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(effective)
        || ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(effective)
        || ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(effective)) {
      return method == null
          ? "there is no token_endpoint_auth_method, and the default client_secret_basic needs a client secret, "
              + "which a federation client never has"
          : "the token_endpoint_auth_method %s needs a client secret, which a federation client never has"
              .formatted(effective);
    }
    if (!this.getAuthenticationMethods().contains(effective)) {
      return "the token_endpoint_auth_method %s is not supported".formatted(effective);
    }

    String fault = checkSupported("token_endpoint_auth_signing_alg", metadata.getTokenEndpointAuthJWSAlg(),
        this.getTokenEndpointAlgorithms());
    if (fault == null) {
      fault = checkSupported("request_object_signing_alg", metadata.getRequestObjectJWSAlg(),
          this.getRequestObjectAlgorithms());
    }
    final OIDCProviderMetadata provider = this.providerMetadata;
    if (fault == null && provider != null) {
      fault = checkSupported("id_token_signed_response_alg", metadata.getIDTokenJWSAlg(),
          provider.getIDTokenJWSAlgs());
      if (fault == null) {
        fault = checkSupported("userinfo_signed_response_alg", metadata.getUserInfoJWSAlg(),
            provider.getUserInfoJWSAlgs());
      }
      if (fault == null) {
        fault = checkAccepted(SigningKeySelector.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
            metadata.getCustomField(SigningKeySelector.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED),
            provider.getIDTokenJWSAlgs());
      }
      if (fault == null) {
        fault = checkAccepted(SigningKeySelector.USERINFO_SIGNING_ALG_VALUES_SUPPORTED,
            metadata.getCustomField(SigningKeySelector.USERINFO_SIGNING_ALG_VALUES_SUPPORTED),
            provider.getUserInfoJWSAlgs());
      }
    }
    if (fault == null) {
      fault = checkEncryption("id_token", metadata.getIDTokenJWEAlg(), metadata.getIDTokenJWEEnc(),
          provider != null ? provider.getIDTokenJWEAlgs() : ClientEncryption.SUPPORTED_ALGORITHMS,
          provider != null ? provider.getIDTokenJWEEncs() : ClientEncryption.SUPPORTED_METHODS);
    }
    if (fault == null) {
      fault = checkEncryption("userinfo", metadata.getUserInfoJWEAlg(), metadata.getUserInfoJWEEnc(),
          provider != null ? provider.getUserInfoJWEAlgs() : ClientEncryption.SUPPORTED_ALGORITHMS,
          provider != null ? provider.getUserInfoJWEEncs() : ClientEncryption.SUPPORTED_METHODS);
    }
    return fault;
  }

  /**
   * Checks the keys of the client, and fetches them when they are at a URI.
   *
   * @param client the resolved client
   * @param earlier the keys that the client held before, or {@code null}
   * @return the outcome
   */
  private @NonNull KeysOutcome checkKeys(final @NonNull ResolvedClient client, final @Nullable HeldKeys earlier) {
    final OIDCClientMetadata metadata = client.metadata();
    final URI jwksUri = metadata.getJWKSetURI();
    if (jwksUri != null && !"https".equalsIgnoreCase(jwksUri.getScheme())) {
      return KeysOutcome.fault("the jwks_uri does not use https", false);
    }
    final URI signedJwksUri = metadata.getSignedJWKSetURI();
    if (signedJwksUri != null && !"https".equalsIgnoreCase(signedJwksUri.getScheme())) {
      return KeysOutcome.fault("the signed_jwks_uri does not use https", false);
    }

    if (metadata.getJWKSet() != null) {
      final String unusable = this.checkUsable(metadata, metadata.getJWKSet(), "jwks");
      return unusable != null ? KeysOutcome.fault(unusable, false) : KeysOutcome.valid(null);
    }
    final boolean signed = signedJwksUri != null;
    final URI uri = signed ? signedJwksUri : jwksUri;
    if (uri == null) {
      final List<String> needs = this.getNeeds(metadata).stream().map(Need::name).toList();
      return needs.isEmpty()
          ? KeysOutcome.valid(null)
          : KeysOutcome.fault("there is no jwks, signed_jwks_uri or jwks_uri, and keys are needed for "
              + String.join(", ", needs), false);
    }
    final String parameter = signed ? "signed_jwks_uri" : "jwks_uri";
    final JWKSet entityKeys = signed ? client.entityKeys() : null;
    if (signed && entityKeys == null) {
      return KeysOutcome.fault("the keys at the signed_jwks_uri cannot be verified, since the resolve response has no "
          + "usable trust_chain", false);
    }

    final JWKSet keys;
    try {
      keys = this.fetch(client.clientId(), uri, signed, entityKeys);
    }
    catch (final IOException e) {
      if (earlier != null && earlier.isFrom(uri.toString(), signed)) {
        final String unusable = this.checkUsable(metadata, earlier.keys(), parameter);
        if (unusable == null) {
          log.warn("The keys at the {} {} of the client '{}' cannot be fetched - the keys held before are kept: {}",
              parameter, uri, client.clientId(), e.getMessage());
          return KeysOutcome.valid(new HeldKeys(earlier.uri(), signed, earlier.keys(),
              signed ? entityKeys : null));
        }
      }
      return KeysOutcome.fault("the keys at the %s cannot be fetched - %s".formatted(parameter, e.getMessage()), true);
    }
    catch (final InvalidKeysException e) {
      return KeysOutcome.fault(e.getMessage(), false);
    }
    final String unusable = this.checkUsable(metadata, keys, parameter);
    return unusable != null
        ? KeysOutcome.fault(unusable, false)
        : KeysOutcome.valid(new HeldKeys(uri.toString(), signed, keys, entityKeys));
  }

  /**
   * Fetches the keys at a URI, and verifies them if they are signed.
   *
   * @param clientId the {@code client_id} of the client
   * @param uri the URI
   * @param signed whether the URI is a {@code signed_jwks_uri}
   * @param entityKeys the client's Federation Entity Keys, needed when the URI is a {@code signed_jwks_uri}
   * @return the keys
   * @throws IOException if the keys cannot be fetched or read
   * @throws InvalidKeysException if a signed JWK Set does not verify or holds no JWK Set
   */
  private @NonNull JWKSet fetch(final @NonNull String clientId, final @NonNull URI uri, final boolean signed,
      final @Nullable JWKSet entityKeys) throws IOException, InvalidKeysException {
    if (!signed) {
      return this.keysFetcher.fetchJwks(uri);
    }
    final SignedJWT jwt = this.keysFetcher.fetchSignedJwks(uri);
    if (entityKeys == null) {
      throw new InvalidKeysException("the keys at the signed_jwks_uri cannot be verified, since there are no "
          + "Federation Entity Keys");
    }
    if (jwt.getHeader().getKeyID() == null) {
      throw new InvalidKeysException("the signed JWK Set at the signed_jwks_uri has no kid");
    }
    final JWTClaimsSet claims;
    try {
      claims = FederationJwtVerifier.verify(jwt, SIGNED_JWKS_TYPE, entityKeys, clientId, null, Set.of("keys", "sub"));
    }
    catch (final ClientRegistryException e) {
      throw new InvalidKeysException("the signed JWK Set at the signed_jwks_uri does not verify - " + e.getMessage());
    }
    try {
      return JWKSet.parse(Map.of("keys", claims.getClaim("keys")));
    }
    catch (final ParseException | RuntimeException e) {
      throw new InvalidKeysException(
          "the signed JWK Set at the signed_jwks_uri holds no valid JWK Set - " + e.getMessage());
    }
  }

  /**
   * Checks that the keys hold a usable key for each need of the client.
   *
   * @param metadata the client metadata
   * @param keys the keys
   * @param parameter the parameter that the keys come from, for the reason
   * @return the fault, or {@code null} if the keys are usable
   */
  private @Nullable String checkUsable(final @NonNull OIDCClientMetadata metadata, final @NonNull JWKSet keys,
      final @NonNull String parameter) {
    for (final Need need : this.getNeeds(metadata)) {
      if (need.matchers().stream().allMatch(m -> new JWKSelector(m).select(keys).isEmpty())) {
        return "the keys of the %s hold no usable key for %s".formatted(parameter, need.name());
      }
    }
    return null;
  }

  /**
   * Gets what the client needs keys for.
   *
   * @param metadata the client metadata
   * @return the needs, possibly empty
   */
  private @NonNull List<Need> getNeeds(final @NonNull OIDCClientMetadata metadata) {
    final List<Need> needs = new ArrayList<>();
    if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(metadata.getTokenEndpointAuthMethod())) {
      final List<JWSAlgorithm> algorithms = metadata.getTokenEndpointAuthJWSAlg() != null
          ? List.of(metadata.getTokenEndpointAuthJWSAlg())
          : this.getTokenEndpointAlgorithms().stream()
              .filter(a -> !JWSAlgorithm.Family.HMAC_SHA.contains(a))
              .toList();
      needs.add(new Need("private_key_jwt", algorithms.stream().map(FederationClientValidator::signing).toList()));
    }
    final JWSAlgorithm requestObject = metadata.getRequestObjectJWSAlg();
    if (requestObject != null && !NONE.equals(requestObject.getName())) {
      needs.add(new Need("request_object_signing_alg " + requestObject, List.of(signing(requestObject))));
    }
    if (metadata.getIDTokenJWEAlg() != null) {
      needs.add(new Need("id_token_encrypted_response_alg " + metadata.getIDTokenJWEAlg(),
          List.of(encryption(metadata.getIDTokenJWEAlg()))));
    }
    if (metadata.getUserInfoJWEAlg() != null) {
      needs.add(new Need("userinfo_encrypted_response_alg " + metadata.getUserInfoJWEAlg(),
          List.of(encryption(metadata.getUserInfoJWEAlg()))));
    }
    return needs;
  }

  /**
   * Gets the client authentication methods that the OpenID Provider supports and has enabled.
   *
   * @return the methods
   */
  private @NonNull List<ClientAuthenticationMethod> getAuthenticationMethods() {
    final OIDCProviderMetadata provider = this.providerMetadata;
    if (provider == null) {
      return List.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    }
    return Objects.requireNonNullElse(provider.getTokenEndpointAuthMethods(), List.of());
  }

  /**
   * Gets the algorithms that the OpenID Provider accepts for client assertions.
   *
   * @return the algorithms
   */
  private @NonNull List<JWSAlgorithm> getTokenEndpointAlgorithms() {
    final OIDCProviderMetadata provider = this.providerMetadata;
    if (provider == null) {
      return RequestObjectDecoder.SUPPORTED_SIGNING_ALGORITHMS;
    }
    return Objects.requireNonNullElse(provider.getTokenEndpointJWSAlgs(), List.of());
  }

  /**
   * Gets the algorithms that the OpenID Provider accepts for request objects.
   *
   * @return the algorithms
   */
  private @NonNull List<JWSAlgorithm> getRequestObjectAlgorithms() {
    final OIDCProviderMetadata provider = this.providerMetadata;
    if (provider == null) {
      final List<JWSAlgorithm> algorithms = new ArrayList<>(RequestObjectDecoder.SUPPORTED_SIGNING_ALGORITHMS);
      algorithms.add(new JWSAlgorithm(NONE));
      return algorithms;
    }
    return Objects.requireNonNullElse(provider.getRequestObjectJWSAlgs(), List.of());
  }

  /**
   * Checks that a declared algorithm is supported.
   *
   * @param parameter the parameter, for the reason
   * @param declared the declared algorithm, or {@code null}
   * @param supported the supported algorithms, or {@code null} for none
   * @return the fault, or {@code null} if there is none
   */
  private static @Nullable String checkSupported(final @NonNull String parameter, final @Nullable Algorithm declared,
      final @Nullable List<? extends Algorithm> supported) {
    if (declared == null) {
      return null;
    }
    if (supported == null || supported.stream().noneMatch(a -> a.getName().equals(declared.getName()))) {
      return "the %s %s is not supported".formatted(parameter, declared);
    }
    return null;
  }

  /**
   * Checks that one of a list of accepted signing algorithms is supported, see {@link SigningKeySelector}.
   *
   * @param parameter the parameter, for the reason
   * @param value the value of the parameter, or {@code null}
   * @param supported the supported algorithms, or {@code null} for none
   * @return the fault, or {@code null} if there is none
   */
  private static @Nullable String checkAccepted(final @NonNull String parameter, final @Nullable Object value,
      final @Nullable List<JWSAlgorithm> supported) {
    if (value == null) {
      return null;
    }
    final List<String> accepted = value instanceof final List<?> list
        ? list.stream().map(String::valueOf).filter(a -> !NONE.equals(a)).toList()
        : List.of();
    if (supported == null || supported.stream().noneMatch(a -> accepted.contains(a.getName()))) {
      return "none of the %s %s is supported".formatted(parameter, accepted);
    }
    return null;
  }

  /**
   * Checks declared encryption.
   *
   * @param what {@code id_token} or {@code userinfo}
   * @param algorithm the declared key management algorithm, or {@code null}
   * @param method the declared content encryption algorithm, or {@code null}
   * @param algorithms the supported key management algorithms, or {@code null} for none
   * @param methods the supported content encryption algorithms, or {@code null} for none
   * @return the fault, or {@code null} if there is none
   */
  private static @Nullable String checkEncryption(final @NonNull String what, final @Nullable JWEAlgorithm algorithm,
      final @Nullable EncryptionMethod method, final @Nullable List<JWEAlgorithm> algorithms,
      final @Nullable List<EncryptionMethod> methods) {
    if (algorithm == null) {
      return method != null
          ? "the %1$s_encrypted_response_enc is given without %1$s_encrypted_response_alg".formatted(what)
          : null;
    }
    final String fault = checkSupported(what + "_encrypted_response_alg", algorithm, algorithms);
    return fault != null
        ? fault
        : checkSupported(what + "_encrypted_response_enc",
            method != null ? method : EncryptionMethod.A128CBC_HS256, methods);
  }

  /**
   * Creates the matcher of a key that can verify a signature made with an algorithm.
   *
   * @param algorithm the algorithm
   * @return the matcher
   */
  private static @NonNull JWKMatcher signing(final @NonNull JWSAlgorithm algorithm) {
    final JWKMatcher.Builder builder = new JWKMatcher.Builder()
        .keyType(KeyType.forAlgorithm(algorithm))
        .keyUses(KeyUse.SIGNATURE, null)
        .algorithms(algorithm, null);
    final Set<Curve> curves = Curve.forJWSAlgorithm(algorithm);
    if (curves != null && !curves.isEmpty()) {
      builder.curves(curves);
    }
    return builder.build();
  }

  /**
   * Creates the matcher of a key that can be encrypted for with an algorithm, as {@link ClientEncryption} selects it.
   *
   * @param algorithm the algorithm
   * @return the matcher
   */
  private static @NonNull JWKMatcher encryption(final @NonNull JWEAlgorithm algorithm) {
    return new JWKMatcher.Builder()
        .keyType(KeyType.forAlgorithm(algorithm))
        .keyUses(KeyUse.ENCRYPTION, null)
        .algorithms(algorithm, null)
        .build();
  }

  /**
   * Logs a fault and creates the outcome for it.
   *
   * @param clientId the {@code client_id} of the client
   * @param reason why the client is invalid
   * @param temporary whether the mark is temporary
   * @param heldKeys the keys that the client holds, or {@code null}
   * @return the outcome
   */
  private static @NonNull Outcome invalid(final @NonNull String clientId, final @NonNull String reason,
      final boolean temporary, final @Nullable HeldKeys heldKeys) {
    log.warn("The federation client '{}' is marked as invalid{} - {}", clientId,
        temporary ? " for a while" : " until it is resolved again", reason);
    return new Outcome(reason, temporary, null, heldKeys);
  }

  /**
   * The outcome of a validation.
   *
   * @param invalidReason why the client is invalid, or {@code null} if it is valid
   * @param temporary whether the client is invalid only for a while, since its keys or the document at its
   *     {@code sector_identifier_uri} could not be fetched. Otherwise an invalid client stays invalid until it is
   *     resolved again
   * @param verifiedSector the successful check of the {@code sector_identifier_uri} to remember for the client, or
   *     {@code null}
   * @param heldKeys the keys to hold for the client, or {@code null}
   */
  public record Outcome(@Nullable String invalidReason, boolean temporary, @Nullable VerifiedSector verifiedSector,
      @Nullable HeldKeys heldKeys) {

    /**
     * Tells whether the client is valid.
     *
     * @return {@code true} if the client is valid and {@code false} otherwise
     */
    public boolean isValid() {
      return this.invalidReason == null;
    }
  }

  /**
   * Something that the client needs a key for, with the matchers of the keys that serve it. One matching key is
   * enough.
   *
   * @param name what the key is needed for, for the reason
   * @param matchers the matchers
   */
  private record Need(@NonNull String name, @NonNull List<JWKMatcher> matchers) {
  }

  /**
   * The outcome of the check of the keys.
   *
   * @param fault the fault, or {@code null} if there is none
   * @param temporary whether the fault is temporary
   * @param held the keys to hold, or {@code null}
   */
  private record KeysOutcome(@Nullable String fault, boolean temporary, @Nullable HeldKeys held) {

    /**
     * Creates the outcome of keys that pass.
     *
     * @param held the keys to hold, or {@code null}
     * @return the outcome
     */
    static @NonNull KeysOutcome valid(final @Nullable HeldKeys held) {
      return new KeysOutcome(null, false, held);
    }

    /**
     * Creates the outcome of a fault.
     *
     * @param fault the fault
     * @param temporary whether the fault is temporary
     * @return the outcome
     */
    static @NonNull KeysOutcome fault(final @NonNull String fault, final boolean temporary) {
      return new KeysOutcome(fault, temporary, null);
    }
  }

  /**
   * Keys that were fetched but cannot be used.
   */
  private static final class InvalidKeysException extends Exception {

    /** For serialization. */
    @Serial
    private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param message the message
     */
    InvalidKeysException(final @NonNull String message) {
      super(message);
    }
  }

}
