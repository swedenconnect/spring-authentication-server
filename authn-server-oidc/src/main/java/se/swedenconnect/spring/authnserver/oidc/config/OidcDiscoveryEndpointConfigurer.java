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
package se.swedenconnect.spring.authnserver.oidc.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;

import se.oidc.nimbus.claims.ParameterConstants;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestObjectDecoder;
import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;
import se.swedenconnect.spring.authnserver.oidc.scope.SupportedScopesAndClaims;
import se.swedenconnect.spring.authnserver.oidc.web.OidcDiscoveryEndpointFilter;

/**
 * Configurer for the discovery document of the OpenID Provider, and for the endpoint that publishes it.
 * <p>
 * The document is built from the values of the {@link OidcProviderConfigurer}: the issuer, the JWKS URI, the ID token
 * signing algorithms, which are those of the active signing keys, the request object encryption algorithms, which are
 * those of the active decryption keys, the scopes, the claims, the authentication context URIs of the authentication
 * providers, the subject types, the UI locales, and the user message support parameters of the Swedish OpenID Connect
 * Profile when user messages are supported.
 * </p>
 * <p>
 * For the authorization endpoint, the document holds the endpoint, the response type {@code code}, the response modes
 * {@code query} and {@code form_post}, support for the {@code claims}, {@code request} and {@code request_uri}
 * parameters (a {@code request_uri} must be registered), the accepted request object signing algorithms, including
 * {@code none} only when unsigned request objects are accepted, the PKCE method {@code S256}, and support for the
 * {@code authnProvider} parameter of the Swedish OpenID Connect Profile.
 * </p>
 * <p>
 * Additional parameters are added to the built document, and may not replace a parameter that the OpenID Provider
 * sets. The customizer gets the document last, and may change anything.
 * </p>
 * <p>
 * The document is published at the issuer followed by {@value #WELL_KNOWN_PATH}, as OpenID Connect Discovery, Section
 * 4, requires. So it follows the issuer when the issuer has a path.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcDiscoveryEndpointConfigurer {

  /** The path, relative to the issuer, where the discovery document is published, {@value}. */
  public static final String WELL_KNOWN_PATH = "/.well-known/openid-configuration";

  /** The OIDC configurer. */
  private final OidcProviderConfigurer oidcConfigurer;

  /** Additional parameters. */
  private Map<String, Object> additionalParameters;

  /** For customizing the document once it has been built. */
  private Customizer<OIDCProviderMetadata> providerMetadataCustomizer = Customizer.withDefaults();

  /** The request matcher for the discovery endpoint. */
  private RequestMatcher requestMatcher;

  /**
   * Constructor.
   *
   * @param oidcConfigurer the OIDC configurer
   */
  OidcDiscoveryEndpointConfigurer(final @Nonnull OidcProviderConfigurer oidcConfigurer) {
    this.oidcConfigurer = oidcConfigurer;
  }

  /**
   * Assigns parameters that are added to the discovery document, for example {@code service_documentation},
   * {@code op_policy_uri} or parameters of other specifications. A value is a string, a number, a boolean, a list or a
   * map. A parameter that the OpenID Provider sets itself cannot be given here, use the
   * {@link #providerMetadataCustomizer(Customizer) customizer} for that.
   *
   * @param additionalParameters the parameters, or {@code null}
   * @return this configurer
   */
  public @Nonnull OidcDiscoveryEndpointConfigurer additionalParameters(
      final @Nullable Map<String, Object> additionalParameters) {
    this.additionalParameters = additionalParameters;
    return this;
  }

  /**
   * Assigns a customizer that gets the built discovery document, including the additional parameters, before it is
   * published.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @Nonnull OidcDiscoveryEndpointConfigurer providerMetadataCustomizer(
      final @Nonnull Customizer<OIDCProviderMetadata> customizer) {
    this.providerMetadataCustomizer = Objects.requireNonNull(customizer, "customizer must not be null");
    return this;
  }

  /**
   * Initializes the configurer.
   */
  void init() {
    this.requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.GET, this.getEndpointPath());
  }

  /**
   * Builds the document and adds the filter that publishes it.
   *
   * @param http the HTTP security object
   */
  void configure(final @Nonnull HttpSecurity http) {
    final OidcDiscoveryEndpointFilter filter =
        new OidcDiscoveryEndpointFilter(this.createProviderMetadata(), this.getRequestMatcher());
    http.addFilterBefore(this.oidcConfigurer.postProcessObject(filter),
        AbstractPreAuthenticatedProcessingFilter.class);
  }

  /**
   * Gets the path of the discovery endpoint relative to the application: the part of the issuer after the base URL,
   * followed by {@value #WELL_KNOWN_PATH}.
   *
   * @return the path
   */
  @Nonnull
  String getEndpointPath() {
    final String baseUrl = Objects.requireNonNull(this.oidcConfigurer.getServer().getBaseUrl());
    return this.oidcConfigurer.getIssuer().substring(baseUrl.length()) + WELL_KNOWN_PATH;
  }

  /**
   * Gets the request matcher for the discovery endpoint.
   *
   * @return the request matcher
   */
  @Nonnull
  RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Builds the discovery document.
   *
   * @return the OpenID Provider metadata
   * @throws IllegalArgumentException if an additional parameter is invalid, or replaces a parameter that the OpenID
   *     Provider sets
   */
  @Nonnull
  OIDCProviderMetadata createProviderMetadata() {
    final OidcProviderConfigurer oidc = this.oidcConfigurer;
    final OidcKeys keys = oidc.getKeys();
    final SupportedScopesAndClaims scopesAndClaims = oidc.getSupportedScopesAndClaims();

    final OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer(oidc.getIssuer()),
        oidc.getActiveSubjectGeneratorFactory().getSupportedSubjectTypes(),
        URI.create(oidc.getEndpointUrl(oidc.getJwksEndpoint())));

    metadata.setIDTokenJWSAlgs(keys.getSigningAlgorithms());
    if (!keys.getDecryptionAlgorithms().isEmpty()) {
      metadata.setRequestObjectJWEAlgs(keys.getDecryptionAlgorithms());
    }
    metadata.setScopes(new Scope(scopesAndClaims.scopes().toArray(String[]::new)));
    metadata.setClaims(scopesAndClaims.claims());

    final List<ACR> acrs = oidc.getSupportedAuthnContextUris().stream().map(ACR::new).toList();
    if (!acrs.isEmpty()) {
      metadata.setACRs(acrs);
    }
    if (oidc.getUiLocales() != null && !oidc.getUiLocales().isEmpty()) {
      metadata.setUILocales(oidc.getUiLocales().stream().map(OidcDiscoveryEndpointConfigurer::toLangTag).toList());
    }
    if (oidc.isSupportsUserMessage()) {
      metadata.setCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_PARAM_NAME, true);
      metadata.setCustomParameter(ParameterConstants.USER_MESSAGE_SUPPORTED_MIMETYPES_PARAM_NAME,
          List.of(MessageMimeType.TEXT_PLAIN.getMimeType(), MessageMimeType.TEXT_MARKDOWN.getMimeType()));
    }

    // The authorization endpoint ...
    //
    metadata.setAuthorizationEndpointURI(URI.create(oidc.getEndpointUrl(oidc.getAuthorizationEndpoint())));
    metadata.setResponseTypes(List.of(ResponseType.CODE));
    metadata.setResponseModes(List.of(ResponseMode.QUERY, ResponseMode.FORM_POST));
    metadata.setSupportsClaimsParams(true);
    metadata.setSupportsRequestParam(true);
    metadata.setSupportsRequestURIParam(true);
    metadata.setRequiresRequestURIRegistration(true);
    final List<JWSAlgorithm> requestObjectAlgorithms =
        new ArrayList<>(RequestObjectDecoder.SUPPORTED_SIGNING_ALGORITHMS);
    if (!oidc.isRequireSignedRequestObject()) {
      requestObjectAlgorithms.add(new JWSAlgorithm("none"));
    }
    metadata.setRequestObjectJWSAlgs(requestObjectAlgorithms);
    metadata.setCodeChallengeMethods(List.of(CodeChallengeMethod.S256));
    metadata.setCustomParameter(ParameterConstants.REQUESTED_PROVIDER_SUPPORTED_PARAM_NAME, true);

    final OIDCProviderMetadata result = this.addParameters(metadata);
    this.providerMetadataCustomizer.customize(result);
    return result;
  }

  /**
   * Adds the additional parameters to the document.
   *
   * @param metadata the built document
   * @return the document with the additional parameters
   */
  private @Nonnull OIDCProviderMetadata addParameters(final @Nonnull OIDCProviderMetadata metadata) {
    if (this.additionalParameters == null || this.additionalParameters.isEmpty()) {
      return metadata;
    }
    final JSONObject json = metadata.toJSONObject();
    for (final Map.Entry<String, Object> parameter : new LinkedHashMap<>(this.additionalParameters).entrySet()) {
      if (json.containsKey(parameter.getKey())) {
        throw new IllegalArgumentException(("The OIDC discovery parameter '%s' is set by the OpenID Provider and "
            + "cannot be given as an additional parameter").formatted(parameter.getKey()));
      }
      json.put(parameter.getKey(), parameter.getValue());
    }
    try {
      return OIDCProviderMetadata.parse(json);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid OIDC discovery parameter - " + e.getMessage(), e);
    }
  }

  /**
   * Parses a language tag.
   *
   * @param value the language tag
   * @return a {@link LangTag}
   */
  private static @Nonnull LangTag toLangTag(final @Nonnull String value) {
    try {
      return LangTag.parse(value);
    }
    catch (final LangTagException e) {
      throw new IllegalArgumentException("Invalid OIDC UI locale '%s'".formatted(value), e);
    }
  }

}
