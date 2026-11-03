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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import se.swedenconnect.spring.authnserver.oidc.attributes.requested.OidcRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.DefaultClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.HttpRequestUriFetcher;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestUriFetcher;
import se.swedenconnect.spring.authnserver.oidc.client.ClientKeysFetcher;
import se.swedenconnect.spring.authnserver.oidc.client.ClientValidationStore;
import se.swedenconnect.spring.authnserver.oidc.client.HttpClientKeysFetcher;
import se.swedenconnect.spring.authnserver.oidc.client.InMemoryClientValidationStore;
import se.swedenconnect.spring.authnserver.oidc.response.ResponsePage;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAssertionReplayCache;

/**
 * Configurer for the components that process OpenID Connect authentication requests, send responses and serve the
 * token endpoint, and for the stores of authorization codes, access tokens, client assertions and client validation.
 * Each component has a default, built from the values of the {@link OidcProviderConfigurer}; assign one here to
 * replace it.
 *
 * @author Martin Lindström
 */
public class OidcAuthnRequestProcessorConfigurer {

  /** The requested attribute resolver. */
  private OidcRequestedAttributeResolver requestedAttributeResolver;

  /** Finds the keys of clients. */
  private ClientKeyResolver clientKeyResolver;

  /** Fetches request objects passed by reference. */
  private RequestUriFetcher requestUriFetcher;

  /** The response page. */
  private ResponsePage responsePage;

  /** The handler of processed requests. */
  private AuthenticationSuccessHandler successHandler;

  /** The authorization code store. */
  private AuthorizationCodeStore authorizationCodeStore;

  /** The access token store. */
  private AccessTokenStore accessTokenStore;

  /** The client assertion replay cache. */
  private ClientAssertionReplayCache clientAssertionReplayCache;

  /** Where the outcomes of the validation of clients are kept. */
  private ClientValidationStore clientValidationStore;

  /** Fetches the keys at the jwks_uri of clients from the configuration and client repositories. */
  private ClientKeysFetcher clientKeysFetcher;

  /**
   * Constructor.
   */
  OidcAuthnRequestProcessorConfigurer() {
  }

  /**
   * Assigns the resolver of requested attributes. The default is an {@link OidcRequestedAttributeResolver} with the
   * attribute mapping and the scope registry of the {@link OidcProviderConfigurer}.
   *
   * @param requestedAttributeResolver the resolver
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer requestedAttributeResolver(
      final @Nullable OidcRequestedAttributeResolver requestedAttributeResolver) {
    this.requestedAttributeResolver = requestedAttributeResolver;
    return this;
  }

  /**
   * Gets the resolver of requested attributes.
   *
   * @return the resolver, or {@code null} for the default
   */
  public @Nullable OidcRequestedAttributeResolver getRequestedAttributeResolver() {
    return this.requestedAttributeResolver;
  }

  /**
   * Assigns the component that finds the keys of clients that do not hold their keys, that is, clients of a backend of
   * the application's own. The default is a {@link DefaultClientKeyResolver}. Clients from the configuration, from a
   * client repository and from OpenID Federation use the keys held with them instead, see
   * {@link se.swedenconnect.spring.authnserver.oidc.client.HeldKeysClientKeyResolver}.
   *
   * @param clientKeyResolver the resolver
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer clientKeyResolver(
      final @Nullable ClientKeyResolver clientKeyResolver) {
    this.clientKeyResolver = clientKeyResolver;
    return this;
  }

  /**
   * Gets the component that finds the keys of clients.
   *
   * @return the resolver, or {@code null} for the default
   */
  public @Nullable ClientKeyResolver getClientKeyResolver() {
    return this.clientKeyResolver;
  }

  /**
   * Assigns the component that fetches request objects passed by reference. The default is an
   * {@link HttpRequestUriFetcher}.
   *
   * @param requestUriFetcher the fetcher
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer requestUriFetcher(
      final @Nullable RequestUriFetcher requestUriFetcher) {
    this.requestUriFetcher = requestUriFetcher;
    return this;
  }

  /**
   * Gets the component that fetches request objects passed by reference.
   *
   * @return the fetcher, or {@code null} for the default
   */
  public @Nullable RequestUriFetcher getRequestUriFetcher() {
    return this.requestUriFetcher;
  }

  /**
   * Assigns the page that posts responses to the client, for the {@code form_post} response mode.
   *
   * @param responsePage the response page
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer responsePage(final @Nullable ResponsePage responsePage) {
    this.responsePage = responsePage;
    return this;
  }

  /**
   * Gets the response page.
   *
   * @return the response page, or {@code null} for the default
   */
  public @Nullable ResponsePage getResponsePage() {
    return this.responsePage;
  }

  /**
   * Assigns the handler of processed requests, which gets the
   * {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
   * UserAuthenticationInputToken}. Without one, the filter chain continues and the user is authenticated. A handler
   * replaces the authentication of the user, and is meant for tests and special cases.
   *
   * @param successHandler the handler
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer successHandler(
      final @Nullable AuthenticationSuccessHandler successHandler) {
    this.successHandler = successHandler;
    return this;
  }

  /**
   * Gets the handler of processed requests.
   *
   * @return the handler, or {@code null}
   */
  public @Nullable AuthenticationSuccessHandler getSuccessHandler() {
    return this.successHandler;
  }

  /**
   * Assigns the store for authorization codes. The default is an
   * {@link se.swedenconnect.spring.authnserver.oidc.token.InMemoryAuthorizationCodeStore
   * InMemoryAuthorizationCodeStore}, which only serves the node it runs on.
   *
   * @param authorizationCodeStore the store
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer authorizationCodeStore(
      final @Nullable AuthorizationCodeStore authorizationCodeStore) {
    this.authorizationCodeStore = authorizationCodeStore;
    return this;
  }

  /**
   * Gets the store for authorization codes.
   *
   * @return the store, or {@code null} for the default
   */
  public @Nullable AuthorizationCodeStore getAuthorizationCodeStore() {
    return this.authorizationCodeStore;
  }

  /**
   * Assigns the store for access tokens. The default is an
   * {@link se.swedenconnect.spring.authnserver.oidc.token.InMemoryAccessTokenStore InMemoryAccessTokenStore}, which
   * only serves the node it runs on.
   *
   * @param accessTokenStore the store
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer accessTokenStore(
      final @Nullable AccessTokenStore accessTokenStore) {
    this.accessTokenStore = accessTokenStore;
    return this;
  }

  /**
   * Gets the store for access tokens.
   *
   * @return the store, or {@code null} for the default
   */
  public @Nullable AccessTokenStore getAccessTokenStore() {
    return this.accessTokenStore;
  }

  /**
   * Assigns the cache that remembers used client assertions. The default is an
   * {@link se.swedenconnect.spring.authnserver.oidc.token.InMemoryClientAssertionReplayCache
   * InMemoryClientAssertionReplayCache}, which only serves the node it runs on.
   *
   * @param clientAssertionReplayCache the cache
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer clientAssertionReplayCache(
      final @Nullable ClientAssertionReplayCache clientAssertionReplayCache) {
    this.clientAssertionReplayCache = clientAssertionReplayCache;
    return this;
  }

  /**
   * Gets the cache that remembers used client assertions.
   *
   * @return the cache, or {@code null} for the default
   */
  public @Nullable ClientAssertionReplayCache getClientAssertionReplayCache() {
    return this.clientAssertionReplayCache;
  }

  /**
   * Assigns where the outcomes of the validation of clients from the configuration and from client repositories are
   * kept, together with the keys read from their {@code jwks_uri}. The default is an
   * {@link InMemoryClientValidationStore}.
   *
   * @param clientValidationStore the store
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer clientValidationStore(
      final @Nullable ClientValidationStore clientValidationStore) {
    this.clientValidationStore = clientValidationStore;
    return this;
  }

  /**
   * Gets where the outcomes of the validation of clients are kept.
   *
   * @return the store, or {@code null} for the default
   */
  public @Nullable ClientValidationStore getClientValidationStore() {
    return this.clientValidationStore;
  }

  /**
   * Assigns the component that reads the keys at the {@code jwks_uri} of clients from the configuration and from
   * client repositories. The default is the fetcher of the federation backend, if there is one, and otherwise an
   * {@link HttpClientKeysFetcher}.
   *
   * @param clientKeysFetcher the fetcher
   * @return this configurer
   */
  public @NonNull OidcAuthnRequestProcessorConfigurer clientKeysFetcher(
      final @Nullable ClientKeysFetcher clientKeysFetcher) {
    this.clientKeysFetcher = clientKeysFetcher;
    return this;
  }

  /**
   * Gets the component that reads the keys at the {@code jwks_uri} of clients.
   *
   * @return the fetcher, or {@code null} for the default
   */
  public @Nullable ClientKeysFetcher getClientKeysFetcher() {
    return this.clientKeysFetcher;
  }

}
