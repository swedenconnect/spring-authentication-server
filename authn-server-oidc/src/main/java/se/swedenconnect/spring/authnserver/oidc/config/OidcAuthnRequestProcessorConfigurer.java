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

import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import se.swedenconnect.spring.authnserver.oidc.attributes.requested.OidcRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.DefaultClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.HttpRequestUriFetcher;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestUriFetcher;
import se.swedenconnect.spring.authnserver.oidc.response.ResponsePage;

/**
 * Configurer for the components that process OpenID Connect authentication requests and send responses. Each
 * component has a default, built from the values of the {@link OidcProviderConfigurer}; assign one here to replace it.
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
  public @Nonnull OidcAuthnRequestProcessorConfigurer requestedAttributeResolver(
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
   * Assigns the component that finds the keys of clients, for verifying signed request objects. The default is a
   * {@link DefaultClientKeyResolver}.
   *
   * @param clientKeyResolver the resolver
   * @return this configurer
   */
  public @Nonnull OidcAuthnRequestProcessorConfigurer clientKeyResolver(
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
  public @Nonnull OidcAuthnRequestProcessorConfigurer requestUriFetcher(
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
  public @Nonnull OidcAuthnRequestProcessorConfigurer responsePage(final @Nullable ResponsePage responsePage) {
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
   * UserAuthenticationInputToken}. Without one, the token is put in a request attribute and the filter chain
   * continues. Meant for tests and special cases.
   *
   * @param successHandler the handler
   * @return this configurer
   */
  public @Nonnull OidcAuthnRequestProcessorConfigurer successHandler(
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

}
