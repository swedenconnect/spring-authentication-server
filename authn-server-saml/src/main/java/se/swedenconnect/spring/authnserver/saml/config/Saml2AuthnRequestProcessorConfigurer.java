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
package se.swedenconnect.spring.authnserver.saml.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.Objects;

import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.MessageSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.spring.authnserver.saml.attributes.requested.SamlRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.saml.authnrequest.SignMessageExtractor;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AssertionConsumerServiceValidator;
import se.swedenconnect.spring.authnserver.saml.response.ResponsePage;

/**
 * Configurer for the components that process SAML authentication requests and send error responses. Each component
 * has a default, built from the values of the {@link Saml2IdpConfigurer}; assign one here to replace it.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestProcessorConfigurer {

  /** The replay checker. */
  private MessageReplayChecker messageReplayChecker;

  /** The requested attribute resolver. */
  private SamlRequestedAttributeResolver requestedAttributeResolver;

  /** The sign message extractor. */
  private SignMessageExtractor signMessageExtractor;

  /** The assertion consumer service validator. */
  private AssertionConsumerServiceValidator assertionConsumerServiceValidator;

  /** The response page. */
  private ResponsePage responsePage;

  /** The message source for status messages. */
  private MessageSource messageSource;

  /** The customizer for responses. */
  private Customizer<Response> responseCustomizer;

  /** The handler of processed requests. */
  private AuthenticationSuccessHandler successHandler;

  /**
   * Constructor.
   */
  Saml2AuthnRequestProcessorConfigurer() {
  }

  /**
   * Assigns the replay checker. The default is built from the replay values of the {@link Saml2IdpConfigurer}.
   *
   * @param messageReplayChecker the replay checker
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer messageReplayChecker(
      final @Nullable MessageReplayChecker messageReplayChecker) {
    this.messageReplayChecker = messageReplayChecker;
    return this;
  }

  /**
   * Gets the replay checker.
   *
   * @return the replay checker, or {@code null} for the default
   */
  public @Nullable MessageReplayChecker getMessageReplayChecker() {
    return this.messageReplayChecker;
  }

  /**
   * Assigns the resolver of requested attributes. The default is a {@link SamlRequestedAttributeResolver} with the
   * entity categories that the authentication providers declare.
   *
   * @param requestedAttributeResolver the resolver
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer requestedAttributeResolver(
      final @Nullable SamlRequestedAttributeResolver requestedAttributeResolver) {
    this.requestedAttributeResolver = requestedAttributeResolver;
    return this;
  }

  /**
   * Gets the resolver of requested attributes.
   *
   * @return the resolver, or {@code null} for the default
   */
  public @Nullable SamlRequestedAttributeResolver getRequestedAttributeResolver() {
    return this.requestedAttributeResolver;
  }

  /**
   * Assigns the sign message extractor. The default is a
   * {@link se.swedenconnect.spring.authnserver.saml.authnrequest.DefaultSignMessageExtractor
   * DefaultSignMessageExtractor} with the encryption credentials of the Identity Provider.
   *
   * @param signMessageExtractor the extractor
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer signMessageExtractor(
      final @Nullable SignMessageExtractor signMessageExtractor) {
    this.signMessageExtractor = signMessageExtractor;
    return this;
  }

  /**
   * Gets the sign message extractor.
   *
   * @return the extractor, or {@code null} for the default
   */
  public @Nullable SignMessageExtractor getSignMessageExtractor() {
    return this.signMessageExtractor;
  }

  /**
   * Assigns the assertion consumer service validator.
   *
   * @param assertionConsumerServiceValidator the validator
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer assertionConsumerServiceValidator(
      final @Nullable AssertionConsumerServiceValidator assertionConsumerServiceValidator) {
    this.assertionConsumerServiceValidator = assertionConsumerServiceValidator;
    return this;
  }

  /**
   * Gets the assertion consumer service validator.
   *
   * @return the validator, or {@code null} for the default
   */
  public @Nullable AssertionConsumerServiceValidator getAssertionConsumerServiceValidator() {
    return this.assertionConsumerServiceValidator;
  }

  /**
   * Assigns the page that posts responses to the Service Provider.
   *
   * @param responsePage the response page
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer responsePage(final @Nullable ResponsePage responsePage) {
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
   * Assigns the message source that status messages of error responses are resolved against. Without one, the status
   * message is the description of the error.
   *
   * @param messageSource the message source
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer messageSource(final @Nullable MessageSource messageSource) {
    this.messageSource = messageSource;
    return this;
  }

  /**
   * Gets the message source.
   *
   * @return the message source, or {@code null}
   */
  public @Nullable MessageSource getMessageSource() {
    return this.messageSource;
  }

  /**
   * Assigns a customizer that gets each response before it is signed.
   *
   * @param responseCustomizer the customizer
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer responseCustomizer(
      final @Nullable Customizer<Response> responseCustomizer) {
    this.responseCustomizer = responseCustomizer;
    return this;
  }

  /**
   * Gets the response customizer.
   *
   * @return the customizer, or {@code null}
   */
  public @Nullable Customizer<Response> getResponseCustomizer() {
    return this.responseCustomizer;
  }

  /**
   * Assigns the handler of processed requests, which gets the
   * {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
   * UserAuthenticationInputToken}. Without one, the token is put in the security context and the filter chain
   * continues.
   *
   * @param successHandler the handler
   * @return this configurer
   */
  public @Nonnull Saml2AuthnRequestProcessorConfigurer successHandler(
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

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "replay-checker=%s, requested-attribute-resolver=%s, sign-message-extractor=%s".formatted(
        Objects.toString(this.messageReplayChecker, "default"),
        Objects.toString(this.requestedAttributeResolver, "default"),
        Objects.toString(this.signMessageExtractor, "default"));
  }

}
