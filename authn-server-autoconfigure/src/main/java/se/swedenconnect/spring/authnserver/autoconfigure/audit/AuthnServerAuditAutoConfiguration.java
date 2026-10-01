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
package se.swedenconnect.spring.authnserver.autoconfigure.audit;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import se.swedenconnect.spring.authnserver.audit.transform.AuthnAuthorizationResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnErrorResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnRequestAcceptedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnRequestReceivedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnSuccessResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUnrecoverableErrorEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUserAuthenticatedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUserInfoDeliveredEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.CredentialReloadErrorEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.CredentialReloadSuccessEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.CredentialTestErrorEventTransformer;

/**
 * Registers the transformers that turn the events of the authentication server, and the credential monitoring events
 * of credentials-support, into audit events. spring-audit-support's own autoconfiguration picks them up, together with
 * the repositories configured under {@code audit.*}.
 * <p>
 * Each transformer is created only if the application has not declared a bean of the same type. An application
 * replaces a transformer by declaring its own bean of that type, typically a subclass that adds or removes fields.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration
public class AuthnServerAuditAutoConfiguration {

  /**
   * Creates the transformer for {@code authn_request_received}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnRequestReceivedEventTransformer authnRequestReceivedEventTransformer() {
    return new AuthnRequestReceivedEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_request_accepted}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnRequestAcceptedEventTransformer authnRequestAcceptedEventTransformer() {
    return new AuthnRequestAcceptedEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_user_authenticated}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnUserAuthenticatedEventTransformer authnUserAuthenticatedEventTransformer() {
    return new AuthnUserAuthenticatedEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_authorization_response}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnAuthorizationResponseEventTransformer authnAuthorizationResponseEventTransformer() {
    return new AuthnAuthorizationResponseEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_success_response}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnSuccessResponseEventTransformer authnSuccessResponseEventTransformer() {
    return new AuthnSuccessResponseEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_userinfo_delivered}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnUserInfoDeliveredEventTransformer authnUserInfoDeliveredEventTransformer() {
    return new AuthnUserInfoDeliveredEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_error_response}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnErrorResponseEventTransformer authnErrorResponseEventTransformer() {
    return new AuthnErrorResponseEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_unrecoverable_error}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull AuthnUnrecoverableErrorEventTransformer authnUnrecoverableErrorEventTransformer() {
    return new AuthnUnrecoverableErrorEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_credential_test_error}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull CredentialTestErrorEventTransformer credentialTestErrorEventTransformer() {
    return new CredentialTestErrorEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_credential_reload_success}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull CredentialReloadSuccessEventTransformer credentialReloadSuccessEventTransformer() {
    return new CredentialReloadSuccessEventTransformer();
  }

  /**
   * Creates the transformer for {@code authn_credential_reload_error}.
   *
   * @return the transformer
   */
  @Bean
  @ConditionalOnMissingBean
  @NonNull CredentialReloadErrorEventTransformer credentialReloadErrorEventTransformer() {
    return new CredentialReloadErrorEventTransformer();
  }

}
