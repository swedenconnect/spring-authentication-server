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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.autoconfigure.AuditSupportAutoConfiguration;
import se.swedenconnect.spring.audit.value.AuditValue;
import se.swedenconnect.spring.audit.value.StringAuditValue;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.events.AuthnRequestReceivedEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUserAuthenticatedEvent;
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
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Tests for {@link AuthnServerAuditAutoConfiguration}, together with spring-audit-support's autoconfiguration.
 *
 * @author Martin Lindström
 */
class AuthnServerAuditAutoConfigurationTest {

  private static final AuditRequester SP =
      new AuditRequester(AuthenticationProtocol.SAML, "https://sp.example.com", null, true);

  private final ApplicationContextRunner runner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(AuditSupportAutoConfiguration.class,
          AuthnServerAuditAutoConfiguration.class))
      .withPropertyValues("spring.application.name=authn-server-test")
      .withUserConfiguration(CollectorConfiguration.class);

  @Configuration(proxyBeanMethods = false)
  static class CollectorConfiguration {

    @Bean
    Collector collector() {
      return new Collector();
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class ReplacedTransformerConfiguration {

    @Bean
    AuthnUserAuthenticatedEventTransformer withoutAttributes() {
      return new WithoutAttributesTransformer();
    }
  }

  @Test
  void everyTransformerIsRegistered() {
    this.runner.run(context -> {
      assertThat(context).hasSingleBean(AuthnRequestReceivedEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnRequestAcceptedEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnUserAuthenticatedEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnAuthorizationResponseEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnSuccessResponseEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnUserInfoDeliveredEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnErrorResponseEventTransformer.class);
      assertThat(context).hasSingleBean(AuthnUnrecoverableErrorEventTransformer.class);
      assertThat(context).hasSingleBean(CredentialTestErrorEventTransformer.class);
      assertThat(context).hasSingleBean(CredentialReloadSuccessEventTransformer.class);
      assertThat(context).hasSingleBean(CredentialReloadErrorEventTransformer.class);

      context.publishEvent(new AuthnRequestReceivedEvent(SP, null));
      assertThat(context.getBean(Collector.class).events).extracting(AuditEvent::getType)
          .containsExactly("authn_request_received");
      assertThat(context.getBean(Collector.class).events.getFirst().getPrincipal())
          .isEqualTo("https://sp.example.com");
    });
  }

  @Test
  void aReplacedTransformerIsUsedInsteadOfOurs() {
    this.runner.withUserConfiguration(ReplacedTransformerConfiguration.class).run(context -> {
      assertThat(context).getBean(AuthnUserAuthenticatedEventTransformer.class)
          .isInstanceOf(WithoutAttributesTransformer.class);

      context.publishEvent(new AuthnUserAuthenticatedEvent(SP, null, new UserAuthentication(user()), false));

      final AuditEvent event = context.getBean(Collector.class).events.getFirst();
      assertThat(event.getType()).isEqualTo("authn_user_authenticated");
      assertThat(event.getData()).doesNotContainKey(AuthnUserAuthenticatedEventTransformer.ATTRIBUTES)
          .containsEntry("note", "replaced");
    });
  }

  @Test
  void credentialMonitoringEventsAreAudited() {
    this.runner.run(context -> {
      context.publishEvent(new FailedCredentialTestEvent("sign", "Test failed", "java.lang.IllegalStateException"));
      context.publishEvent(new SuccessfulCredentialReloadEvent("sign"));
      context.publishEvent(new FailedCredentialReloadEvent("sign", "Reload failed", null));

      final List<AuditEvent> events = context.getBean(Collector.class).events;
      assertThat(events).extracting(AuditEvent::getType).containsExactly("authn_credential_test_error",
          "authn_credential_reload_success", "authn_credential_reload_error");
      assertThat(events).allSatisfy(e -> {
        assertThat(e.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
        assertThat(e.getData()).containsEntry("credential_name", "sign");
      });
    });
  }

  private static AuthenticatedUser user() {
    return new AuthenticatedUser(List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
        "197705232382")), AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3",
        Instant.now(), "127.0.0.1");
  }

  /** Collects the audit events. */
  static class Collector implements ApplicationListener<AuditApplicationEvent> {

    final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void onApplicationEvent(final AuditApplicationEvent event) {
      this.events.add((AuditEvent) event.getAuditEvent());
    }
  }

  /** A transformer that leaves out the attributes. */
  static class WithoutAttributesTransformer extends AuthnUserAuthenticatedEventTransformer {

    @Override
    protected List<AuditValue<? extends Serializable>> getDataFields(final AuthnUserAuthenticatedEvent event) {
      final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
      fields.removeIf(f -> ATTRIBUTES.equals(f.getName()));
      fields.add(new StringAuditValue("note", "replaced"));
      return fields;
    }
  }

}
