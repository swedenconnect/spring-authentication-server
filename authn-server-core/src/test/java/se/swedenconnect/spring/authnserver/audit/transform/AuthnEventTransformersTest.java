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
package se.swedenconnect.spring.authnserver.audit.transform;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.AuditEventContext;
import se.swedenconnect.spring.audit.DefaultAuditEventContextResolver;
import se.swedenconnect.spring.audit.repository.JsonAuditEventMapper;
import se.swedenconnect.spring.audit.support.ApplicationName;
import se.swedenconnect.spring.audit.transform.EventTransformer;
import se.swedenconnect.spring.audit.value.AuditValue;
import se.swedenconnect.spring.authnserver.AuthenticationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.AuditStage;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.FlowCorrelation;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;
import se.swedenconnect.spring.authnserver.audit.events.AuthnAuthorizationResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnErrorResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnRequestAcceptedEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnRequestReceivedEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnSuccessResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUnrecoverableErrorEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUserAuthenticatedEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUserInfoDeliveredEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;
import tools.jackson.databind.json.JsonMapper;

/**
 * Tests for the event transformers.
 *
 * @author Martin Lindström
 */
class AuthnEventTransformersTest {

  private static final AuditRequester SP =
      new AuditRequester(AuthenticationProtocol.SAML, "https://sp.example.com", "5566778899", true);

  private static final ProtocolAuditData AUTHN_REQUEST =
      ProtocolAuditData.builder("authn_request").member("id", "_abc").member("force_authn", false).build();

  private final DefaultAuditEventContextResolver resolver =
      new DefaultAuditEventContextResolver(new ApplicationName("test-app"), null);

  @AfterEach
  void clear() {
    FlowCorrelation.clear();
  }

  @Test
  void theCommonDataAndPrincipalAreWrittenForEveryAuthenticationEvent() {
    FlowCorrelation.join("flow-1");
    final AuthnRequestReceivedEvent event = new AuthnRequestReceivedEvent(SP, AUTHN_REQUEST);
    final AuditEvent audit = this.transform(new AuthnRequestReceivedEventTransformer(), event);

    assertThat(audit.getType()).isEqualTo("authn_request_received");
    assertThat(audit.getPrincipal()).isEqualTo("https://sp.example.com");
    assertThat(audit.getCorrelationId().getValue()).isEqualTo("flow-1");
    assertThat(audit.getApplication().getName()).hasToString("test-app");
    assertThat(audit.getTimestamp()).isEqualTo(Instant.ofEpochMilli(event.getTimestamp()));
    assertThat(audit.getData()).containsOnlyKeys("requester", "authn_request");
    assertThat(map(audit, "requester")).isEqualTo(Map.of("protocol", "saml",
        "id", "https://sp.example.com", "organization_number", "5566778899", "verified", true));
    assertThat(map(audit, "authn_request")).containsEntry("id", "_abc").containsEntry("force_authn", false);
  }

  @Test
  void anUnverifiedRequesterWithoutIdentifierIsTheUnknownPrincipal() {
    final AuditEvent audit = this.transform(new AuthnRequestReceivedEventTransformer(),
        new AuthnRequestReceivedEvent(AuditRequester.named(AuthenticationProtocol.SAML, null), null));
    assertThat(audit.getPrincipal()).isEqualTo("unknown");
    assertThat(audit.getData()).containsOnlyKeys("requester");
    assertThat(map(audit, "requester")).isEqualTo(Map.of("protocol", "saml", "verified", false));

    final AuditEvent noProtocol = this.transform(new AuthnRequestReceivedEventTransformer(),
        new AuthnRequestReceivedEvent(AuditRequester.unknown(null), null));
    assertThat(map(noProtocol, "requester")).isEqualTo(Map.of("verified", false));
  }

  @Test
  void requestAcceptedAndAuthorizationResponse() {
    assertThat(this.transform(new AuthnRequestAcceptedEventTransformer(),
        new AuthnRequestAcceptedEvent(SP, AUTHN_REQUEST)).getType()).isEqualTo("authn_request_accepted");
    final AuditEvent audit = this.transform(new AuthnAuthorizationResponseEventTransformer(),
        new AuthnAuthorizationResponseEvent(SP,
            ProtocolAuditData.builder("authorization_response").member("state", "s").build()));
    assertThat(audit.getType()).isEqualTo("authn_authorization_response");
    assertThat(map(audit, "authorization_response")).containsEntry("state", "s");
  }

  @Test
  void theUserAuthenticationCarriesAllDeliveredAttributes() {
    final AuthenticatedUser user = new AuthenticatedUser(List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AuthenticationTestSupport.IDENTITY_NUMBER),
        GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, List.of("Agda", "Maria")),
        GenericAttribute.of(AttributeIdentifiers.AUTHENTICATION_PROVIDER, "https://proxied.example.com")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AuthenticationTestSupport.LOA3,
        Instant.parse("2026-10-01T10:00:00Z"), "192.168.1.14");
    user.setSignMessageDisplayed(true, "sv");
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com", "_abc", List.of());

    final AuditEvent audit = this.transform(new AuthnUserAuthenticatedEventTransformer(),
        new AuthnUserAuthenticatedEvent(SP, AUTHN_REQUEST, authentication, false));

    assertThat(audit.getType()).isEqualTo("authn_user_authenticated");
    assertThat(audit.getData()).containsOnlyKeys("requester", "authn_request", "user_authentication", "attributes");
    assertThat(map(audit, "user_authentication"))
        .containsEntry("authn_instant", Instant.parse("2026-10-01T10:00:00Z"))
        .containsEntry("acr", AuthenticationTestSupport.LOA3)
        .containsEntry("authenticating_authority", "https://proxied.example.com")
        .containsEntry("client_ip_address", "192.168.1.14")
        .containsEntry("sign_message_displayed", true)
        .containsEntry("allowed_to_reuse", false)
        .containsEntry("sso", false)
        .doesNotContainKey("sso_information");
    assertThat(audit.getData().get("attributes")).asInstanceOf(InstanceOfAssertFactories.list(Map.class))
        .containsExactly(
            Map.of("name", AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
                "values", List.of(AuthenticationTestSupport.IDENTITY_NUMBER)),
            Map.of("name", AttributeIdentifiers.GIVEN_NAME, "values", List.of("Agda", "Maria")),
            Map.of("name", AttributeIdentifiers.AUTHENTICATION_PROVIDER,
                "values", List.of("https://proxied.example.com")));
  }

  @Test
  void singleSignOnNamesTheOriginalRequesterAndRequest() {
    final UserAuthentication authentication = AuthenticationTestSupport.authentication(AuthenticationTestSupport.user(),
        AuthenticationTestSupport.oidcRequester("the-client"), List.of());
    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com", "_abc", List.of());

    final AuditEvent audit = this.transform(new AuthnUserAuthenticatedEventTransformer(),
        new AuthnUserAuthenticatedEvent(SP, AUTHN_REQUEST, authentication, true));

    assertThat(map(audit, "user_authentication"))
        .containsEntry("sso", true)
        .containsEntry("allowed_to_reuse", true)
        .doesNotContainKey("authenticating_authority")
        .containsEntry("sso_information",
            Map.of("original_protocol", "oidc", "original_requester", "the-client",
                "original_request_id", "_original"));
  }

  @Test
  void theResponseEventsCarryTheReleasedAttributes() {
    final List<AuditAttribute> released =
        List.of(new AuditAttribute("urn:oid:1.2.752.29.4.13", List.of("197705232382")));
    final AuditEvent success = this.transform(new AuthnSuccessResponseEventTransformer(),
        new AuthnSuccessResponseEvent(SP, ProtocolAuditData.builder("response").member("id", "_r").build(), released));
    assertThat(success.getType()).isEqualTo("authn_success_response");
    assertThat(success.getData()).containsOnlyKeys("requester", "response", "released_attributes");
    assertThat(success.getData().get("released_attributes"))
        .isEqualTo(List.of(Map.of("name", "urn:oid:1.2.752.29.4.13", "values", List.of("197705232382"))));

    final AuditEvent userInfo = this.transform(new AuthnUserInfoDeliveredEventTransformer(),
        new AuthnUserInfoDeliveredEvent(SP, null, List.of()));
    assertThat(userInfo.getType()).isEqualTo("authn_userinfo_delivered");
    assertThat(userInfo.getData()).containsOnlyKeys("requester", "released_attributes");
    assertThat(userInfo.getData().get("released_attributes")).isEqualTo(List.of());
  }

  @Test
  void anErrorResponseCarriesTheStageAndTheErrorOfTheProtocol() {
    final AuditEvent audit = this.transform(new AuthnErrorResponseEventTransformer(),
        new AuthnErrorResponseEvent(SP, ProtocolAuditData.builder("response").member("http_status", 400).build(),
            AuditStage.TOKEN, "invalid_grant", "The code has expired"));
    assertThat(audit.getType()).isEqualTo("authn_error_response");
    assertThat(audit.getData().get("stage")).isEqualTo("token");
    assertThat(map(audit, "error")).containsEntry("code", "invalid_grant")
        .containsEntry("message", "The code has expired");
    assertThat(map(audit, "response")).containsEntry("http_status", 400);

    final AuditEvent noStage = this.transform(new AuthnErrorResponseEventTransformer(),
        new AuthnErrorResponseEvent(SP, null, null, "access_denied", null));
    assertThat(noStage.getData()).doesNotContainKey("stage");
  }

  @Test
  void anUnrecoverableErrorCarriesTheStageAndTheError() {
    final AuditEvent audit = this.transform(new AuthnUnrecoverableErrorEventTransformer(),
        new AuthnUnrecoverableErrorEvent(AuditRequester.named(AuthenticationProtocol.SAML, "https://sp.example.com"),
            AuditStage.AUTHN_REQUEST,
            new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION, "No session")));
    assertThat(audit.getType()).isEqualTo("authn_unrecoverable_error");
    assertThat(audit.getPrincipal()).isEqualTo("https://sp.example.com");
    assertThat(audit.getData().get("stage")).isEqualTo("authn_request");
    assertThat(map(audit, "error"))
        .containsEntry("code", CommonUnrecoverableError.INVALID_SESSION.getMessageCode())
        .containsEntry("message", "No session");
    assertThat(map(audit, "requester")).containsEntry("verified", false);

    assertThat(this.transform(new AuthnUnrecoverableErrorEventTransformer(),
        new AuthnUnrecoverableErrorEvent(AuditRequester.unknown(null), null,
            new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL))).getData()).doesNotContainKey("stage");
  }

  @Test
  void credentialMonitoringEventsHaveTheSystemPrincipal() {
    final AuditEvent testError = this.transform(new CredentialTestErrorEventTransformer(),
        new FailedCredentialTestEvent("sign", "Key not available", "java.security.KeyException"));
    assertThat(testError.getType()).isEqualTo("authn_credential_test_error");
    assertThat(testError.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
    assertThat(testError.getData().get("credential_name")).isEqualTo("sign");
    assertThat(map(testError, "error")).isEqualTo(
        Map.of("message", "Key not available", "exception_class", "java.security.KeyException"));

    final AuditEvent reloadError = this.transform(new CredentialReloadErrorEventTransformer(),
        new FailedCredentialReloadEvent("sign", "Reload failed", null));
    assertThat(reloadError.getType()).isEqualTo("authn_credential_reload_error");
    assertThat(reloadError.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
    assertThat(map(reloadError, "error")).isEqualTo(Map.of("message", "Reload failed"));

    final AuditEvent reloaded = this.transform(new CredentialReloadSuccessEventTransformer(),
        new SuccessfulCredentialReloadEvent("sign"));
    assertThat(reloaded.getType()).isEqualTo("authn_credential_reload_success");
    assertThat(reloaded.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
    assertThat(reloaded.getData()).containsOnlyKeys("credential_name");
  }

  @Test
  void clientEventsHaveTheSystemPrincipal() {
    final KnownClient sp = new KnownClient(new Requester(AuthenticationProtocol.SAML, "https://sp.example.com"),
        "556677-8899", "https://md.example.com/sp.xml");
    final AuditEvent added = this.transform(new ClientAddedEventTransformer(), new ClientAddedEvent(sp));
    assertThat(added.getType()).isEqualTo("client_added");
    assertThat(added.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
    assertThat(added.getData()).containsOnlyKeys("client");
    assertThat(map(added, "client")).isEqualTo(Map.of("protocol", "saml", "id", "https://sp.example.com",
        "organization_number", "556677-8899", "source", "https://md.example.com/sp.xml"));

    final KnownClient rp = new KnownClient(new Requester(AuthenticationProtocol.OIDC, "https://rp.example.com"), null,
        "federation");
    final AuditEvent removed = this.transform(new ClientRemovedEventTransformer(),
        new ClientRemovedEvent(rp, "the resolver reports the client as not found"));
    assertThat(removed.getType()).isEqualTo("client_removed");
    assertThat(removed.getPrincipal()).isEqualTo(AuditEvent.SYSTEM_PRINCIPAL);
    assertThat(map(removed, "client")).isEqualTo(
        Map.of("protocol", "oidc", "id", "https://rp.example.com", "source", "federation"));
    assertThat(removed.getData().get("reason")).isEqualTo("the resolver reports the client as not found");
    assertThat(new ClientAddedEventTransformer().getEventType()).isEqualTo(ClientAddedEvent.class);
    assertThat(new ClientRemovedEventTransformer().getEventType()).isEqualTo(ClientRemovedEvent.class);
  }

  @Test
  void eachTransformerSupportsOnlyItsOwnEvent() {
    final ApplicationEvent received = new AuthnRequestReceivedEvent(SP, null);
    assertThat(new AuthnRequestReceivedEventTransformer().supports(received)).isTrue();
    assertThat(new AuthnRequestAcceptedEventTransformer().supports(received)).isFalse();
    assertThat(new CredentialTestErrorEventTransformer().supports(received)).isFalse();
    assertThat(new AuthnRequestReceivedEventTransformer().getAuditType())
        .isEqualTo(AuthnAuditTypes.AUTHN_REQUEST_RECEIVED);
  }

  @Test
  void aSubclassMayChangeTheData() {
    final AuthnUserAuthenticatedEventTransformer withoutAttributes = new AuthnUserAuthenticatedEventTransformer() {
      @Override
      protected List<AuditValue<? extends Serializable>> getDataFields(final AuthnUserAuthenticatedEvent event) {
        final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
        fields.removeIf(f -> ATTRIBUTES.equals(f.getName()));
        return fields;
      }
    };
    final AuditEvent audit = this.transform(withoutAttributes, new AuthnUserAuthenticatedEvent(SP, null,
        new UserAuthentication(AuthenticationTestSupport.user()), false));
    assertThat(audit.getData()).containsOnlyKeys("requester", "user_authentication");
  }

  @Test
  void theEventsCanBeWrittenAsJson() {
    FlowCorrelation.join("flow-1");
    final UserAuthentication authentication = new UserAuthentication(AuthenticationTestSupport.user());
    final AuditEvent audit = this.transform(new AuthnUserAuthenticatedEventTransformer(),
        new AuthnUserAuthenticatedEvent(SP, ProtocolAuditData.builder("authn_request")
            .member("issued_at", Instant.parse("2026-10-01T10:00:00Z"))
            .member(ProtocolAuditData.builder("nested").member("list", List.of("a")).build())
            .build(), authentication, false));

    final JsonAuditEventMapper mapper = new JsonAuditEventMapper(JsonMapper.builder().build());
    final String json = mapper.write(audit);
    assertThat(json).contains("\"type\":\"authn_user_authenticated\"", "\"correlation_id\":\"flow-1\"",
        "\"principal\":\"https://sp.example.com\"", "\"issued_at\":\"2026-10-01T10:00:00Z\"",
        "\"nested\":{\"list\":[\"a\"]}", "\"organization_number\":\"5566778899\"");
    final AuditEvent read = (AuditEvent) mapper.read(json);
    assertThat(read.getType()).isEqualTo("authn_user_authenticated");
    assertThat(read.getCorrelationId().getValue()).isEqualTo("flow-1");
  }

  private AuditEvent transform(final EventTransformer transformer, final ApplicationEvent event) {
    final AuditEventContext context = this.resolver.getContext(event);
    return (AuditEvent) transformer.transform(event, context);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> map(final AuditEvent audit, final String name) {
    return (Map<String, Object>) audit.getData().get(name);
  }

}
