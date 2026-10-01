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
package se.swedenconnect.spring.authnserver.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;
import org.springframework.mock.web.MockHttpServletRequest;

import se.swedenconnect.spring.audit.tracing.CorrelationIDHolder;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.audit.events.AuthnErrorResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnRequestReceivedEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUnrecoverableErrorEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for the audit data classes, {@link FlowCorrelation} and {@link AuthnEventPublisher}.
 *
 * @author Martin Lindström
 */
class AuditModelTest {

  @AfterEach
  void clear() {
    CorrelationIDHolder.clear();
  }

  // AuditRequester

  @Test
  void aRequesterWithoutIdentifierHasTheUnknownPrincipal() {
    assertThat(AuditRequester.unknown(null).getPrincipal()).isEqualTo(AuditRequester.UNKNOWN_PRINCIPAL);
    assertThat(AuditRequester.unknown(AuthenticationProtocol.SAML).protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(AuditRequester.named(AuthenticationProtocol.OIDC, null).getPrincipal()).isEqualTo("unknown");
    assertThat(AuditRequester.named(AuthenticationProtocol.OIDC, " ").identifier()).isNull();
  }

  @Test
  void aNamedRequesterIsNotVerified() {
    final AuditRequester requester = AuditRequester.named(AuthenticationProtocol.OIDC, "client");
    assertThat(requester.getPrincipal()).isEqualTo("client");
    assertThat(requester.verified()).isFalse();
    assertThat(requester.organizationNumber()).isNull();
    assertThat(requester.asVerified().verified()).isTrue();
    assertThat(requester.asVerified().identifier()).isEqualTo("client");
  }

  @Test
  void aRequesterFromTheRegistryHasTheOrganizationNumberAsTheRegistryHoldsIt() {
    final RequesterRecord record = new RequesterRecord(new Requester(AuthenticationProtocol.OIDC, "client"),
        List.of(), List.of(), Set.of(), "urn:glue:iso6523:0007:5566778899", new Object());
    final AuditRequester requester = AuditRequester.of(record, true);
    assertThat(requester.protocol()).isEqualTo(AuthenticationProtocol.OIDC);
    assertThat(requester.identifier()).isEqualTo("client");
    assertThat(requester.organizationNumber()).isEqualTo("urn:glue:iso6523:0007:5566778899");
    assertThat(requester.verified()).isTrue();
    assertThat(AuditRequester.of(record, false).verified()).isFalse();
  }

  // ProtocolAuditData

  @Test
  void membersWithoutValueAreLeftOut() {
    final ProtocolAuditData data = ProtocolAuditData.builder("authn_request")
        .member("id", "_123")
        .member("empty", "")
        .member("missing", (String) null)
        .member("flag", false)
        .member("no_flag", (Boolean) null)
        .member("count", 3)
        .member("no_count", (Integer) null)
        .member("instant", Instant.EPOCH)
        .member("no_instant", (Instant) null)
        .member("list", List.of("a", "b"))
        .member("empty_list", List.of())
        .member("no_list", (List<String>) null)
        .build();
    assertThat(data.getName()).isEqualTo("authn_request");
    assertThat(data.getMembers()).containsOnlyKeys("id", "flag", "count", "instant", "list");
    assertThat(data.get("list")).isEqualTo(List.of("a", "b"));
    assertThat(data.toString()).startsWith("authn_request=");
  }

  @Test
  void aNestedObjectIsAddedUnderItsOwnName() {
    final ProtocolAuditData nested = ProtocolAuditData.builder("assertion").member("id", "_a").build();
    final ProtocolAuditData data = ProtocolAuditData.builder("response")
        .member(nested)
        .member(ProtocolAuditData.builder("empty").build())
        .member((ProtocolAuditData) null)
        .build();
    assertThat(data.getMembers()).containsOnlyKeys("assertion");
    assertThat(data.get("assertion")).isEqualTo(Map.of("id", "_a"));
    assertThat(data.toAuditValue().getName()).isEqualTo("response");
    assertThat(data.toAuditValue().getValue()).containsOnlyKeys("assertion");
  }

  @Test
  void theMembersCannotBeChangedAndKeepTheirOrder() {
    final ProtocolAuditData data = ProtocolAuditData.builder("x").member("b", "1").member("a", "2").build();
    assertThat(new ArrayList<>(data.getMembers().keySet())).containsExactly("b", "a");
    assertThatThrownBy(() -> data.getMembers().put("c", "3")).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> ProtocolAuditData.builder(" ")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void protocolDataEqualityAndSerialization() throws Exception {
    final ProtocolAuditData data = ProtocolAuditData.builder("x").member("a", "1").member("t", Instant.EPOCH).build();
    assertThat(data).isEqualTo(ProtocolAuditData.builder("x").member("a", "1").member("t", Instant.EPOCH).build());
    assertThat(data).hasSameHashCodeAs(
        ProtocolAuditData.builder("x").member("a", "1").member("t", Instant.EPOCH).build());
    assertThat(data).isNotEqualTo(ProtocolAuditData.builder("y").member("a", "1").build());
    assertThat(roundTrip(data)).isEqualTo(data);

    final AuditFlowData flowData =
        new AuditFlowData("corr", AuditRequester.named(AuthenticationProtocol.SAML, "sp").asVerified(), data);
    assertThat(roundTrip(flowData)).isEqualTo(flowData);
  }

  // AuditAttribute

  @Test
  void anAttributeIsWrittenWithNameAndStringValues() {
    final AuditAttribute attribute =
        AuditAttribute.of(GenericAttribute.of("attribute.given-name", List.of("Kalle", "Olle")));
    assertThat(attribute.name()).isEqualTo("attribute.given-name");
    assertThat(attribute.values()).containsExactly("Kalle", "Olle");
    final Map<String, Serializable> map = attribute.toMap();
    assertThat(map).containsEntry("name", "attribute.given-name");
    assertThat(map.get("values")).isEqualTo(List.of("Kalle", "Olle"));
  }

  // FlowCorrelation

  @Test
  void aNewFlowGetsANewCorrelationId() {
    final String first = FlowCorrelation.startFlow();
    assertThat(FlowCorrelation.current()).isEqualTo(first);
    final String second = FlowCorrelation.startFlow();
    assertThat(second).isNotEqualTo(first);
    assertThat(CorrelationIDHolder.get().getValue()).isEqualTo(second);
  }

  @Test
  void joiningAFlowUsesItsCorrelationId() {
    FlowCorrelation.startFlow();
    assertThat(FlowCorrelation.join("flow-1")).isEqualTo("flow-1");
    assertThat(FlowCorrelation.current()).isEqualTo("flow-1");
  }

  @Test
  void aRequestThatCannotBeJoinedToAFlowGetsACorrelationIdOfItsOwn() {
    assertThat(FlowCorrelation.current()).isNull();
    final String id = FlowCorrelation.join(null);
    assertThat(id).isNotBlank();
    assertThat(FlowCorrelation.current()).isEqualTo(id);
    // ... but an ID already assigned to the request is kept
    assertThat(FlowCorrelation.join("")).isEqualTo(id);
    assertThat(FlowCorrelation.ensure()).isEqualTo(id);
    FlowCorrelation.clear();
    assertThat(FlowCorrelation.current()).isNull();
  }

  @Test
  void flowDataTakesTheCorrelationIdOfTheRequest() {
    final String id = FlowCorrelation.startFlow();
    assertThat(AuditFlowData.of(AuditRequester.unknown(null), null).correlationId()).isEqualTo(id);
    FlowCorrelation.clear();
    assertThat(AuditFlowData.of(AuditRequester.unknown(null), null).correlationId()).isNotBlank()
        .isEqualTo(FlowCorrelation.current());
  }

  // AuditRequestContext

  @Test
  void theRequestContextIsKeptOnTheRequest() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final AuditRequestContext context = AuditRequestContext.get(request);
    assertThat(context.getRequester().getPrincipal()).isEqualTo("unknown");
    assertThat(context.getRequester().protocol()).isNull();
    assertThat(context.getStage()).isNull();
    context.setStage(AuditStage.RESPONSE).setRequester(AuditRequester.named(AuthenticationProtocol.SAML, "sp"));
    assertThat(AuditRequestContext.get(request)).isSameAs(context);
    assertThat(AuditRequestContext.get(request).getStage()).isEqualTo(AuditStage.RESPONSE);
    assertThat(AuditRequestContext.get(new MockHttpServletRequest())).isNotSameAs(context);
  }

  @Test
  void stageValuesAreSnakeCase() {
    assertThat(AuditStage.AUTHN_REQUEST.getValue()).isEqualTo("authn_request");
    assertThat(AuditStage.USER_AUTHENTICATION.getValue()).isEqualTo("user_authentication");
    assertThat(AuditStage.RESPONSE.getValue()).isEqualTo("response");
    assertThat(AuditStage.TOKEN.getValue()).isEqualTo("token");
    assertThat(AuditStage.USERINFO.getValue()).isEqualTo("userinfo");
  }

  // AuthnEventPublisher

  @Test
  void anEventIsPublishedUnderACorrelationId() {
    final List<ApplicationEvent> events = new ArrayList<>();
    final List<String> correlationIds = new ArrayList<>();
    final AuthnEventPublisher publisher = new AuthnEventPublisher(e -> {
      events.add((ApplicationEvent) e);
      correlationIds.add(FlowCorrelation.current());
    });
    publisher.publish(new AuthnRequestReceivedEvent(AuditRequester.unknown(null), null));
    assertThat(events).hasSize(1);
    assertThat(correlationIds.getFirst()).isNotBlank();

    FlowCorrelation.join("flow-1");
    publisher.publish(new AuthnRequestReceivedEvent(AuditRequester.unknown(null), null));
    assertThat(correlationIds.get(1)).isEqualTo("flow-1");
  }

  @Test
  void errorEventsTakeTheRequesterAndStageFromTheRequest() {
    final List<Object> events = new ArrayList<>();
    final AuthnEventPublisher publisher = new AuthnEventPublisher(events::add);
    final MockHttpServletRequest request = new MockHttpServletRequest();
    AuditRequestContext.get(request)
        .setRequester(AuditRequester.named(AuthenticationProtocol.SAML, "sp"))
        .setStage(AuditStage.AUTHN_REQUEST);

    publisher.publishErrorResponse(request, null, "code", "description");
    publisher.publishUnrecoverableError(request,
        new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "message"));

    assertThat(events.getFirst()).isInstanceOfSatisfying(AuthnErrorResponseEvent.class, e -> {
      assertThat(e.getRequester().getPrincipal()).isEqualTo("sp");
      assertThat(e.getStage()).isEqualTo(AuditStage.AUTHN_REQUEST);
      assertThat(e.getErrorCode()).isEqualTo("code");
      assertThat(e.getErrorDescription()).isEqualTo("description");
      assertThat(e.getProtocolData()).isNull();
    });
    assertThat(events.get(1)).isInstanceOfSatisfying(AuthnUnrecoverableErrorEvent.class, e -> {
      assertThat(e.getRequester().getPrincipal()).isEqualTo("sp");
      assertThat(e.getStage()).isEqualTo(AuditStage.AUTHN_REQUEST);
      assertThat(e.getError().getError()).isEqualTo(CommonUnrecoverableError.INTERNAL);
    });
  }

  @Test
  void aNoopPublisherPublishesNothingAndAssignsNoCorrelationId() {
    AuthnEventPublisher.noop().publish(new AuthnRequestReceivedEvent(AuditRequester.unknown(null), null));
    assertThat(FlowCorrelation.current()).isNull();
  }

  @SuppressWarnings("unchecked")
  private static <T> T roundTrip(final T object) throws Exception {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(object);
    }
    try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }

}
