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
package se.swedenconnect.spring.authnserver.oidc.audit;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;

import se.swedenconnect.spring.audit.AuditApplicationListener;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.DefaultAuditEventContextResolver;
import se.swedenconnect.spring.audit.support.ApplicationName;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnAuthorizationResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnErrorResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnRequestAcceptedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnRequestReceivedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnSuccessResponseEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUnrecoverableErrorEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUserAuthenticatedEventTransformer;
import se.swedenconnect.spring.authnserver.audit.transform.AuthnUserInfoDeliveredEventTransformer;

/**
 * Collects the audit events of a test, as spring-audit-support produces them from the server's events.
 *
 * @author Martin Lindström
 */
public class AuditCollector implements ApplicationListener<AuditApplicationEvent> {

  /** The audit events, in the order they were produced. */
  private final List<AuditEvent> events = new CopyOnWriteArrayList<>();

  /**
   * Creates the spring-audit-support listener with the transformers of the server.
   *
   * @param publisher the application event publisher
   * @return an {@link AuditApplicationListener}
   */
  public static AuditApplicationListener listener(final ApplicationEventPublisher publisher) {
    return new AuditApplicationListener(publisher,
        new DefaultAuditEventContextResolver(new ApplicationName("authn-server-test"), null),
        List.of(new AuthnRequestReceivedEventTransformer(), new AuthnRequestAcceptedEventTransformer(),
            new AuthnUserAuthenticatedEventTransformer(), new AuthnAuthorizationResponseEventTransformer(),
            new AuthnSuccessResponseEventTransformer(), new AuthnUserInfoDeliveredEventTransformer(),
            new AuthnErrorResponseEventTransformer(), new AuthnUnrecoverableErrorEventTransformer()));
  }

  @Override
  public void onApplicationEvent(final AuditApplicationEvent event) {
    this.events.add((AuditEvent) event.getAuditEvent());
  }

  /**
   * Gets the audit events.
   *
   * @return the events
   */
  public List<AuditEvent> getEvents() {
    return List.copyOf(this.events);
  }

  /**
   * Gets the types of the audit events.
   *
   * @return the types
   */
  public List<String> getTypes() {
    return this.events.stream().map(AuditEvent::getType).toList();
  }

  /**
   * Gets the first audit event of a type.
   *
   * @param type the type
   * @return the event
   */
  public AuditEvent get(final String type) {
    return this.events.stream().filter(e -> type.equals(e.getType())).findFirst().orElseThrow();
  }

  /**
   * Gets the correlation IDs of the audit events.
   *
   * @return the correlation IDs, {@code null} for an event without one
   */
  public List<String> getCorrelationIds() {
    return this.events.stream()
        .map(e -> e.getCorrelationId() != null ? e.getCorrelationId().getValue() : null)
        .toList();
  }

  /**
   * Removes the collected events.
   */
  public void clear() {
    this.events.clear();
  }

  /**
   * Gets an object of the data of an audit event.
   *
   * @param event the event
   * @param name the name of the object
   * @return the object
   */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> data(final AuditEvent event, final String name) {
    return (Map<String, Object>) event.getData().get(name);
  }

}
