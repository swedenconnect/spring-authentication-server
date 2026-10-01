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

import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.AuditEventBuilder;
import se.swedenconnect.spring.audit.AuditEventContext;
import se.swedenconnect.spring.audit.AuditType;
import se.swedenconnect.spring.audit.transform.SingleEventTransformer;
import se.swedenconnect.spring.audit.value.AuditValue;
import se.swedenconnect.spring.audit.value.ListAuditValue;
import se.swedenconnect.spring.audit.value.MapAuditValue;
import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.events.AbstractAuthnEvent;

/**
 * Base class for the transformers of the events of an authentication flow.
 * <p>
 * The audit event gets the timestamp of the event, the requester as principal, and as data the common {@code requester}
 * object followed by the protocol-specific part of the event. A subclass adds the data of its own event type by
 * overriding {@link #getDataFields(AbstractAuthnEvent)}. An application that wants other data in an event type
 * extends the transformer of that type in the same way, and declares its own transformer as a bean.
 * </p>
 *
 * @param <T> the type of event
 * @author Martin Lindström
 */
public abstract class AbstractAuthnEventTransformer<T extends AbstractAuthnEvent> implements SingleEventTransformer<T> {

  /** The name of the common object identifying the requester. */
  public static final String REQUESTER = "requester";

  /** The event type handled by the transformer. */
  private final Class<T> eventType;

  /** The audit type of the audit events produced. */
  private final AuditType auditType;

  /**
   * Constructor.
   *
   * @param eventType the event type handled by the transformer
   * @param auditType the audit type of the audit events produced
   */
  protected AbstractAuthnEventTransformer(final @NonNull Class<T> eventType, final @NonNull AuditType auditType) {
    this.eventType = Objects.requireNonNull(eventType, "eventType must not be null");
    this.auditType = Objects.requireNonNull(auditType, "auditType must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuditEvent transformEvent(final @NonNull T event, final @NonNull AuditEventContext context) {
    final AuditEventBuilder builder = AuditEventBuilder.builder(context)
        .type(this.auditType)
        .timestamp(Instant.ofEpochMilli(event.getTimestamp()))
        .principal(event.getRequester().getPrincipal());
    this.getDataFields(event).forEach(builder::dataField);
    return builder.build();
  }

  /**
   * Gets the data fields of the audit event. The default is the {@code requester} object, followed by the
   * protocol-specific part of the event if there is one.
   *
   * @param event the event
   * @return the data fields, in the order they are written
   */
  protected @NonNull List<AuditValue<? extends Serializable>> getDataFields(final @NonNull T event) {
    final List<AuditValue<? extends Serializable>> fields = new ArrayList<>();
    fields.add(requester(event.getRequester()));
    if (event.getProtocolData() != null) {
      fields.add(event.getProtocolData().toAuditValue());
    }
    return fields;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Class<T> getEventType() {
    return this.eventType;
  }

  /**
   * Gets the audit type of the audit events produced.
   *
   * @return the audit type
   */
  public @NonNull AuditType getAuditType() {
    return this.auditType;
  }

  /**
   * Creates the common {@code requester} object, with the members {@code protocol}, {@code id},
   * {@code organization_number} and {@code verified}. A member without a value is left out.
   *
   * @param requester the requester
   * @return a {@link MapAuditValue}
   */
  public static @NonNull MapAuditValue requester(final @NonNull AuditRequester requester) {
    final MapAuditValue.Builder builder = MapAuditValue.builder().name(REQUESTER);
    if (requester.protocol() != null) {
      builder.value("protocol", requester.protocol().name().toLowerCase(Locale.ROOT));
    }
    if (requester.identifier() != null) {
      builder.value("id", requester.identifier());
    }
    if (requester.organizationNumber() != null) {
      builder.value("organization_number", requester.organizationNumber());
    }
    return builder.value("verified", requester.verified()).build();
  }

  /**
   * Creates a list of attributes, each an object with the members {@code name} and {@code values}.
   *
   * @param name the name of the list
   * @param attributes the attributes
   * @return a {@link ListAuditValue}
   */
  public static @NonNull ListAuditValue attributes(final @NonNull String name,
      final @NonNull List<AuditAttribute> attributes) {
    return new ListAuditValue(name, attributes.stream().map(AuditAttribute::toMap).toList());
  }

}
