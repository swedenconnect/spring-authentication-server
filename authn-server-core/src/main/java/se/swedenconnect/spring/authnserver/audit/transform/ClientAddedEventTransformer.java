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

import java.time.Instant;
import java.util.Locale;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.AuditEventBuilder;
import se.swedenconnect.spring.audit.AuditEventContext;
import se.swedenconnect.spring.audit.transform.SingleEventTransformer;
import se.swedenconnect.spring.audit.value.MapAuditValue;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.ClientAddedEvent;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClient;

/**
 * Transforms a {@link ClientAddedEvent} into a {@code client_added} audit event. The principal is the system
 * principal, and the data is the {@code client} object.
 *
 * @author Martin Lindström
 */
public class ClientAddedEventTransformer implements SingleEventTransformer<ClientAddedEvent> {

  /** The name of the object describing the client. */
  public static final String CLIENT = "client";

  /** {@inheritDoc} */
  @Override
  public @NonNull AuditEvent transformEvent(final @NonNull ClientAddedEvent event,
      final @NonNull AuditEventContext context) {
    return AuditEventBuilder.builder(context)
        .type(AuthnAuditTypes.CLIENT_ADDED)
        .timestamp(Instant.ofEpochMilli(event.getTimestamp()))
        .principal(AuditEvent.SYSTEM_PRINCIPAL)
        .dataField(client(event.getClient()))
        .build();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Class<ClientAddedEvent> getEventType() {
    return ClientAddedEvent.class;
  }

  /**
   * Creates the {@code client} object, with the members {@code protocol}, {@code id}, {@code organization_number} and
   * {@code source}. The organisation number is left out when the client has none.
   *
   * @param client the client
   * @return a {@link MapAuditValue}
   */
  public static @NonNull MapAuditValue client(final @NonNull KnownClient client) {
    final MapAuditValue.Builder builder = MapAuditValue.builder()
        .name(CLIENT)
        .value("protocol", client.protocol().name().toLowerCase(Locale.ROOT))
        .value("id", client.identifier());
    if (client.organizationNumber() != null) {
      builder.value("organization_number", client.organizationNumber());
    }
    return builder.value("source", client.source()).build();
  }

}
