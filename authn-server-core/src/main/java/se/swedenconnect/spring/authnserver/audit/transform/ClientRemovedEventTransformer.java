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

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.AuditEventBuilder;
import se.swedenconnect.spring.audit.AuditEventContext;
import se.swedenconnect.spring.audit.transform.SingleEventTransformer;
import se.swedenconnect.spring.audit.value.StringAuditValue;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.ClientRemovedEvent;

/**
 * Transforms a {@link ClientRemovedEvent} into a {@code client_removed} audit event. The principal is the system
 * principal, and the data is the {@code client} object, see {@link ClientAddedEventTransformer#client}, and the
 * {@code reason}.
 *
 * @author Martin Lindström
 */
public class ClientRemovedEventTransformer implements SingleEventTransformer<ClientRemovedEvent> {

  /** {@inheritDoc} */
  @Override
  public @NonNull AuditEvent transformEvent(final @NonNull ClientRemovedEvent event,
      final @NonNull AuditEventContext context) {
    return AuditEventBuilder.builder(context)
        .type(AuthnAuditTypes.CLIENT_REMOVED)
        .timestamp(Instant.ofEpochMilli(event.getTimestamp()))
        .principal(AuditEvent.SYSTEM_PRINCIPAL)
        .dataField(ClientAddedEventTransformer.client(event.getClient()))
        .dataField(new StringAuditValue("reason", event.getReason()))
        .build();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Class<ClientRemovedEvent> getEventType() {
    return ClientRemovedEvent.class;
  }

}
