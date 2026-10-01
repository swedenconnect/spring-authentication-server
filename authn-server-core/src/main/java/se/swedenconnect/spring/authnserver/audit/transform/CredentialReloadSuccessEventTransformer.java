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

import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.AuditEventBuilder;
import se.swedenconnect.spring.audit.AuditEventContext;
import se.swedenconnect.spring.audit.transform.SingleEventTransformer;
import se.swedenconnect.spring.audit.value.StringAuditValue;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;

/**
 * Transforms a credentials-support {@link SuccessfulCredentialReloadEvent} into an audit event of the type
 * {@code authn_credential_reload_success}. A monitored credential that failed its test was reloaded.
 * <p>
 * The principal is the system principal. The data is the {@code credential_name}.
 * </p>
 *
 * @author Martin Lindström
 */
public class CredentialReloadSuccessEventTransformer
    implements SingleEventTransformer<SuccessfulCredentialReloadEvent> {

  /** {@inheritDoc} */
  @Override
  public @NonNull AuditEvent transformEvent(final @NonNull SuccessfulCredentialReloadEvent event,
      final @NonNull AuditEventContext context) {
    final AuditEventBuilder builder = AuditEventBuilder.builder(context)
        .type(AuthnAuditTypes.AUTHN_CREDENTIAL_RELOAD_SUCCESS)
        .timestamp(Instant.ofEpochMilli(event.getTimestamp()))
        .principal(AuditEvent.SYSTEM_PRINCIPAL)
        .dataField(new StringAuditValue("credential_name", event.getCredentialName()));
    return builder.build();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Class<SuccessfulCredentialReloadEvent> getEventType() {
    return SuccessfulCredentialReloadEvent.class;
  }

}
