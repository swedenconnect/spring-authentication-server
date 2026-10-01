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
package se.swedenconnect.spring.authnserver.autoconfigure.storage;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * The condition of {@link ConditionalOnRedisInUse}. An invalid value does not match; it is reported by
 * {@link AuthnServerStorageAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class OnRedisInUseCondition extends SpringBootCondition {

  /** {@inheritDoc} */
  @Override
  public @NonNull ConditionOutcome getMatchOutcome(final @NonNull ConditionContext context,
      final @NonNull AnnotatedTypeMetadata metadata) {
    try {
      final List<String> settings = StorageSettings.redisSettings(context.getEnvironment());
      return settings.isEmpty()
          ? ConditionOutcome.noMatch("nothing is kept in Redis")
          : ConditionOutcome.match("%s keep state in Redis".formatted(settings));
    }
    catch (final IllegalArgumentException e) {
      return ConditionOutcome.noMatch(e.getMessage());
    }
  }

}
