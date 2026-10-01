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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Adds the default place of the {@link AuthnServerHealthStatus#WARNING} status in the health status order, as a
 * property source of the lowest precedence, so that a deployment that sets
 * {@value #STATUS_ORDER_PROPERTY} itself decides the order.
 * <p>
 * No HTTP mapping is added: Spring Boot answers HTTP 200 for a status that has no mapping. A deployment that maps
 * {@code WARNING} to another code with {@code management.endpoint.health.status.http-mapping} replaces Spring Boot's
 * default mappings, so it maps {@code DOWN} and {@code OUT_OF_SERVICE} too.
 * </p>
 *
 * @author Martin Lindström
 */
public class HealthStatusEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

  /** The property holding the status order. */
  public static final String STATUS_ORDER_PROPERTY = "management.endpoint.health.status.order";

  /** The default status order, the most severe first. */
  public static final String DEFAULT_STATUS_ORDER = "DOWN,OUT_OF_SERVICE,WARNING,UP,UNKNOWN";

  /** The name of the property source. */
  public static final String PROPERTY_SOURCE_NAME = "authnServerHealthDefaults";

  /** {@inheritDoc} */
  @Override
  public void postProcessEnvironment(final @NonNull ConfigurableEnvironment environment,
      final @Nullable SpringApplication application) {
    if (environment.getPropertySources().contains(PROPERTY_SOURCE_NAME)) {
      return;
    }
    environment.getPropertySources().addLast(
        new MapPropertySource(PROPERTY_SOURCE_NAME, Map.of(STATUS_ORDER_PROPERTY, DEFAULT_STATUS_ORDER)));
  }

  /** {@inheritDoc} */
  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE;
  }

}
