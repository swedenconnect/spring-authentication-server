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

import org.springframework.boot.health.contributor.Status;

/**
 * The health status that the authentication server adds to those of Spring Boot.
 *
 * @author Martin Lindström
 */
public final class AuthnServerHealthStatus {

  /**
   * Something has failed, but the server still works. Mapped to HTTP 200 by default, and placed between {@code UP} and
   * the failing statuses in the status order, see {@link HealthStatusEnvironmentPostProcessor}.
   */
  public static final Status WARNING = new Status("WARNING");

  // Hidden constructor
  private AuthnServerHealthStatus() {
  }

}
