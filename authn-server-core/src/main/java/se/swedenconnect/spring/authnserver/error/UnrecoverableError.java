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
package se.swedenconnect.spring.authnserver.error;

import org.jspecify.annotations.NonNull;
import org.springframework.context.MessageSource;

/**
 * An error that makes it impossible to send the user back to the requester, so the user is shown an error page instead.
 * <p>
 * The core defines the errors that do not depend on a protocol, see {@link CommonUnrecoverableError}. Each protocol
 * module adds its own as its request processing is built, which is why this is an interface and not an enum.
 * </p>
 *
 * @author Martin Lindström
 */
public interface UnrecoverableError {

  /**
   * Gets the message code to resolve the error message with, against a {@link MessageSource}.
   *
   * @return the message code
   */
  @NonNull String getMessageCode();

  /**
   * Gets a description of the error, for logs.
   *
   * @return the description
   */
  @NonNull String getDescription();

  /**
   * Gets the HTTP status that the error page is shown with, when the protocol sets one. The default is 500.
   *
   * @return the HTTP status
   */
  default int getHttpStatus() {
    return 500;
  }

}
