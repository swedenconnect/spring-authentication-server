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
package se.swedenconnect.spring.authnserver.registry;

import java.io.Serial;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Thrown when a client registry backend fails, for example when a metadata source or a resolver service cannot be
 * reached.
 * <p>
 * A requester that the backend does not know is not an error. That is told by a {@code null} record.
 * </p>
 *
 * @author Martin Lindström
 */
public class ClientRegistryException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param message the error message
   */
  public ClientRegistryException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public ClientRegistryException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
