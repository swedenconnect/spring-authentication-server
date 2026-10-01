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
package se.swedenconnect.spring.authnserver.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The Sweden Connect reference authentication server: a SAML Identity Provider and an OpenID Provider where the user
 * authentication is simulated.
 *
 * @author Martin Lindström
 */
@SpringBootApplication
public class ReferenceApplication {

  /**
   * Starts the server.
   *
   * @param args the program arguments
   */
  public static void main(final String[] args) {
    SpringApplication.run(ReferenceApplication.class, args);
  }

}
