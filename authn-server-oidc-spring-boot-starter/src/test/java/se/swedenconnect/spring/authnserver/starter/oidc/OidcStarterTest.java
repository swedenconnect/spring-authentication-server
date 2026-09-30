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
package se.swedenconnect.spring.authnserver.starter.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.ClassUtils;

/**
 * Tests that an application using the OIDC starter starts without the SAML module.
 *
 * @author Martin Lindström
 */
@SpringBootTest(classes = OidcStarterTest.TestApplication.class, properties = {
    "authn-server.base-url=https://op.example.com",
    "authn-server.oidc.enabled=true"
})
class OidcStarterTest {

  /** The test application. */
  @SpringBootApplication
  static class TestApplication {
  }

  @Autowired
  private SecurityFilterChain filterChain;

  @Test
  void theApplicationStartsWithoutTheSamlModule() {
    assertThat(ClassUtils.isPresent("se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer", null))
        .isFalse();
    assertThat(this.filterChain).isNotNull();
  }

}
