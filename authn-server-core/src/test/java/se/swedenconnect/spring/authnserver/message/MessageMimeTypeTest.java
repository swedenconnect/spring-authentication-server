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
package se.swedenconnect.spring.authnserver.message;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link MessageMimeType}.
 *
 * @author Martin Lindström
 */
class MessageMimeTypeTest {

  @Test
  void everyTypeHasItsMimeType() {
    assertThat(MessageMimeType.TEXT_PLAIN.getMimeType()).isEqualTo("text/plain");
    assertThat(MessageMimeType.TEXT_MARKDOWN.getMimeType()).isEqualTo("text/markdown");
    assertThat(MessageMimeType.TEXT_HTML.getMimeType()).isEqualTo("text/html");
    assertThat(MessageMimeType.TEXT_HTML).hasToString("text/html");
  }

  @Test
  void parsingAcceptsTheSamlSpellingAndParameters() {
    assertThat(MessageMimeType.parse("text")).isEqualTo(MessageMimeType.TEXT_PLAIN);
    assertThat(MessageMimeType.parse("text/plain")).isEqualTo(MessageMimeType.TEXT_PLAIN);
    assertThat(MessageMimeType.parse("text/plain;charset=UTF-8")).isEqualTo(MessageMimeType.TEXT_PLAIN);
    assertThat(MessageMimeType.parse("TEXT/MARKDOWN")).isEqualTo(MessageMimeType.TEXT_MARKDOWN);
    assertThat(MessageMimeType.parse("text/html")).isEqualTo(MessageMimeType.TEXT_HTML);
  }

  @Test
  void aMissingMimeTypeMeansPlainText() {
    assertThat(MessageMimeType.parse(null)).isEqualTo(MessageMimeType.TEXT_PLAIN);
    assertThat(MessageMimeType.parse("  ")).isEqualTo(MessageMimeType.TEXT_PLAIN);
  }

  @Test
  void anUnsupportedMimeTypeIsRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> MessageMimeType.parse("application/pdf"))
        .withMessageContaining("application/pdf");
  }

}
