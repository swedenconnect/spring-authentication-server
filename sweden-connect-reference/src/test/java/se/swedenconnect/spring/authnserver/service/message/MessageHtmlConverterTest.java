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
package se.swedenconnect.spring.authnserver.service.message;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;

/**
 * Tests for {@link MessageHtmlConverter}.
 *
 * @author Martin Lindström
 */
class MessageHtmlConverterTest {

  private final MessageHtmlConverter converter = new MessageHtmlConverter();

  @Test
  void plainTextIsEscapedAndKeepsItsLineBreaks() throws Exception {
    final String html = this.converter.toHtml(message("Line <one>\nLine\ttwo & three"), MessageMimeType.TEXT_PLAIN);
    assertThat(html)
        .startsWith("<div style=")
        .contains("Line &lt;one&gt;<br />Line&emsp;two &amp; three")
        .endsWith("</div>");
  }

  @Test
  void markdownIsRenderedToHtml() throws Exception {
    final String html = this.converter.toHtml(message("### Heading\n\nThis is a **bold** text"),
        MessageMimeType.TEXT_MARKDOWN);
    assertThat(html).contains("<h3>Heading</h3>").contains("<strong>bold</strong>");
  }

  @Test
  void markdownTablesAreSupported() throws Exception {
    final String html = this.converter.toHtml(message("| A | B |\n|---|---|\n| 1 | 2 |"),
        MessageMimeType.TEXT_MARKDOWN);
    assertThat(html).contains("<table>").contains("<td>1</td>");
  }

  @Test
  void markdownWithLinksOrImagesIsRejected() {
    assertThatThrownBy(() -> this.converter.toHtml(message("[link](https://evil.example.com)"),
        MessageMimeType.TEXT_MARKDOWN))
        .isInstanceOf(MessageProcessingException.class);
    assertThatThrownBy(() -> this.converter.toHtml(message("![image](https://evil.example.com/x.png)"),
        MessageMimeType.TEXT_MARKDOWN))
        .isInstanceOf(MessageProcessingException.class);
  }

  @Test
  void allowedHtmlIsStrippedOfItsAttributes() throws Exception {
    final String html = this.converter.toHtml(message("<p style=\"color:red\" onclick=\"x()\">Hello <b>you</b></p>"),
        MessageMimeType.TEXT_HTML);
    assertThat(html).isEqualTo("<p>Hello <b>you</b></p>");
  }

  @Test
  void htmlWithTagsThatAreNotAllowedIsRejected() {
    assertThatThrownBy(() -> this.converter.toHtml(message("<p>Hi</p><script>alert(1)</script>"),
        MessageMimeType.TEXT_HTML))
        .isInstanceOf(MessageProcessingException.class)
        .hasMessageContaining("not allowed");
  }

  private static LocalizedMessage message(final String text) {
    return new LocalizedMessage("en", Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)));
  }

}
