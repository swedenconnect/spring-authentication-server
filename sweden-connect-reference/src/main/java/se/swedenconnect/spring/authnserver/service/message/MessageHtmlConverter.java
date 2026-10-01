/*
 * Copyright 2016-2026 Sweden Connect
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

import java.util.List;
import java.util.Objects;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;
import org.jspecify.annotations.NonNull;
import org.springframework.web.util.HtmlUtils;

import com.vladsch.flexmark.ext.tables.TablesExtension;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.parser.ParserEmulationProfile;
import com.vladsch.flexmark.util.data.MutableDataSet;

import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;

/**
 * Turns a sign message or a user message into HTML that is safe to include in a page.
 * <p>
 * Plain text is escaped and shown in a monospace font with its line breaks. Markdown is rendered into HTML. HTML, and
 * the HTML rendered from Markdown, is rejected if it holds a tag that is not allowed, and the allowed tags are
 * stripped of all attributes.
 * </p>
 *
 * @author Martin Lindström
 */
public class MessageHtmlConverter {

  /** The HTML tags that may appear in a message. */
  private static final String[] ALLOWED_HTML_TAGS = { "b", "blockquote", "br", "caption", "cite", "code",
      "dd", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6",
      "i", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong",
      "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul" };

  /** The safelist used when cleaning HTML. It removes all attributes. */
  private final Safelist htmlSafelist;

  /** The safelist used when checking for tags that are not allowed. It allows all attributes. */
  private final Safelist htmlCheckSafelist;

  /** Markdown parser. */
  private final Parser markdownParser;

  /** HTML renderer for Markdown. */
  private final HtmlRenderer markdownHtmlRenderer;

  /**
   * Constructor.
   */
  public MessageHtmlConverter() {
    this.htmlSafelist = new Safelist();
    this.htmlSafelist.addTags(ALLOWED_HTML_TAGS);

    this.htmlCheckSafelist = new AllAttributesSafelist();
    this.htmlCheckSafelist.addTags(ALLOWED_HTML_TAGS);

    final MutableDataSet options = new MutableDataSet();
    options.setFrom(ParserEmulationProfile.MARKDOWN);
    options.set(Parser.EXTENSIONS, List.of(TablesExtension.create()));
    this.markdownParser = Parser.builder(options).build();
    this.markdownHtmlRenderer = HtmlRenderer.builder(options).build();
  }

  /**
   * Turns a message into HTML that is safe to show.
   *
   * @param message the message, holding the Base64 encoding of its text
   * @param mimeType the MIME type of the message
   * @return the HTML
   * @throws MessageProcessingException if the message cannot be decoded, or holds HTML that is not allowed
   */
  public @NonNull String toHtml(final @NonNull LocalizedMessage message, final @NonNull MessageMimeType mimeType)
      throws MessageProcessingException {
    Objects.requireNonNull(message, "message must not be null");
    Objects.requireNonNull(mimeType, "mimeType must not be null");

    final String text;
    try {
      text = message.getText();
    }
    catch (final IllegalArgumentException e) {
      throw new MessageProcessingException("Invalid message encoding", e);
    }
    return switch (mimeType) {
      case TEXT_PLAIN -> this.textToHtml(text);
      case TEXT_MARKDOWN -> this.markdownToHtml(text);
      case TEXT_HTML -> this.validateAndCleanHtml(text);
    };
  }

  /**
   * Turns plain text into HTML.
   *
   * @param text the plain text
   * @return the HTML
   */
  protected @NonNull String textToHtml(final @NonNull String text) {
    return "<div style='font-family: \"Lucida Console\", Monaco, monospace'>"
        + HtmlUtils.htmlEscape(text)
            .replaceAll("(\r\n|\n\r|\r|\n)", "<br />")
            .replace("\t", "&emsp;")
        + "</div>";
  }

  /**
   * Turns Markdown into HTML.
   *
   * @param markdown the Markdown text
   * @return the HTML
   * @throws MessageProcessingException if the rendered HTML holds tags that are not allowed
   */
  protected @NonNull String markdownToHtml(final @NonNull String markdown) throws MessageProcessingException {
    return this.validateAndCleanHtml(this.markdownHtmlRenderer.render(this.markdownParser.parse(markdown)));
  }

  /**
   * Checks that the HTML holds only allowed tags, and removes all attributes.
   *
   * @param html the HTML
   * @return the cleaned HTML
   * @throws MessageProcessingException if the HTML holds tags that are not allowed
   */
  protected @NonNull String validateAndCleanHtml(final @NonNull String html) throws MessageProcessingException {
    if (!Jsoup.isValid(html, this.htmlCheckSafelist)) {
      throw new MessageProcessingException("Message holds invalid HTML or HTML tags that are not allowed");
    }
    return Jsoup.clean(html, this.htmlSafelist);
  }

  /**
   * A {@link Safelist} that allows all attributes, used when checking for tags that are not allowed.
   */
  private static class AllAttributesSafelist extends Safelist {

    /** {@inheritDoc} */
    @Override
    public boolean isSafeAttribute(final @NonNull String tagName, final @NonNull Element el,
        final @NonNull Attribute attr) {
      return true;
    }

  }

}
