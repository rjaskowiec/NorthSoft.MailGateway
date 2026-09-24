import sanitizeHtml from "sanitize-html";

export function sanitizeEmailHtml(html: string): string {
  if (typeof html !== "string") {
    return "";
  }

  const trimmed = html.trim();
  if (!trimmed) {
    return "";
  }

  const sanitized = sanitizeHtml(trimmed, {
    allowedTags: [
      "html", "head", "body", "title", "style",
      "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "p", "a", "ul", "ol",
      "nl", "li", "b", "i", "strong", "em", "strike", "code", "hr", "br", "div",
      "table", "thead", "caption", "tbody", "tr", "th", "td", "pre", "span", "center",
      "u", "s", "sub", "sup", "img"
    ],
    nonTextTags: [
      "script", "iframe", "object", "embed", "form", "input", "button", "select",
      "textarea", "option", "base", "applet", "frame", "frameset", "noscript", "svg", "math"
    ],
    allowedAttributes: {
      a: ["href", "name", "target", "title", "rel", "style", "class", "id"],
      img: ["src", "srcset", "alt", "title", "width", "height", "style", "class", "id", "align", "border"],
      table: ["width", "height", "align", "valign", "bgcolor", "border", "cellpadding", "cellspacing", "style", "class", "id", "colspan", "rowspan"],
      td: ["width", "height", "align", "valign", "bgcolor", "border", "cellpadding", "cellspacing", "style", "class", "id", "colspan", "rowspan"],
      th: ["width", "height", "align", "valign", "bgcolor", "border", "cellpadding", "cellspacing", "style", "class", "id", "colspan", "rowspan"],
      tr: ["width", "height", "align", "valign", "bgcolor", "style", "class", "id"],
      div: ["style", "class", "id", "align"],
      span: ["style", "class", "id"],
      p: ["style", "class", "id", "align"],
      center: ["style", "class", "id"],
      "*": ["style", "class", "id", "dir", "lang"]
    },
    allowedSchemes: ["http", "https", "mailto", "tel", "cid"],
    allowedSchemesAppliedToAttributes: ["href", "src"],
    allowProtocolRelative: false,
    allowVulnerableTags: true
  });

  return sanitized.trim();
}
