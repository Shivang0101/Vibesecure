import DOMPurify from "dompurify";

// Comments support basic formatting, so they're stored and shown as HTML.
export function CommentBody({ html }: { html: string }) {
  return <div className="prose" dangerouslySetInnerHTML={{ __html: html }} />;
}

// The same, done right: sanitized before it's rendered.
export function SafeCommentBody({ html }: { html: string }) {
  return <div className="prose" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
