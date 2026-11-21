// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The crate's XML (decision D2): a pull reader over a borrowed `&str` and an
//! escaper. No dependency, no DTD, no processing instruction, no CDATA, a
//! depth cap ([`MAX_DEPTH`]); namespaces are plain attributes.

use std::borrow::Cow;

/// How deep elements may nest.
pub const MAX_DEPTH: usize = 32;

/// Why a text is not the XML this reader takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    /// The text ended inside an element, or held no element.
    #[error("xml: unexpected end")]
    Eof,
    /// Not well-formed, with where.
    #[error("xml: {0}")]
    Syntax(&'static str),
    /// A closing tag that closes nothing open, or something else.
    #[error("xml: mismatched closing tag")]
    Mismatch,
    /// More than [`MAX_DEPTH`] elements open at once.
    #[error("xml: nesting too deep")]
    TooDeep,
    /// An entity that is not one of the five, a character reference to a
    /// character XML does not have, or one that never ends.
    #[error("xml: bad entity")]
    Entity,
    /// A DTD or any other `<!` declaration.
    #[error("xml: DTD refused")]
    Dtd,
    /// `<?...?>`.
    #[error("xml: processing instruction refused")]
    ProcessingInstruction,
    /// `<![CDATA[`.
    #[error("xml: CDATA refused")]
    Cdata,
}

/// An opening tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Start<'a> {
    /// The name, prefix included.
    pub name: &'a str,
    /// The tag ends in `/>`: no [`Event::End`] follows.
    pub self_closing: bool,
    attrs: &'a str,
}

impl<'a> Start<'a> {
    /// The attributes as written, values still escaped, in order.
    pub fn raw_attrs(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        let src = self.attrs;
        let mut pos = 0;
        std::iter::from_fn(move || next_attr(src, &mut pos).ok().flatten())
    }

    /// The value of the first attribute called `name`, decoded.
    ///
    /// # Errors
    /// [`XmlError::Entity`] when the value has a bad entity.
    pub fn attr(&self, name: &str) -> Result<Option<Cow<'a, str>>, XmlError> {
        self.raw_attrs()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| unescape(v))
            .transpose()
    }
}

/// One step through a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// `<name ...>` or `<name .../>`.
    Start(Start<'a>),
    /// `</name>`; not sent for a self-closing tag.
    End(&'a str),
    /// Character data, decoded; borrowed unless it had an entity.
    Text(Cow<'a, str>),
}

/// A pull reader over one document (one root element). It holds the name of
/// each open element, [`MAX_DEPTH`] of them, and nothing else.
#[derive(Debug)]
pub struct Reader<'a> {
    src: &'a str,
    pos: usize,
    /// Where the last opening tag began.
    tag: usize,
    stack: [&'a str; MAX_DEPTH],
    depth: usize,
    started: bool,
    finished: bool,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `src`.
    #[must_use]
    pub fn new(src: &'a str) -> Self {
        Self {
            src,
            pos: 0,
            tag: 0,
            stack: [""; MAX_DEPTH],
            depth: 0,
            started: false,
            finished: false,
        }
    }

    /// The next event; `None` after the root element closed and nothing but
    /// white space follows.
    ///
    /// # Errors
    /// The text is not well-formed, or is more than this XML takes.
    pub fn next_event(&mut self) -> Result<Option<Event<'a>>, XmlError> {
        loop {
            let rest = &self.src[self.pos..];
            if rest.is_empty() {
                return if self.finished {
                    Ok(None)
                } else {
                    Err(XmlError::Eof)
                };
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                let raw = &rest[..end];
                self.pos += end;
                if self.depth == 0 {
                    // Outside the root only white space may stand.
                    if raw.bytes().all(is_space) {
                        continue;
                    }
                    return Err(XmlError::Syntax("text outside the root element"));
                }
                return Ok(Some(Event::Text(unescape(raw)?)));
            }
            if self.finished {
                return Err(XmlError::Syntax("content after the root element"));
            }
            if let Some(body) = rest.strip_prefix("<!--") {
                let end = body.find("-->").ok_or(XmlError::Eof)?;
                self.pos += 4 + end + 3;
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                return Err(XmlError::Cdata);
            }
            if rest.starts_with("<!") {
                return Err(XmlError::Dtd);
            }
            if rest.starts_with("<?") {
                return Err(XmlError::ProcessingInstruction);
            }
            if let Some(after) = rest.strip_prefix("</") {
                let name = take_name(after)?;
                let mut at = name.len();
                at += after[at..].bytes().take_while(|b| is_space(*b)).count();
                if !after[at..].starts_with('>') {
                    return Err(if after[at..].is_empty() {
                        XmlError::Eof
                    } else {
                        XmlError::Syntax("closing tag")
                    });
                }
                if self.depth == 0 || self.stack[self.depth - 1] != name {
                    return Err(XmlError::Mismatch);
                }
                self.depth -= 1;
                self.finished = self.depth == 0;
                self.pos += 2 + at + 1;
                return Ok(Some(Event::End(name)));
            }
            // A start tag.
            let after = &rest[1..];
            let name = take_name(after)?;
            let attrs_from = name.len();
            let (attrs_len, self_closing, tag_len) = scan_attrs(&after[attrs_from..])?;
            let attrs = &after[attrs_from..attrs_from + attrs_len];
            if self.depth >= MAX_DEPTH {
                return Err(XmlError::TooDeep);
            }
            self.started = true;
            self.tag = self.pos;
            self.pos += 1 + attrs_from + tag_len;
            if self_closing {
                self.finished = self.depth == 0;
            } else {
                self.stack[self.depth] = name;
                self.depth += 1;
            }
            return Ok(Some(Event::Start(Start {
                name,
                self_closing,
                attrs,
            })));
        }
    }
}

/// The root element's opening tag; the rest of the text is not read.
///
/// # Errors
/// The text does not start with an element.
pub fn root(xml: &str) -> Result<Start<'_>, XmlError> {
    match Reader::new(xml).next_event()? {
        Some(Event::Start(s)) => Ok(s),
        _ => Err(XmlError::Syntax("no root element")),
    }
}

/// The elements just inside the root element, each whole as it is written,
/// in order; none for a root that closes itself or holds no element. Text
/// and comments between them are left out.
///
/// # Errors
/// The text is not one well-formed element.
pub fn children(xml: &str) -> Result<Vec<&str>, XmlError> {
    let mut r = Reader::new(xml);
    if !matches!(r.next_event()?, Some(Event::Start(_))) {
        return Err(XmlError::Syntax("no root element"));
    }
    let mut out = Vec::new();
    // How many elements are open inside the root, and where the one just
    // inside it began.
    let (mut depth, mut from) = (0usize, 0usize);
    while let Some(e) = r.next_event()? {
        match e {
            Event::Start(s) => {
                if depth == 0 {
                    from = r.tag;
                }
                if !s.self_closing {
                    depth += 1;
                } else if depth == 0 {
                    out.push(&xml[from..r.pos]);
                }
            }
            // The root's own end comes with nothing open inside it.
            Event::End(_) if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    out.push(&xml[from..r.pos]);
                }
            }
            Event::End(_) | Event::Text(_) => {}
        }
    }
    Ok(out)
}

/// The text just inside the first element called `name` (empty for an
/// element with none), or `None` when there is no such element.
///
/// # Errors
/// The text is malformed before the element is found.
pub fn text_of<'a>(xml: &'a str, name: &str) -> Result<Option<Cow<'a, str>>, XmlError> {
    let mut r = Reader::new(xml);
    while let Some(e) = r.next_event()? {
        if let Event::Start(s) = e {
            if s.name == name {
                if s.self_closing {
                    return Ok(Some(Cow::Borrowed("")));
                }
                return Ok(Some(match r.next_event()? {
                    Some(Event::Text(t)) => t,
                    _ => Cow::Borrowed(""),
                }));
            }
        }
    }
    Ok(None)
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// The name at the start of `s`.
fn take_name(s: &str) -> Result<&str, XmlError> {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if c.is_ascii_alphabetic() || c == '_' || c == ':' || !c.is_ascii() => {}
        Some(_) => return Err(XmlError::Syntax("name")),
        None => return Err(XmlError::Eof),
    }
    let end = chars
        .find(|(_, c)| {
            !(c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-' | '.') || !c.is_ascii())
        })
        .map_or(s.len(), |(i, _)| i);
    Ok(&s[..end])
}

/// The next attribute of `src` (the part of a tag after its name, up to its
/// end): name and raw value; `None` at the end of the list.
fn next_attr<'a>(src: &'a str, pos: &mut usize) -> Result<Option<(&'a str, &'a str)>, XmlError> {
    let had_space = {
        let n = src[*pos..].bytes().take_while(|b| is_space(*b)).count();
        *pos += n;
        n > 0
    };
    let rest = &src[*pos..];
    if rest.is_empty() || rest.starts_with('>') || rest.starts_with("/>") {
        return Ok(None);
    }
    if !had_space {
        return Err(XmlError::Syntax("attribute without a space before it"));
    }
    let name = take_name(rest)?;
    let mut at = name.len();
    at += rest[at..].bytes().take_while(|b| is_space(*b)).count();
    if !rest[at..].starts_with('=') {
        return Err(XmlError::Syntax("attribute without a value"));
    }
    at += 1;
    at += rest[at..].bytes().take_while(|b| is_space(*b)).count();
    let quote = match rest[at..].chars().next() {
        Some(q @ ('"' | '\'')) => q,
        Some(_) => return Err(XmlError::Syntax("attribute value not quoted")),
        None => return Err(XmlError::Eof),
    };
    at += 1;
    let len = rest[at..].find(quote).ok_or(XmlError::Eof)?;
    let value = &rest[at..at + len];
    if value.contains('<') {
        return Err(XmlError::Syntax("'<' in an attribute value"));
    }
    *pos += at + len + 1;
    Ok(Some((name, value)))
}

/// Walks a tag's attributes (`s` starts right after the name): the length
/// of the attribute part, whether the tag is self-closing, and the length of
/// the whole rest of the tag.
fn scan_attrs(s: &str) -> Result<(usize, bool, usize), XmlError> {
    let mut pos = 0;
    while next_attr(s, &mut pos)?.is_some() {}
    // `pos` is after the white space before the end; the attributes end
    // before it.
    let attrs_len = s[..pos]
        .trim_end_matches(|c: char| c.is_ascii() && is_space(c as u8))
        .len();
    let rest = &s[pos..];
    if rest.starts_with("/>") {
        Ok((attrs_len, true, pos + 2))
    } else if rest.starts_with('>') {
        Ok((attrs_len, false, pos + 1))
    } else {
        Err(XmlError::Eof)
    }
}

/// `raw` with its entities replaced by what they stand for.
///
/// # Errors
/// [`XmlError::Entity`].
pub fn unescape(raw: &str) -> Result<Cow<'_, str>, XmlError> {
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find(';').ok_or(XmlError::Entity)?;
        let ent = &after[..end];
        match ent {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let digits = ent.strip_prefix('#').ok_or(XmlError::Entity)?;
                let (digits, radix) = match digits.strip_prefix('x') {
                    Some(h) => (h, 16),
                    None => (digits, 10),
                };
                if digits.is_empty() || digits.len() > 8 {
                    return Err(XmlError::Entity);
                }
                let n = u32::from_str_radix(digits, radix).map_err(|_| XmlError::Entity)?;
                let c = char::from_u32(n)
                    .filter(|c| in_range(*c))
                    .ok_or(XmlError::Entity)?;
                out.push(c);
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

/// XML's `Char`.
fn in_range(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// `s` for text or an attribute value, escaped as Go's `xml.EscapeText`
/// does: the five characters, tab, newline and carriage return as
/// references, anything XML has no character for as U+FFFD.
#[must_use]
pub fn escape(s: &str) -> Cow<'_, str> {
    if s.chars()
        .all(|c| in_range(c) && !matches!(c, '"' | '\'' | '&' | '<' | '>' | '\t' | '\n' | '\r'))
    {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c if in_range(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The events of `xml` as `(kind, name-or-text)` pairs.
    fn events(xml: &str) -> Result<Vec<(char, String)>, XmlError> {
        let mut r = Reader::new(xml);
        let mut out = Vec::new();
        while let Some(e) = r.next_event()? {
            match e {
                Event::Start(s) => {
                    out.push(('<', s.name.to_owned()));
                    if s.self_closing {
                        out.push(('>', s.name.to_owned()));
                    }
                }
                Event::End(n) => out.push(('>', n.to_owned())),
                Event::Text(t) => out.push(('t', t.into_owned())),
            }
        }
        Ok(out)
    }

    #[test]
    fn attributes_in_either_quote_and_the_first_wins() {
        let s = root(r#"<iq from='focus@auth.host' id="123" type='set' id="dup"/>"#).unwrap();
        assert_eq!(s.name, "iq");
        assert!(s.self_closing);
        assert_eq!(s.attr("from").unwrap().as_deref(), Some("focus@auth.host"));
        assert_eq!(s.attr("id").unwrap().as_deref(), Some("123"));
        assert_eq!(s.attr("type").unwrap().as_deref(), Some("set"));
        assert_eq!(s.attr("to").unwrap(), None);
        // TestExtractXMLAttr: an element with none.
        let p = root("<presence/>").unwrap();
        assert_eq!(p.attr("from").unwrap(), None);
    }

    /// Go reads `type` from the first `type=` anywhere in the text; the root
    /// is read here, and a child's attribute is not the root's.
    #[test]
    fn a_childs_attribute_is_not_the_roots() {
        let xml = r#"<iq id="outer" xmlns="jabber:client"><iq id="inner" type="error"/><body>id="zzz" type="error"</body></iq>"#;
        let s = root(xml).unwrap();
        assert_eq!(s.attr("id").unwrap().as_deref(), Some("outer"));
        assert_eq!(s.attr("type").unwrap(), None);
        let ev = events(xml).unwrap();
        assert_eq!(
            ev,
            [
                ('<', "iq".into()),
                ('<', "iq".into()),
                ('>', "iq".into()),
                ('<', "body".into()),
                ('t', r#"id="zzz" type="error""#.into()),
                ('>', "body".into()),
                ('>', "iq".into()),
            ]
        );
    }

    #[test]
    fn a_gt_inside_an_attribute_value_does_not_end_the_tag() {
        let s = root(r#"<a b=">" c='x>y'/>"#).unwrap();
        assert_eq!(s.attr("b").unwrap().as_deref(), Some(">"));
        assert_eq!(s.attr("c").unwrap().as_deref(), Some("x>y"));
    }

    /// Go's `TestExtractBOSHInner` and `TestSplitXMLElements`
    /// (`conn_test.go:380-420`): what stands inside a BOSH body, element by
    /// element. Go cuts the text between the first `>` and the last
    /// `</body>` and counts tags; here the body is read as XML.
    #[test]
    fn the_elements_inside_a_root_as_go_s_bosh_helpers_take_them() {
        // extractBOSHInner: (input, want); the children joined are its text.
        let inner: &[(&str, &str)] = &[
            (
                r#"<body sid="x" xmlns="http://jabber.org/protocol/httpbind"><iq id="1"/><presence/></body>"#,
                r#"<iq id="1"/><presence/>"#,
            ),
            (
                r#"<body sid="x" xmlns="http://jabber.org/protocol/httpbind"/>"#,
                "",
            ),
            (r#"<body sid="x"></body>"#, ""),
            (
                r#"<body sid="abc"><stream:features><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features></body>"#,
                r#"<stream:features><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>"#,
            ),
        ];
        for (input, want) in inner {
            assert_eq!(children(input).unwrap().concat(), *want, "{input}");
        }
        // splitXMLElements: (input, count), inside a body here.
        let split: &[(&str, usize)] = &[
            (r#"<iq id="1"/><presence from="x"/>"#, 2),
            (
                "<stream:features><mechanisms><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>",
                1,
            ),
            (
                r#"<iq id="1"/><presence><x><item/></x></presence><message><body>hi</body></message>"#,
                3,
            ),
            ("", 0),
        ];
        for (input, count) in split {
            let body = format!("<body>{input}</body>");
            let got = children(&body).unwrap();
            assert_eq!(got.len(), *count, "{input}");
            assert_eq!(got.concat(), *input);
        }
        assert_eq!(
            children(r#"<body><iq id="1"/><presence><x><item/></x></presence><message><body>hi</body></message></body>"#).unwrap(),
            [
                r#"<iq id="1"/>"#,
                "<presence><x><item/></x></presence>",
                "<message><body>hi</body></message>"
            ]
        );
    }

    /// What Go's tag counter gets wrong and an XML reader does not: a `>`
    /// inside a value, an element of the root's own name inside it, white
    /// space, comments and text between the elements.
    #[test]
    fn the_elements_inside_a_root_are_cut_where_they_end() {
        assert_eq!(
            children("<body><iq id='g1'><q a='1>2'/></iq><iq id='g2'/></body>").unwrap(),
            ["<iq id='g1'><q a='1>2'/></iq>", "<iq id='g2'/>"]
        );
        assert_eq!(
            children("<body>\n  <a/>\n <!-- <x/> --> text <b>t</b>\n</body>\n").unwrap(),
            ["<a/>", "<b>t</b>"]
        );
        assert_eq!(
            children("<x><x><x/></x><x/></x>").unwrap(),
            ["<x><x/></x>", "<x/>"]
        );
        assert!(children("<body><a></body>").is_err());
        assert!(children("<body><a/>").is_err());
        assert!(children("<body/><a/>").is_err());
        assert!(children("").is_err());
    }

    #[test]
    fn the_five_entities_and_numeric_references() {
        let xml = "<m a='&lt;&gt;&amp;&quot;&apos;&#65;&#x42;&#x1F600;'>&lt;b&gt; &amp; &#233;</m>";
        let s = root(xml).unwrap();
        assert_eq!(s.attr("a").unwrap().as_deref(), Some("<>&\"'AB\u{1F600}"));
        let ev = events(xml).unwrap();
        assert_eq!(ev[1], ('t', "<b> & \u{e9}".into()));
        // A value with no entity is borrowed, not copied.
        let plain = root("<m a='plain'/>").unwrap().attr("a").unwrap().unwrap();
        assert!(matches!(plain, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn bad_entities_are_errors() {
        for bad in [
            "<m>&bogus;</m>",
            "<m>&amp</m>",
            "<m>&#;</m>",
            "<m>&#xD800;</m>",
            "<m>&#x110000;</m>",
            "<m>&#0;</m>",
            "<m>&#99999999999;</m>",
            "<m a='&nope;'/>",
        ] {
            let r = events(bad).and_then(|_| root(bad)?.attr("a").map(|_| ()));
            assert!(r.is_err(), "{bad}");
        }
    }

    #[test]
    fn what_this_xml_does_not_take() {
        for (bad, why) in [
            ("<!DOCTYPE x><a/>", XmlError::Dtd),
            ("<?xml version='1.0'?><a/>", XmlError::ProcessingInstruction),
            ("<a><![CDATA[x]]></a>", XmlError::Cdata),
        ] {
            assert_eq!(events(bad), Err(why), "{bad}");
        }
        // A comment is skipped, not reported.
        assert_eq!(events("<a><!-- x --></a>").unwrap().len(), 2);
    }

    #[test]
    fn malformed_input_is_an_error() {
        for bad in [
            "",
            "   ",
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "</a>",
            "<a/><b/>",
            "<a/>junk",
            "junk<a/>",
            "<a",
            "<a b>",
            "<a b=1/>",
            "<a b='x/>",
            "<a b='<'/>",
            "<1a/>",
            "<a b='1'c='2'/>",
            "< a/>",
            "<a></ a>",
        ] {
            assert!(events(bad).is_err(), "{bad:?} was taken");
        }
        // Whitespace around the root is fine.
        assert!(events(" \n<a/>\n").is_ok());
        assert!(events("<a>  \n </a>").is_ok());
    }

    #[test]
    fn nesting_is_capped_at_32() {
        let deep = |n: usize| format!("{}{}", "<a>".repeat(n), "</a>".repeat(n));
        assert!(events(&deep(MAX_DEPTH)).is_ok());
        assert_eq!(events(&deep(MAX_DEPTH + 1)), Err(XmlError::TooDeep));
        // A bomb of opens is refused before it is read to its end.
        assert_eq!(events(&"<a>".repeat(100_000)), Err(XmlError::TooDeep));
    }

    #[test]
    fn prefixes_and_namespaces_are_plain() {
        let xml = r#"<stream:features xmlns:stream="http://etherx.jabber.org/streams"><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>"#;
        let s = root(xml).unwrap();
        assert_eq!(s.name, "stream:features");
        assert_eq!(
            s.attr("xmlns:stream").unwrap().as_deref(),
            Some("http://etherx.jabber.org/streams")
        );
        assert!(text_of(xml, "mechanism").unwrap().as_deref() == Some("ANONYMOUS"));
        assert_eq!(text_of(xml, "jid").unwrap(), None);
    }

    #[test]
    fn the_bind_result_gives_its_jid() {
        let xml = "<iq id='bind_1' type='result' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>abcdef0123456789@meet.example/uXyZ</jid></bind></iq>";
        assert_eq!(
            text_of(xml, "jid").unwrap().as_deref(),
            Some("abcdef0123456789@meet.example/uXyZ")
        );
    }

    /// Go's `xml.EscapeText`.
    #[test]
    fn escaping_is_gos() {
        assert_eq!(escape("plain"), "plain");
        assert!(matches!(escape("plain"), std::borrow::Cow::Borrowed(_)));
        assert_eq!(
            escape("a<b>&\"'\t\n\r"),
            "a&lt;b&gt;&amp;&#34;&#39;&#x9;&#xA;&#xD;"
        );
        assert_eq!(escape("\u{1}x\u{fffe}"), "\u{fffd}x\u{fffd}");
        assert_eq!(escape("\u{e9}\u{1F600}"), "\u{e9}\u{1F600}");
    }

    /// What the writer writes the reader reads back.
    #[test]
    fn escaped_text_reads_back() {
        let raw = "x<y>&\"'\t\n\rz \u{e9}";
        let xml = format!("<m a=\"{}\">{}</m>", escape(raw), escape(raw));
        let s = root(&xml).unwrap();
        assert_eq!(s.attr("a").unwrap().as_deref(), Some(raw));
        assert_eq!(events(&xml).unwrap()[1], ('t', raw.into()));
    }
}
