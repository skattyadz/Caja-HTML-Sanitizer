var html4 = require("./lib/html4.js");

// Copyright (C) 2006 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @fileoverview
 * An HTML sanitizer that can satisfy a variety of security policies.
 *
 * <p>
 * The HTML sanitizer is built around a SAX parser and HTML element and
 * attributes schemas.
 *
 * If the cssparser is loaded, inline styles are sanitized using the
 * css property and value schemas.  Else they are remove during
 * sanitization.
 *
 * If it exists, uses parseCssDeclarations, sanitizeCssProperty,  cssSchema
 *
 * @author mikesamuel@gmail.com
 * @author jasvir@gmail.com
 * \@requires html4, URI
 * \@overrides window
 * \@provides html, html_sanitize
 */

// The Turkish i seems to be a non-issue, but abort in case it is.
if ('I'.toLowerCase() !== 'i') { throw 'I/i problem'; }

/**
 * \@namespace
 */
var html = (function(html4) {

    // The keys of this object must be 'quoted' or JSCompiler will mangle them!
    // This is a partial list -- lookupEntity() uses the host browser's parser
    // (when available) to implement full entity lookup.
    // Note that entities are in general case-sensitive; the uppercase ones are
    // explicitly defined by HTML5 (presumably as compatibility).
    var ENTITIES = {
        'lt': '<',
        'LT': '<',
        'gt': '>',
        'GT': '>',
        'amp': '&',
        'AMP': '&',
        'quot': '"',
        'apos': '\'',
        'nbsp': '\u00a0'
    };

    // Patterns for types of entity/character reference names.
    var decimalEscapeRe = /^#(\d+)$/;
    var hexEscapeRe = /^#x([0-9A-Fa-f]+)$/;
    // contains every entity per http://www.w3.org/TR/2011/WD-html5-20110113/named-character-references.html
    var safeEntityNameRe = /^[A-Za-z][A-za-z0-9]+$/;
    // Used as a hook to invoke the browser's entity parsing. <textarea> is used
    // because its content is parsed for entities but not tags.
    // TODO(kpreid): This retrieval is a kludge and leads to silent loss of
    // functionality if the document isn't available.
    var entityLookupElement =
        ('undefined' !== typeof window && window['document'])
            ? window['document'].createElement('textarea') : null;
    /**
     * Decodes an HTML entity.
     *
     * {\@updoc
     * $ lookupEntity('lt')
     * # '<'
     * $ lookupEntity('GT')
     * # '>'
     * $ lookupEntity('amp')
     * # '&'
     * $ lookupEntity('nbsp')
     * # '\xA0'
     * $ lookupEntity('apos')
     * # "'"
     * $ lookupEntity('quot')
     * # '"'
     * $ lookupEntity('#xa')
     * # '\n'
     * $ lookupEntity('#10')
     * # '\n'
     * $ lookupEntity('#x0a')
     * # '\n'
     * $ lookupEntity('#010')
     * # '\n'
     * $ lookupEntity('#x00A')
     * # '\n'
     * $ lookupEntity('Pi')      // Known failure
     * # '\u03A0'
     * $ lookupEntity('pi')      // Known failure
     * # '\u03C0'
     * }
     *
     * @param {string} name the content between the '&' and the ';'.
     * @return {string} a single unicode code-point as a string.
     */
    function lookupEntity(name) {
        // TODO: entity lookup as specified by HTML5 actually depends on the
        // presence of the ";".
        if (ENTITIES.hasOwnProperty(name)) { return ENTITIES[name]; }
        var m = name.match(decimalEscapeRe);
        if (m) {
            return String.fromCharCode(parseInt(m[1], 10));
        } else if (!!(m = name.match(hexEscapeRe))) {
            return String.fromCharCode(parseInt(m[1], 16));
        } else if (entityLookupElement && safeEntityNameRe.test(name)) {
            entityLookupElement.innerHTML = '&' + name + ';';
            var text = entityLookupElement.textContent;
            ENTITIES[name] = text;
            return text;
        } else {
            return '&' + name + ';';
        }
    }

    function decodeOneEntity(_, name) {
        return lookupEntity(name);
    }

    var nulRe = /\0/g;
    function stripNULs(s) {
        return s.replace(nulRe, '');
    }

    var ENTITY_RE_1 = /&(#[0-9]+|#[xX][0-9A-Fa-f]+|\w+);/g;
    var ENTITY_RE_2 = /^(#[0-9]+|#[xX][0-9A-Fa-f]+|\w+);/;
    /**
     * The plain text of a chunk of HTML CDATA which possibly containing.
     *
     * {\@updoc
     * $ unescapeEntities('')
     * # ''
     * $ unescapeEntities('hello World!')
     * # 'hello World!'
     * $ unescapeEntities('1 &lt; 2 &amp;&AMP; 4 &gt; 3&#10;')
     * # '1 < 2 && 4 > 3\n'
     * $ unescapeEntities('&lt;&lt <- unfinished entity&gt;')
     * # '<&lt <- unfinished entity>'
     * $ unescapeEntities('/foo?bar=baz&copy=true')  // & often unescaped in URLS
     * # '/foo?bar=baz&copy=true'
     * $ unescapeEntities('pi=&pi;&#x3c0;, Pi=&Pi;\u03A0') // FIXME: known failure
     * # 'pi=\u03C0\u03c0, Pi=\u03A0\u03A0'
     * }
     *
     * @param {string} s a chunk of HTML CDATA.  It must not start or end inside
     *     an HTML entity.
     */
    function unescapeEntities(s) {
	if(s) {
	    return s.replace(ENTITY_RE_1, decodeOneEntity);
	}
	else {
	    return s;
	}
    }

    var looseAmpRe = /&([^a-z#]|#(?:[^0-9x]|x(?:[^0-9a-f]|$)|$)|$)/gi;
    var ltRe = /[<]/g;
    var gtRe = />/g;

    /**
     * Escape entities in RCDATA that can be escaped without changing the meaning.
     * {\@updoc
     * $ normalizeRCData('1 < 2 &&amp; 3 > 4 &amp;& 5 &lt; 7&8')
     * # '1 &lt; 2 &amp;&amp; 3 &gt; 4 &amp;&amp; 5 &lt; 7&amp;8'
     * }
     */
    function normalizeRCData(rcdata) {
	if(rcdata) {
	    return rcdata
                .replace(looseAmpRe, '&amp;$1')
                .replace(ltRe, '&lt;')
                .replace(gtRe, '&gt;');
	}
	else {
	    return rcdata;
	}
    }

    // TODO(felix8a): validate sanitizer regexs against the HTML5 grammar at
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html

    // We initially split input so that potentially meaningful characters
    // like '<' and '>' are separate tokens, using a fast dumb process that
    // ignores quoting.  Then we walk that token stream, and when we see a
    // '<' that's the start of a tag, we use ATTR_RE to extract tag
    // attributes from the next token.  That token will never have a '>'
    // character.  However, it might have an unbalanced quote character, and
    // when we see that, we combine additional tokens to balance the quote.

    var ATTR_RE = new RegExp(
        '^\\s*' +
            '([-.:\\w]+)' +             // 1 = Attribute name
            '(?:' + (
            '\\s*(=)\\s*' +           // 2 = Is there a value?
                '(' + (                   // 3 = Attribute value
                // TODO(felix8a): maybe use backref to match quotes
                '(\")[^\"]*(\"|$)' +    // 4, 5 = Double-quoted string
                    '|' +
                    '(\')[^\']*(\'|$)' +    // 6, 7 = Single-quoted string
                    '|' +
                    // Positive lookahead to prevent interpretation of
                    // <foo a= b=c> as <foo a='b=c'>
                    // TODO(felix8a): might be able to drop this case
                    '(?=[a-z][-\\w]*\\s*=)' +
                    '|' +
                    // Unquoted value that isn't an attribute name
                    // (since we didn't match the positive lookahead above)
                    '[^\"\'\\s]*' ) +
                ')' ) +
            ')?',
        'i');

    // bitmask for tags with special parsing, like <script> and <textarea>
    var EFLAGS_TEXT = html4.eflags['CDATA'] | html4.eflags['RCDATA'];

    // Parsing strategy is to split input into parts that might be lexically
    // meaningful (every ">" becomes a separate part), and then recombine
    // parts if we discover they're in a different context.

    // TODO(felix8a): Significant performance regressions from -legacy,
    // tested on
    //    Chrome 18.0
    //    Firefox 11.0
    //    IE 6, 7, 8, 9
    //    Opera 11.61
    //    Safari 5.1.3
    // Many of these are unusual patterns that are linearly slower and still
    // pretty fast (eg 1ms to 5ms), so not necessarily worth fixing.

    // TODO(felix8a): "<script> && && && ... <\/script>" is slower on all
    // browsers.  The hotspot is htmlSplit.

    // TODO(felix8a): "<p title='>>>>...'><\/p>" is slower on all browsers.
    // This is partly htmlSplit, but the hotspot is parseTagAndAttrs.

    // TODO(felix8a): "<a><\/a><a><\/a>..." is slower on IE9.
    // "<a>1<\/a><a>1<\/a>..." is faster, "<a><\/a>2<a><\/a>2..." is faster.

    // TODO(felix8a): "<p<p<p..." is slower on IE[6-8]

    var continuationMarker = {};

    function continuationMaker(h, parts, initial, state, param) {
        return function () {
            parseCPS(h, parts, initial, state, param);
        };
    }

    function parseCPS(h, parts, initial, state, param) {
        try {
            if (h.startDoc && initial == 0) { h.startDoc(param); }
            var m, p, tagName;
            for (var pos = initial, end = parts.length; pos < end;) {
                var current = parts[pos++];
                var next = parts[pos];
                switch (current) {
                    case '&':
                        if (ENTITY_RE_2.test(next)) {
                            if (h.pcdata) {
                                h.pcdata('&' + next, param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                            pos++;
                        } else {
                            if (h.pcdata) { h.pcdata("&amp;", param, continuationMarker,
                                continuationMaker(h, parts, pos, state, param));
                            }
                        }
                        break;
                    case '<\/':
                        if ((m = /^([-\w:]+)[^\'\"]*/.exec(next))) {
                            if (m[0].length === next.length && parts[pos + 1] === '>') {
                                // fast case, no attribute parsing needed
                                pos += 2;
                                tagName = m[1].toLowerCase();
                                if (h.endTag) {
                                    h.endTag(tagName, param, continuationMarker,
                                        continuationMaker(h, parts, pos, state, param));
                                }
                            } else {
                                // slow case, need to parse attributes
                                // TODO(felix8a): do we really care about misparsing this?
                                pos = parseEndTag(
                                    parts, pos, h, param, continuationMarker, state);
                            }
                        } else {
                            if (h.pcdata) {
                                h.pcdata('&lt;/', param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                        }
                        break;
                    case '<':
                        if (m = /^([-\w:]+)\s*\/?/.exec(next)) {
                            if (m[0].length === next.length && parts[pos + 1] === '>') {
                                // fast case, no attribute parsing needed
                                pos += 2;
                                tagName = m[1].toLowerCase();
                                if (h.startTag) {
                                    h.startTag(tagName, [], param, continuationMarker,
                                        continuationMaker(h, parts, pos, state, param));
                                }
                                // tags like <script> and <textarea> have special parsing
                                var eflags = html4.ELEMENTS[tagName];
                                if (eflags & EFLAGS_TEXT) {
                                    var tag = { name: tagName, next: pos, eflags: eflags };
                                    pos = parseText(
                                        parts, tag, h, param, continuationMarker, state);
                                }
                            } else {
                                // slow case, need to parse attributes
                                pos = parseStartTag(
                                    parts, pos, h, param, continuationMarker, state);
                            }
                        } else {
                            if (h.pcdata) {
                                h.pcdata('&lt;', param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                        }
                        break;
                    case '<\!--':
                        // The pathological case is n copies of '<\!--' without '-->', and
                        // repeated failure to find '-->' is quadratic.  We avoid that by
                        // remembering when search for '-->' fails.
                        if (!state.noMoreEndComments) {
                            // A comment <\!--x--> is split into three tokens:
                            //   '<\!--', 'x--', '>'
                            // We want to find the next '>' token that has a preceding '--'.
                            // pos is at the 'x--'.
                            for (p = pos + 1; p < end; p++) {
                                if (parts[p] === '>' && /--$/.test(parts[p - 1])) { break; }
                            }
                            if (p < end) {
                                if (h.comment) {
                                    var comment = parts.slice(pos, p).join('');
                                    h.comment(
                                        comment.substr(0, comment.length - 2), param,
                                        continuationMarker,
                                        continuationMaker(h, parts, p + 1, state, param));
                                }
                                pos = p + 1;
                            } else {
                                state.noMoreEndComments = true;
                            }
                        }
                        if (state.noMoreEndComments) {
                            if (h.pcdata) {
                                h.pcdata('&lt;!--', param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                        }
                        break;
                    case '<\!':
                        if (!/^\w/.test(next)) {
                            if (h.pcdata) {
                                h.pcdata('&lt;!', param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                        } else {
                            // similar to noMoreEndComment logic
                            if (!state.noMoreGT) {
                                for (p = pos + 1; p < end; p++) {
                                    if (parts[p] === '>') { break; }
                                }
                                if (p < end) {
                                    pos = p + 1;
                                } else {
                                    state.noMoreGT = true;
                                }
                            }
                            if (state.noMoreGT) {
                                if (h.pcdata) {
                                    h.pcdata('&lt;!', param, continuationMarker,
                                        continuationMaker(h, parts, pos, state, param));
                                }
                            }
                        }
                        break;
                    case '<?':
                        // similar to noMoreEndComment logic
                        if (!state.noMoreGT) {
                            for (p = pos + 1; p < end; p++) {
                                if (parts[p] === '>') { break; }
                            }
                            if (p < end) {
                                pos = p + 1;
                            } else {
                                state.noMoreGT = true;
                            }
                        }
                        if (state.noMoreGT) {
                            if (h.pcdata) {
                                h.pcdata('&lt;?', param, continuationMarker,
                                    continuationMaker(h, parts, pos, state, param));
                            }
                        }
                        break;
                    case '>':
                        if (h.pcdata) {
                            h.pcdata("&gt;", param, continuationMarker,
                                continuationMaker(h, parts, pos, state, param));
                        }
                        break;
                    case '':
                        break;
                    default:
                        if (h.pcdata) {
                            h.pcdata(current, param, continuationMarker,
                                continuationMaker(h, parts, pos, state, param));
                        }
                        break;
                }
            }
            if (h.endDoc) { h.endDoc(param); }
        } catch (e) {
            if (e !== continuationMarker) { throw e; }
        }
    }

    function parseEndTag(parts, pos, h, param, continuationMarker, state) {
        var tag = parseTagAndAttrs(parts, pos);
        // drop unclosed tags
        if (!tag) { return parts.length; }
        if (h.endTag) {
            h.endTag(tag.name, param, continuationMarker,
                continuationMaker(h, parts, pos, state, param));
        }
        return tag.next;
    }

    function parseStartTag(parts, pos, h, param, continuationMarker, state) {
        var tag = parseTagAndAttrs(parts, pos);
        // drop unclosed tags
        if (!tag) { return parts.length; }
        if (h.startTag) {
            h.startTag(tag.name, tag.attrs, param, continuationMarker,
                continuationMaker(h, parts, tag.next, state, param));
        }
        // tags like <script> and <textarea> have special parsing
        if (tag.eflags & EFLAGS_TEXT) {
            return parseText(parts, tag, h, param, continuationMarker, state);
        } else {
            return tag.next;
        }
    }

    var endTagRe = {};

    // Tags like <script> and <textarea> are flagged as CDATA or RCDATA,
    // which means everything is text until we see the correct closing tag.
    function parseText(parts, tag, h, param, continuationMarker, state) {
        var end = parts.length;
        if (!endTagRe.hasOwnProperty(tag.name)) {
            endTagRe[tag.name] = new RegExp('^' + tag.name + '(?:[\\s\\/]|$)', 'i');
        }
        var re = endTagRe[tag.name];
        var first = tag.next;
        var p = tag.next + 1;
        for (; p < end; p++) {
            if (parts[p - 1] === '<\/' && re.test(parts[p])) { break; }
        }
        if (p < end) { p -= 1; }
        var buf = parts.slice(first, p).join('');
        if (tag.eflags & html4.eflags['CDATA']) {
            if (h.cdata) {
                h.cdata(buf, param, continuationMarker,
                    continuationMaker(h, parts, p, state, param));
            }
        } else if (tag.eflags & html4.eflags['RCDATA']) {
            if (h.rcdata) {
                h.rcdata(normalizeRCData(buf), param, continuationMarker,
                    continuationMaker(h, parts, p, state, param));
            }
        } else {
            throw new Error('bug');
        }
        return p;
    }

    // at this point, parts[pos-1] is either "<" or "<\/".
    function parseTagAndAttrs(parts, pos) {
        var m = /^([-\w:]+)/.exec(parts[pos]);
        var tag = {};
        tag.name = m[1].toLowerCase();
        tag.eflags = html4.ELEMENTS[tag.name];
        var buf = parts[pos].substr(m[0].length);
        // Find the next '>'.  We optimistically assume this '>' is not in a
        // quoted context, and further down we fix things up if it turns out to
        // be quoted.
        var p = pos + 1;
        var end = parts.length;
        for (; p < end; p++) {
            if (parts[p] === '>') { break; }
            buf += parts[p];
        }
        if (end <= p) { return void 0; }
        var attrs = [];
        while (buf !== '') {
            m = ATTR_RE.exec(buf);
            if (!m) {
                // No attribute found: skip garbage
                buf = buf.replace(/^[\s\S][^a-z\s]*/, '');

            } else if ((m[4] && !m[5]) || (m[6] && !m[7])) {
                // Unterminated quote: slurp to the next unquoted '>'
                var quote = m[4] || m[6];
                var sawQuote = false;
                var abuf = [buf, parts[p++]];
                for (; p < end; p++) {
                    if (sawQuote) {
                        if (parts[p] === '>') { break; }
                    } else if (0 <= parts[p].indexOf(quote)) {
                        sawQuote = true;
                    }
                    abuf.push(parts[p]);
                }
                // Slurp failed: lose the garbage
                if (end <= p) { break; }
                // Otherwise retry attribute parsing
                buf = abuf.join('');
                continue;

            } else {
                // We have an attribute
                var aName = m[1].toLowerCase();
                var aValue = m[2] ? decodeValue(m[3]) : '';
                attrs.push(aName, aValue);
                buf = buf.substr(m[0].length);
            }
        }
        tag.attrs = attrs;
        tag.next = p + 1;
        return tag;
    }

    function decodeValue(v) {
        var q = v.charCodeAt(0);
        if (q === 0x22 || q === 0x27) { // " or '
            v = v.substr(1, v.length - 2);
        }
        return unescapeEntities(stripNULs(v));
    }

    // Export both quoted and unquoted names for Closure linkage.
    var html = {};
    html.unescapeEntities = html['unescapeEntities'] = unescapeEntities;
    return html;
})(html4);

module.exports = html.unescapeEntities
