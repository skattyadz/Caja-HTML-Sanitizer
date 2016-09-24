
This is a fork of [theSmaw/Caja-HTML-Sanitizer](https://github.com/theSmaw/Caja-HTML-Sanitizer) just for the `unescapeEntities` method.

## Installation

```
npm install sanitizer.unescapeEntities
```

## Require

```
var unescapeEntities = require('sanitizer.unescapeEntities');
```

## Use

See /test/test-sanitzer.js for full documentation.

```
unescapeEntities('your string'); // The plain text of a chunk of HTML CDATA which possibly containing.
```

## Caveats

Skattyadz disclaimer: I've just deleted most of the API then done some tree shaking. I don't understand this code

Original disclaimer: It's use this at your own risk really - Caja HTML Sanitizer was written by people far cleverer than me. I have just repackaged it to solve a problem I had (sanitization on a Node server). It seems to work, and it passes all its tests in re-packaged form - however I don't fully understand its internals so cannot guarantee its security.


## More information

http://code.google.com/p/google-caja/source/browse/trunk/src/com/google/caja/plugin/html-sanitizer.js
