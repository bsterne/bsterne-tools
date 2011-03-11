/*
 * Content Security Policy recommendation bookmarklet
 * Brandon Sterne <bsterne@mozilla.com>
 *
 * Walks through the current document and analyzes content types and
 * sources to provide a policy recommendation
 *
 * Uses Steven Levithan's parseUri implementation documented here:
 * http://blog.stevenlevithan.com/archives/parseuri
 *
 * Copyright (c) 2010 Brandon Sterne
 * Licensed under the MIT license.
 * http://brandon.sternefamily.net/files/mit-license.txt
 */

// return an Array of elements matching the comma-separated tag names passed in
function getElements(tags) {
  var arr = []; tags = tags.split(",");
  for (var i = 0 ; i < tags.length ; i++) {
    var elems = document.getElementsByTagName(tags[i]);
    for (var j = 0 ; j < elems.length ; j++) arr.push(elems[j])
  }
  return arr;
}

// parseUri 1.2.2
// (c) Steven Levithan <stevenlevithan.com>
// MIT License
// http://blog.stevenlevithan.com/archives/parseuri
function parseUri (str) {
  var o   = parseUri.options,
      m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
      uri = {},
      i   = 14;

  while (i--) uri[o.key[i]] = m[i] || "";

  uri[o.q.name] = {};
  uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
    if ($1) uri[o.q.name][$1] = $2;
  });

  return uri;
};

parseUri.options = {
  strictMode: false,
  key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
  q:   {
    name:   "queryKey",
    parser: /(?:^|&)([^&=]*)=?([^&]*)/g
  },
  parser: {
    strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
    loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
  }
};

// keep a list of hosts for each type of content served on this page
var sources = {
  'images': {}, 'media': {}, 'script': {}, 'object': {},
  'frame': {},  'font': {},  'style': {}
};

// store mappings between content-types and CSP directive names
var directives = {
  'images': 'img-src', 'media': 'media-src', 'script': 'script-src',
  'object': 'object-src', 'frame': 'frame-src',  'font': 'font-src',
  'style': 'style-src'
};

// keep track of potential inline script violations
var violations = [];

// return a word with the first letter capitalized
function capWord(w) {
  return w.charAt(0).toUpperCase() + w.slice(1);
}

// return whether or not an object has no properties
function objIsEmpty(obj) {
  for (var prop in obj) {
    if (obj.hasOwnProperty(prop))
      return false;
  }
  return true;
}

// turn a list of sources into proper CSP syntax
function generatePolicyFromSources(sourceList, violations) {
  var policy = "Recommended Policy:\n";
  policy += "allow 'self';";
  for (type in sourceList) {
    // skip types which have no sources specified
    if (objIsEmpty(sourceList[type]))
      continue;
    policy += " " + directives[type] + " " +
              Object.keys(sourceList[type]).join(" ") + ";";
  }
  // add potential inline script violations
  if (violations.length) {
    policy += "\n\n";
    policy += (violations.length == 1) ? "Inline Script Violation:" :
                                         "Inline Script Violations:";
    for (var v = 0 ; v < violations.length ; v++)
      policy += "\n" + (v+1) + ": " + violations[v];
  }
  return policy;
}

// Object.keys was added in ES 5
Object.keys = Object.keys || function(obj) {
  var keys = [];
  for (var key in obj) {
    if (obj.hasOwnProperty(key))
      keys.push(key);
  }
  return keys;
}

// Search the document for various types of content and take note of the
// sources being used for each type
function analyzeContent() {
  // use 'self' for content from this host
  var myHost = parseUri(window.location.href).host;

  /* images */
  var images = getElements("img");
  for (var i = 0 ; i < images.length ; i++) {
    var uriParts = parseUri(images[i].src);
    var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
    // relative URL, use 'self'
    if (host == null) {
      if (!(host in sources.images))
        sources.images["'self'"] = null;
    }
    // absolute URL, store the hostname
    else {
      if (host == myHost)
        host = "'self'";
      if (!(host in sources.images))
        sources.images[host] = null;
    }
  }

  /* favicons also restricted by img-src */
  var linkElems = getElements("link");
  for (var i = 0 ; i < linkElems.length ; i++) {
    if (linkElems[i].getAttribute("rel") == "shortcut icon") {
      var uriParts = parseUri(linkElems[i].href);
      var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
      // relative URL, use 'self'
      if (host == null) {
        if (!(host in sources.images))
          sources.images["'self'"] = null;
      }
      // absolute URL, store the hostname
      else {
        if (host == myHost)
          host = "'self'";
        if (!(host in sources.images))
          sources.images[host] = null;
      }
    }
  }

  /* media: <video> and <audio> */
  var media = getElements("video,audio");
  for (var i = 0 ; i < media.length ; i++) {
    var uriParts = parseUri(media[i].src);
    var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
    // relative URL, use 'self'
    if (host == null) {
      if (!(host in sources.media))
        sources.media["'self'"] = null;
    }
    // absolute URL, store the hostname
    else {
      if (host == myHost)
        host = "'self'";
      if (!(host in sources.media))
        sources.media[host] = null;
    }
  }

  /* external script resources */
  var scripts = getElements("script");
  for (var i = 0 ; i < scripts.length ; i++) {
    var uriParts = parseUri(scripts[i].src);
    var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
    // relative URL, use 'self'
    if (host == null) {
      if (!(host in sources.script))
        sources.script["'self'"] = null;
    }
    // absolute URL, store the hostname
    else {
      if (host == myHost)
        host = "'self'";
      if (!(host in sources.script))
        sources.script[host] = null;
    }
  }

  /* <object>, <applet>, <embed> */
  // object, applet
  // http://www.w3.org/TR/1999/REC-html401-19991224/struct/objects.html#h-13.3
  var objAppl = getElements("object,applet");
  for (var i = 0 ; i < objAppl.length ; i++) {
    // codebase: base URI for classid, data, archive attrs
    if (objAppl[i].hasAttribute("codebase")) {
      var uriParts = parseUri(objAppl[i].getAttribute("codebase"));
      var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
      // relative URL, use 'self'
      if (host == null) {
        if (!(host in sources.object))
          sources.object["'self'"] = null;
      }
      // absolute URL, store the hostname
      else {
        if (host == myHost)
          host = "'self'";
        if (!(host in sources.object))
          sources.object[host] = null;
      }
    }

    // classid: location of an object's implementation.
    // XXX bsterne - spec says this is a URI, but in the wild this usually
    // references a COM registry ID.
    if (objAppl[i].hasAttribute("classid")) {  // applet won't have this
      var uriParts = parseUri(objAppl[i].getAttribute("classid"));
      // Skipping this URL for any non-data-returning protocols, e.g. clsid:.
      if (["http", "https", "ftp", null].indexOf(uriParts["protocol"]) != -1) {
        var host = uriParts["host"];
        // relative URL, use 'self'
        if (host == null) {
          if (!(host in sources.object))
            sources.object["'self'"] = null;
        }
        // absolute URL, store the hostname
        else {
          if (host == myHost)
            host = "'self'";
          if (!(host in sources.object))
            sources.object[host] = null;
        }
      }
    }

    // data: object's or applet's location
    if (objAppl[i].hasAttribute("data")) {  // applet won't have this
      var uriParts = parseUri(objAppl[i].getAttribute("data"));
      var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
      // relative URL, use 'self'
      if (host == null) {
        if (!(host in sources.object))
          sources.object["'self'"] = null;
      }
      // absolute URL, store the hostname
      else {
        if (host == myHost)
          host = "'self'";
        if (!(host in sources.object))
          sources.object[host] = null;
      }
    }

    // archive: space-separated list of URIs of relevant resources
    if (objAppl[i].hasAttribute("archive")) {
      var uriParts = parseUri(objAppl[i].getAttribute("archive"));
      var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
      // relative URL, use 'self'
      if (host == null) {
        if (!(host in sources.object))
          sources.object["'self'"] = null;
      }
      // absolute URL, store the hostname
      else {
        if (host == myHost)
          host = "'self'";
        if (!(host in sources.object))
          sources.object[host] = null;
      }
    }
  }

  /* embed elements */
  var embeds = getElements("embed");
  for (var i = 0 ; i < embeds.length ; i++) {
    var uriParts = parseUri(embeds[i].src);
    var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
    // relative URL, use 'self'
    if (host == null) {
      if (!(host in sources.object))
        sources.object["'self'"] = null;
    }
    // absolute URL, store the hostname
    else {
      if (host == myHost)
        host = "'self'";
      if (!(host in sources.object))
        sources.object[host] = null;
    }
  }

  /* frame, iframe */
  var frameElems = getElements("frame,iframe");
  for (var i = 0 ; i < frameElems.length ; i++) {
    var uriParts = parseUri(frameElems[i].src);
    var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
    // relative URL, use 'self'
    if (host == null) {
      if (!(host in sources.frame))
        sources.frame["'self'"] = null;
    }
    // absolute URL, store the hostname
    else {
      if (host == myHost)
        host = "'self'";
      if (!(host in sources.frame))
        sources.frame[host] = null;
    }
  }

  /* @font-face (downloadable fonts) */
  var stylesheets = {};
  try {
    var stylesheets = document.styleSheets;
  }
  // see http://www.quirksmode.org/dom/w3c_css.html
  catch (e) {}

  for (var i = 0 ; i < stylesheets.length ; i++) {
    // XXX bsterne - apparently, cross-site stylesheets' rules are subject to
    // same-origin.  We'll only be able to make font policy reccommendations
    // based on same-site stylesheets.
    var rules = {};
    try {
      // Firefox, Chrome, Safari, etc.
      rules = stylesheets[i].cssRules;
      // Internet Explorer would use .rules if we can add support
      // rules = stylesheets[i].rules;
    }
    catch (e) { // probably a cross-site stylesheet which we can't read
      continue;
    }
    // XXX bsterne - Chrome can return null for cssRules but not throw
    if (!rules) {
      continue;
    }
    // search stylesheet rules for @font-face
    for (var j = 0 ; j < rules.length ; j++) {
      if (rules[j].type == rules[j].FONT_FACE_RULE) {
        var src = rules[j].style.getPropertyValue("src");
        if (src) {
          // remove url() wrapper from font-face src
          var url = src.replace(/^url['"]*/, "").replace(/['"]*\)$/, "");
          var uriParts = parseUri(url);
          var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
          // relative URL, use 'self'
          if (host == null) {
            if (!(host in sources.font))
              sources.font["'self'"] = null;
          }
          // absolute URL, store the hostname
          else {
            if (host == myHost)
              host = "'self'";
            if (!(host in sources.font))
              sources.font[host] = null;
          }
        }
      }
    }
  }

  /* external stylesheets */
  var linkElems = getElements("link");
  for (var i = 0 ; i < linkElems.length ; i++) {
    if (linkElems[i].getAttribute("rel") == "stylesheet") {
      var uriParts = parseUri(linkElems[i].href);
      var host = (uriParts["protocol"] == "data") ? "data:" : uriParts["host"];
      // relative URL, use 'self'
      if (host == null) {
        if (!(host in sources.style))
          sources.style["'self'"] = null;
      }
      // absolute URL, store the hostname
      else {
        if (host == myHost)
          host = "'self'";
        if (!(host in sources.style))
          sources.style[host] = null;
      }
    }
  }

  /* inline script violations */
  var allElems = getElements("*");
  for (var e = 0 ; e < allElems.length ; e++) {
    // check attributes of the element
    var elem = allElems[e];
    var attrs = [];
    for (var key in elem.attributes) {
      if (!isNaN(key)) {
        attrs.push(elem.attributes[key].name);
      }
    }

    for (var i = 0 ; i < attrs.length ; i++) {
      if (attrs[i].match(/^on/)) {
        var attr_pairs = []
        for (var j = 0 ; j < attrs.length ; j++) {
          // shorten the white space to make the output more readable
          var attr_val = elem.attributes[attrs[j]].nodeValue.replace(/\s+/g, " ");
          attr_pairs.push(attrs[j] + '="' + attr_val + '"');
        }
        var error = attrs[i] + " on element <" + elem.nodeName + " " +
          attr_pairs.join(" ") + ">";
        violations.push("event handling attribute: " + error);
      }
    }

    // if elem is a script tag, see if it has a body
    if (elem.nodeName === "SCRIPT" && elem.text.length) {
      var script = (elem.text.length > 100) ? elem.text.substr(0, 100) + " ... " :
                                              elem.text;
      violations.push("internal script node: " + script);
    }
  }

  // return the recommended policy and any inline script violations
  alert( generatePolicyFromSources(sources, violations) );
}

analyzeContent();
