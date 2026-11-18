/* ==========================================================================
   osint-tools.js: the four self-audit tools on tools.html
   Tool 1: Browser Fingerprint Viewer
   Tool 2: Phishing URL and Punycode Analyzer
   Tool 3: Local EXIF Metadata Inspector
   Tool 4: Password Strength and Breach-Pattern Checker

   Privacy rule for this file: no fetch, no uploads, no storage.
   Security rule for this file: visitor data is only ever written to the page
   with textContent, so it can never run as code.
   ========================================================================== */

"use strict";

/* Shared helpers ========================================================== */

// Creates an element with an optional class name and text.
function createEl(tag, className, text) {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
}

// Adds one row to a table. The first cell is a row heading.
function addTableRow(tbody, cells) {
  const row = tbody.insertRow();
  cells.forEach(function (text, index) {
    const cell = createEl(index === 0 ? "th" : "td", index === 1 ? "cell-value" : "", text);
    if (index === 0) {
      cell.scope = "row";
    }
    row.appendChild(cell);
  });
}

// Builds a table with a caption and column headings, ready for rows.
function createResultTable(captionText, headings) {
  const wrap = createEl("div", "table-wrap");
  const table = createEl("table");
  const headRow = table.createTHead().insertRow();
  const tbody = table.createTBody();

  table.createCaption().textContent = captionText;
  headings.forEach(function (heading) {
    const cell = createEl("th", "", heading);
    cell.scope = "col";
    headRow.appendChild(cell);
  });
  wrap.appendChild(table);
  return { wrap: wrap, tbody: tbody };
}

// FNV-1a: a small hash that turns any text into a short ID.
function hashText(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}


/* ==========================================================================
   TOOL 1: BROWSER FINGERPRINT VIEWER
   ========================================================================== */

// Draws hidden text. Small rendering differences identify the device.
function getCanvasHash() {
  try {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    canvas.width = 240;
    canvas.height = 60;
    context.fillStyle = "#1E3E62";
    context.fillRect(10, 10, 100, 30);
    context.fillStyle = "#00D2FF";
    context.font = "16px Arial";
    context.fillText("Vanguard fingerprint", 14, 32);
    return hashText(canvas.toDataURL());
  } catch (error) {
    return "Blocked by this browser";
  }
}

// Asks the graphics system which GPU is installed.
function getGraphicsCard() {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) {
      return "WebGL unavailable";
    }
    const info = gl.getExtension("WEBGL_debug_renderer_info");
    return info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
  } catch (error) {
    return "Blocked by this browser";
  }
}

function runFingerprint() {
  const nav = window.navigator;
  const notExposed = "Not exposed";
  const rows = [
    ["User-Agent", nav.userAgent, "Names your browser, version and operating system."],
    ["Platform", nav.platform || notExposed, "Shows the type of system you are using."],
    ["Languages", (nav.languages || [nav.language]).join(", "), "Hints at where you live and what you read."],
    ["Timezone", Intl.DateTimeFormat().resolvedOptions().timeZone || notExposed, "Narrows down your region, even behind a VPN."],
    ["Screen Size", screen.width + " x " + screen.height + " px", "Helps separate your device from others."],
    ["Window Size", window.innerWidth + " x " + window.innerHeight + " px", "Changes with your setup and toolbars."],
    ["Colour Depth", screen.colorDepth + "-bit", "Describes your display hardware."],
    ["Pixel Ratio", String(window.devicePixelRatio), "Separates high-density screens from standard ones."],
    ["CPU Cores", String(nav.hardwareConcurrency || notExposed), "Reveals part of your hardware."],
    ["Device Memory", nav.deviceMemory ? nav.deviceMemory + " GB or more" : notExposed, "Reveals part of your hardware."],
    ["Touch Points", String(nav.maxTouchPoints), "Shows whether you use a touch screen."],
    ["Cookies Enabled", nav.cookieEnabled ? "Yes" : "No", "Shows whether sites can store identifiers."],
    ["Graphics Card", getGraphicsCard(), "Can identify your exact GPU model."],
    ["Canvas Hash", getCanvasHash(), "Tracks devices without storing any cookie."]
  ];

  const table = document.getElementById("fpTable");
  rows.forEach(function (row) {
    addTableRow(table, row);
  });

  // Combines every value into one short ID.
  const combined = rows.map(function (row) {
    return row[1];
  }).join("|");
  document.getElementById("fpId").textContent = hashText(combined);
}

runFingerprint();


/* ==========================================================================
   TOOL 2: PHISHING URL AND PUNYCODE ANALYZER
   The link is only treated as text. It is never opened or requested.
   ========================================================================== */

const urlForm = document.getElementById("urlForm");
const urlInput = document.getElementById("urlInput");
const urlError = document.getElementById("urlError");
const urlOutput = document.getElementById("urlOutput");

// Real domains for brands that phishing sites often copy.
const BRAND_DOMAINS = {
  paypal: ["paypal.com"],
  google: ["google.com", "google.com.pk"],
  microsoft: ["microsoft.com"],
  apple: ["apple.com"],
  amazon: ["amazon.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  netflix: ["netflix.com"],
  linkedin: ["linkedin.com"],
  github: ["github.com"],
  easypaisa: ["easypaisa.com.pk"],
  jazzcash: ["jazzcash.com.pk"],
  meezanbank: ["meezanbank.com"]
};

// Letters from other alphabets, and digits, that look like Latin letters.
const LOOKALIKES = {
  "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
  "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l",
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
  "0": "o", "1": "l", "3": "e", "5": "s"
};

const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "loan", "work", "rest", "cam", "icu", "buzz", "support"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"];
const BAIT_WORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password", "banking", "wallet"];
const TWO_PART_ENDINGS = ["com.pk", "edu.pk", "gov.pk", "net.pk", "org.pk", "co.uk", "ac.uk", "org.uk", "com.au", "co.in", "co.jp"];

// Decodes a punycode label such as "pple-43d" (RFC 3492 algorithm).
function decodePunycode(input) {
  const BASE = 36;
  const output = [];
  const dash = input.lastIndexOf("-");
  let n = 128;
  let i = 0;
  let bias = 72;
  let index = dash > 0 ? dash + 1 : 0;

  for (let j = 0; j < dash; j += 1) {
    output.push(input.charCodeAt(j));
  }

  while (index < input.length) {
    const oldI = i;
    let weight = 1;

    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) {
        throw new Error("Invalid punycode");
      }
      const code = input.charCodeAt(index);
      index += 1;
      const digit = code >= 48 && code <= 57 ? code - 22 : code >= 97 && code <= 122 ? code - 97 : BASE;
      if (digit >= BASE) {
        throw new Error("Invalid punycode");
      }
      i += digit * weight;
      const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < threshold) {
        break;
      }
      weight *= BASE - threshold;
    }

    // Adjusts the bias so the next number is decoded correctly.
    const count = output.length + 1;
    let delta = oldI === 0 ? Math.floor((i - oldI) / 700) : Math.floor((i - oldI) / 2);
    delta += Math.floor(delta / count);
    let steps = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      steps += BASE;
    }
    bias = steps + Math.floor((36 * delta) / (delta + 38));

    n += Math.floor(i / count);
    i %= count;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint.apply(null, output);
}

// Turns "xn--pple-43d.com" into its real Unicode form.
function decodeHost(host) {
  return host.split(".").map(function (label) {
    if (label.indexOf("xn--") !== 0) {
      return label;
    }
    try {
      return decodePunycode(label.slice(4));
    } catch (error) {
      return label;
    }
  }).join(".");
}

// Replaces lookalike characters so "раypa1" can be compared with "paypal".
function toSkeleton(text) {
  return Array.from(text.toLowerCase()).map(function (ch) {
    return LOOKALIKES[ch] || ch;
  }).join("");
}

// Finds the part of a host that a person actually registered.
function getRegisteredDomain(host) {
  const labels = host.split(".");
  const lastTwo = labels.slice(-2).join(".");
  const size = TWO_PART_ENDINGS.indexOf(lastTwo) !== -1 ? 3 : 2;
  return labels.slice(-size).join(".");
}

// Counts the single-letter edits needed to turn one word into another.
function editDistance(a, b) {
  let previous = [];
  for (let j = 0; j <= b.length; j += 1) {
    previous.push(j);
  }
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current.push(Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost));
    }
    previous = current;
  }
  return previous[b.length];
}

// Names the alphabets used in a piece of text.
function detectScripts(text) {
  const scripts = [];
  if (/\p{Script=Latin}/u.test(text)) { scripts.push("Latin"); }
  if (/\p{Script=Cyrillic}/u.test(text)) { scripts.push("Cyrillic"); }
  if (/\p{Script=Greek}/u.test(text)) { scripts.push("Greek"); }
  return scripts;
}

// Compares the domain with each protected brand.
function checkBrands(unicodeHost, registered, addFinding) {
  const name = registered.split(".")[0];
  const skeleton = toSkeleton(name);

  // Whole words only, so "pineapple.com" is not mistaken for "apple".
  const hostWords = toSkeleton(unicodeHost).split(/[.-]/);

  Object.keys(BRAND_DOMAINS).some(function (brand) {
    if (BRAND_DOMAINS[brand].indexOf(registered) !== -1) {
      return true;
    }
    if (name === brand) {
      // Could be a real regional site such as amazon.co.uk, so only warn.
      addFinding("medium", 25, "Unfamiliar ending for " + brand, "The usual address is " + BRAND_DOMAINS[brand][0] + ". Confirm that " + registered + " is official.");
      return true;
    }
    if (skeleton === brand) {
      addFinding("high", 50, "Lookalike of " + brand, "The domain looks like " + BRAND_DOMAINS[brand][0] + " but is a different address.");
      return true;
    }
    if (hostWords.indexOf(brand) !== -1) {
      addFinding("high", 50, "Brand name used as bait", "The address mentions " + brand + ", but the real owner is " + registered + ".");
      return true;
    }
    if (brand.length >= 5 && editDistance(skeleton, brand) === 1) {
      addFinding("medium", 25, "Possible typosquat of " + brand, "The name is one letter away from " + BRAND_DOMAINS[brand][0] + ".");
      return true;
    }
    return false;
  });
}

// Runs every check and returns the findings and details of the link.
function analyzeUrl(rawInput) {
  const findings = [];
  let score = 0;

  function addFinding(level, points, title, detail) {
    findings.push({ level: level, title: title, detail: detail });
    score += points;
  }

  // Links pasted without a scheme are read as https.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawInput);
  const isScriptScheme = /^(javascript|data|vbscript|file):/i.test(rawInput);
  const text = hasScheme || isScriptScheme ? rawInput : "https://" + rawInput;
  const parsed = new URL(text);

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    addFinding("high", 60, "Dangerous link type", "Links starting with " + parsed.protocol + " can run code or open local files.");
    return { findings: findings, score: score, parsed: parsed, unicodeHost: "", registered: "" };
  }

  // The URL parser converts Unicode to punycode, so decode it again for display.
  const host = parsed.hostname.toLowerCase();
  const unicodeHost = decodeHost(host);
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.charAt(0) === "[";

  if (!isIp && host.indexOf(".") === -1) {
    throw new Error("No domain");
  }

  const registered = isIp ? host : getRegisteredDomain(host);
  const unicodeRegistered = isIp ? host : getRegisteredDomain(unicodeHost);

  if (parsed.protocol === "http:") {
    addFinding("medium", 15, "No HTTPS encryption", "Anything sent to this address can be read or changed in transit.");
  }
  if (parsed.username || parsed.password) {
    addFinding("high", 50, "Hidden destination using @", "Browsers ignore the text before @. This link really goes to " + host + ".");
  }
  if (isIp) {
    addFinding("high", 35, "IP address instead of a domain", "Legitimate services rarely send people to a bare IP address.");
  }
  if (host.indexOf("xn--") !== -1) {
    addFinding("high", 30, "Punycode domain", "The address " + host + " is displayed as " + unicodeHost + ".");
  }

  const scripts = detectScripts(unicodeHost);
  if (scripts.length > 1) {
    addFinding("high", 35, "Mixed alphabets", "This domain mixes " + scripts.join(" and ") + " letters, a common homograph trick.");
  } else if (scripts.length === 1 && scripts[0] !== "Latin") {
    addFinding("medium", 20, "Non-Latin characters", "These characters may imitate familiar letters.");
  }

  if (!isIp) {
    checkBrands(unicodeHost, unicodeRegistered, addFinding);

    const subdomains = host.split(".").length - registered.split(".").length - (host.indexOf("www.") === 0 ? 1 : 0);
    if (subdomains >= 3) {
      addFinding("medium", 15, "Too many subdomains", "Long chains of subdomains can hide the real owner of a site.");
    }
    const ending = host.split(".").pop();
    if (SUSPICIOUS_TLDS.indexOf(ending) !== -1) {
      addFinding("medium", 15, "Risky domain ending", "The ." + ending + " ending is cheap and often abused.");
    }
    if (SHORTENERS.indexOf(host) !== -1) {
      addFinding("medium", 20, "Shortened link", "The final destination is hidden behind this service.");
    }
    if ((unicodeRegistered.split(".")[0].match(/-/g) || []).length >= 2) {
      addFinding("low", 5, "Many hyphens", "Phishing domains often join several words together.");
    }
  }

  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    addFinding("medium", 10, "Unusual port", "Port " + parsed.port + " is not normally used by public websites.");
  }

  const bait = BAIT_WORDS.filter(function (word) {
    return (host + parsed.pathname + parsed.search).toLowerCase().indexOf(word) !== -1;
  });
  if (bait.length > 0) {
    addFinding("low", 5, "Urgency or login wording", "Found: " + bait.join(", ") + ".");
  }
  if (rawInput.length > 100) {
    addFinding("low", 5, "Very long link", "Long links can push the real domain out of view.");
  }

  return { findings: findings, score: score, parsed: parsed, unicodeHost: unicodeHost, registered: unicodeRegistered };
}

// Writes the verdict, findings and link breakdown to the page.
function showUrlReport(report) {
  const LEVELS = {
    high: { text: "HIGH", className: "badge-danger" },
    medium: { text: "MEDIUM", className: "badge-warn" },
    low: { text: "LOW", className: "badge-info" }
  };
  let verdict = { text: "LOW RISK", className: "badge-safe", note: "No common warning signs found. This does not prove the link is safe." };
  if (report.score >= 50) {
    verdict = { text: "HIGH RISK", className: "badge-danger", note: "Do not open this link or enter any details." };
  } else if (report.score >= 20) {
    verdict = { text: "SUSPICIOUS", className: "badge-warn", note: "Check with the sender through another channel first." };
  }

  urlOutput.textContent = "";

  const summary = createEl("p", "tool-summary");
  summary.appendChild(createEl("span", "badge " + verdict.className, verdict.text));
  summary.appendChild(createEl("span", "", verdict.note));
  urlOutput.appendChild(summary);

  if (report.findings.length > 0) {
    const list = createEl("ul", "finding-list");
    report.findings.forEach(function (finding) {
      const item = createEl("li");
      const body = createEl("div");
      item.appendChild(createEl("span", "badge " + LEVELS[finding.level].className, LEVELS[finding.level].text));
      body.appendChild(createEl("strong", "", finding.title));
      body.appendChild(createEl("span", "", finding.detail));
      item.appendChild(body);
      list.appendChild(item);
    });
    urlOutput.appendChild(list);
  }

  const table = createResultTable("Link breakdown", ["Part", "Value"]);
  addTableRow(table.tbody, ["Protocol", report.parsed.protocol.replace(":", "")]);
  addTableRow(table.tbody, ["Host", report.parsed.hostname || "None"]);
  addTableRow(table.tbody, ["Displayed As", report.unicodeHost || "None"]);
  addTableRow(table.tbody, ["Registered Domain", report.registered || "None"]);
  addTableRow(table.tbody, ["Path", report.parsed.pathname || "/"]);
  addTableRow(table.tbody, ["Query", report.parsed.search || "None"]);
  urlOutput.appendChild(table.wrap);
}

function runUrlAnalysis() {
  const value = urlInput.value.trim();
  urlOutput.textContent = "";
  urlError.textContent = "";

  if (value === "") {
    urlError.textContent = "Paste a link to analyze.";
    return;
  }

  try {
    showUrlReport(analyzeUrl(value));
  } catch (error) {
    urlError.textContent = "That does not look like a valid web address. Try a link such as https://example.com.";
  }
}

urlForm.addEventListener("submit", function (event) {
  event.preventDefault();
  runUrlAnalysis();
});

document.querySelectorAll("[data-url]").forEach(function (button) {
  button.addEventListener("click", function () {
    urlInput.value = button.dataset.url;
    runUrlAnalysis();
  });
});


/* ==========================================================================
   TOOL 3: LOCAL EXIF METADATA INSPECTOR
   FileReader loads the photo into memory. The bytes are then read by hand
   following the EXIF layout: JPEG segment > TIFF header > tag directories.
   ========================================================================== */

const exifInput = document.getElementById("exifInput");
const exifError = document.getElementById("exifError");
const exifOutput = document.getElementById("exifOutput");

const MAX_IMAGE_BYTES = 25 * 1024 * 1024;

// Size in bytes of each EXIF data type (index = type number).
const EXIF_TYPE_SIZES = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8];

// Reads text from the file, stopping at the first empty byte.
function readAscii(view, start, length) {
  let text = "";
  const limit = Math.min(length, 256);
  for (let i = 0; i < limit; i += 1) {
    const code = view.getUint8(start + i);
    if (code === 0) {
      break;
    }
    text += String.fromCharCode(code);
  }
  return text.trim();
}

// Reads the value of one EXIF tag according to its data type.
function readTagValue(view, tiffStart, entry, little) {
  const type = view.getUint16(entry + 2, little);
  const count = view.getUint32(entry + 4, little);
  const size = EXIF_TYPE_SIZES[type];
  if (!size) {
    return null;
  }

  // Values of 4 bytes or fewer are stored directly inside the entry.
  const start = count * size <= 4 ? entry + 8 : tiffStart + view.getUint32(entry + 8, little);

  if (type === 2) {
    return readAscii(view, start, count);
  }

  const values = [];
  for (let i = 0; i < Math.min(count, 16); i += 1) {
    const at = start + i * size;
    if (type === 3) {
      values.push(view.getUint16(at, little));
    } else if (type === 4) {
      values.push(view.getUint32(at, little));
    } else if (type === 5 || type === 10) {
      const top = type === 5 ? view.getUint32(at, little) : view.getInt32(at, little);
      const bottom = type === 5 ? view.getUint32(at + 4, little) : view.getInt32(at + 4, little);
      values.push(bottom === 0 ? 0 : top / bottom);
    } else {
      values.push(view.getUint8(at));
    }
  }
  return values.length === 1 ? values[0] : values;
}

// Reads a whole tag directory into an object such as { 271: "Apple" }.
function readDirectory(view, tiffStart, offset, little) {
  const tags = {};
  const directory = tiffStart + offset;
  const count = Math.min(view.getUint16(directory, little), 512);

  for (let i = 0; i < count; i += 1) {
    const entry = directory + 2 + i * 12;
    try {
      tags[view.getUint16(entry, little)] = readTagValue(view, tiffStart, entry, little);
    } catch (error) {
      // A damaged tag is skipped so the remaining tags can still be read.
    }
  }
  return tags;
}

// Every JPEG file starts with the two bytes FF D8.
function isJpeg(buffer) {
  return buffer.byteLength >= 4 && new DataView(buffer).getUint16(0) === 0xFFD8;
}

// Finds the EXIF block in a JPEG. Returns null when there is none.
function parseExif(buffer) {
  const view = new DataView(buffer);
  if (!isJpeg(buffer)) {
    return null;
  }

  let offset = 2;
  while (offset + 4 <= view.byteLength) {
    const marker = view.getUint16(offset);
    if ((marker & 0xFF00) !== 0xFF00 || marker === 0xFFDA) {
      return null;
    }
    if (marker === 0xFFE1 && readAscii(view, offset + 4, 4) === "Exif") {
      const tiffStart = offset + 10;
      const little = view.getUint16(tiffStart) === 0x4949;
      const main = readDirectory(view, tiffStart, view.getUint32(tiffStart + 4, little), little);
      const exif = main[0x8769] ? readDirectory(view, tiffStart, main[0x8769], little) : {};
      const gps = main[0x8825] ? readDirectory(view, tiffStart, main[0x8825], little) : {};
      return { main: main, exif: exif, gps: gps };
    }
    offset += 2 + view.getUint16(offset + 2);
  }
  return null;
}

// Converts degrees, minutes and seconds to a single decimal number.
function gpsToDecimal(parts, reference) {
  if (!Array.isArray(parts) || parts.length < 3) {
    return null;
  }
  const decimal = parts[0] + parts[1] / 60 + parts[2] / 3600;
  return reference === "S" || reference === "W" ? -decimal : decimal;
}

// Converts the raw tags into labelled rows for the results table.
function buildExifRows(data) {
  const rows = [];

  function addRow(label, value, suffix) {
    if (value !== undefined && value !== null && value !== "") {
      rows.push([label, String(value) + (suffix || "")]);
    }
  }

  addRow("Camera Make", data.main[0x010F]);
  addRow("Camera Model", data.main[0x0110]);
  addRow("Lens", data.exif[0xA434]);
  addRow("Device Serial", data.exif[0xA431]);
  addRow("Software", data.main[0x0131]);
  addRow("Artist", data.main[0x013B]);
  addRow("Date Taken", data.exif[0x9003] || data.main[0x0132]);
  addRow("ISO", data.exif[0x8827]);
  addRow("Aperture", typeof data.exif[0x829D] === "number" ? "f/" + data.exif[0x829D].toFixed(1) : undefined);
  addRow("Focal Length", typeof data.exif[0x920A] === "number" ? data.exif[0x920A].toFixed(1) : undefined, " mm");

  const latitude = gpsToDecimal(data.gps[2], data.gps[1]);
  const longitude = gpsToDecimal(data.gps[4], data.gps[3]);
  const hasGps = latitude !== null && longitude !== null && Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180;
  if (hasGps) {
    addRow("GPS Latitude", latitude.toFixed(6));
    addRow("GPS Longitude", longitude.toFixed(6));
    addRow("GPS Altitude", typeof data.gps[6] === "number" ? data.gps[6].toFixed(1) : undefined, " m");
  }
  return { rows: rows, hasGps: hasGps };
}

// Writes the results for one image to the page.
function showExifReport(file, dimensions, data, status) {
  const report = data ? buildExifRows(data) : { rows: [], hasGps: false };
  let badge = { text: "CLEAN", className: "badge-safe", note: "No EXIF metadata was found in this file." };

  // Never call a file clean when its metadata could not be fully checked.
  if (status === "damaged") {
    badge = { text: "NOT CHECKED", className: "badge-warn", note: "The metadata in this file is damaged, so it could not be read." };
  } else if (status === "not-jpeg") {
    badge = { text: "NOT CHECKED", className: "badge-warn", note: "EXIF is only read from JPEG photos, so this file may still contain metadata." };
  } else if (report.hasGps) {
    badge = { text: "HIGH RISK", className: "badge-danger", note: "This photo reveals where it was taken. Remove location data before sharing." };
  } else if (report.rows.length > 0) {
    badge = { text: "METADATA FOUND", className: "badge-warn", note: "This photo reveals details about the device or the time it was taken." };
  }

  exifOutput.textContent = "";

  const summary = createEl("p", "tool-summary");
  summary.appendChild(createEl("span", "badge " + badge.className, badge.text));
  summary.appendChild(createEl("span", "", badge.note));
  exifOutput.appendChild(summary);

  const table = createResultTable("Image details", ["Property", "Value"]);
  addTableRow(table.tbody, ["File Name", file.name]);
  addTableRow(table.tbody, ["File Type", file.type || "Unknown"]);
  addTableRow(table.tbody, ["File Size", (file.size / 1024).toFixed(1) + " KB"]);
  addTableRow(table.tbody, ["Dimensions", dimensions]);
  addTableRow(table.tbody, ["Last Modified", new Date(file.lastModified).toLocaleString()]);
  report.rows.forEach(function (row) {
    addTableRow(table.tbody, row);
  });
  exifOutput.appendChild(table.wrap);
}

// Loads the image in memory just to measure its width and height.
function measureImage(file, callback) {
  const address = URL.createObjectURL(file);
  const image = new Image();
  image.onload = function () {
    URL.revokeObjectURL(address);
    callback(image.naturalWidth + " x " + image.naturalHeight + " px");
  };
  image.onerror = function () {
    URL.revokeObjectURL(address);
    callback(null);
  };
  image.src = address;
}

exifInput.addEventListener("change", function () {
  const file = exifInput.files[0];
  exifError.textContent = "";
  exifOutput.textContent = "";

  if (!file) {
    return;
  }
  if (file.type.indexOf("image/") !== 0) {
    exifError.textContent = "Please choose an image file, such as a JPEG photo.";
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    exifError.textContent = "This image is larger than 25 MB. Please choose a smaller file.";
    return;
  }

  const reader = new FileReader();
  reader.onerror = function () {
    exifError.textContent = "This file could not be read. Please try another image.";
  };
  reader.onload = function () {
    let data = null;
    let status = isJpeg(reader.result) ? "ok" : "not-jpeg";
    try {
      data = parseExif(reader.result);
    } catch (error) {
      status = "damaged";
    }
    measureImage(file, function (dimensions) {
      if (dimensions === null) {
        exifError.textContent = "This file is damaged or is not a supported image format.";
        return;
      }
      showExifReport(file, dimensions, data, status);
    });
  };
  reader.readAsArrayBuffer(file);
});


/* ==========================================================================
   TOOL 4: PASSWORD STRENGTH AND BREACH-PATTERN CHECKER
   Entropy = length x log2(size of the character set). Predictable patterns
   then reduce that score, because attackers try those patterns first.
   ========================================================================== */

const pwInput = document.getElementById("pwInput");
const pwToggle = document.getElementById("pwToggle");
const pwMeter = document.getElementById("pwMeter");
const pwLabel = document.getElementById("pwLabel");
const pwBits = document.getElementById("pwBits");
const pwTime = document.getElementById("pwTime");
const pwTips = document.getElementById("pwTips");

// Passwords that attackers try first, including common local choices.
const COMMON_PASSWORDS = new Set([
  "123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234", "111111", "000000",
  "123123", "654321", "666666", "121212", "112233", "555555", "888888", "987654321", "786786",
  "password", "passcode", "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm", "qazwsx",
  "abc123", "iloveyou", "admin", "administrator", "welcome", "monkey", "dragon", "letmein", "login",
  "princess", "sunshine", "master", "football", "baseball", "cricket", "shadow", "superman", "batman",
  "trustno", "hello", "freedom", "whatever", "michael", "jordan", "charlie", "secret", "starwars",
  "pakistan", "islamabad", "karachi", "lahore", "rawalpindi", "peshawar", "bismillah", "allah", "muhammad",
  "ali786", "khan", "bahria", "student", "google", "facebook", "instagram"
]);

const PATTERN_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz", "01234567890"];

// Undoes common swaps, so "p@ssw0rd" is recognised as "password".
function removeLeetSpeak(text) {
  const swaps = { "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t" };
  return text.replace(/[@431!0$57]/g, function (ch) {
    return swaps[ch];
  });
}

// Finds a run of 4 or more neighbouring keys or letters, in either direction.
function findKeyboardRun(lowerText) {
  const reversed = PATTERN_ROWS.map(function (row) {
    return row.split("").reverse().join("");
  });
  const rows = PATTERN_ROWS.concat(reversed);

  for (let i = 0; i + 4 <= lowerText.length; i += 1) {
    const piece = lowerText.slice(i, i + 4);
    const found = rows.some(function (row) {
      return row.indexOf(piece) !== -1;
    });
    if (found) {
      return true;
    }
  }
  return false;
}

// Scores a password and returns the numbers and advice to display.
function analyzePassword(password) {
  const lower = password.toLowerCase();
  const tips = [];

  // Step 1: work out how many different characters could have been used.
  let pool = 0;
  if (/[a-z]/.test(password)) { pool += 26; }
  if (/[A-Z]/.test(password)) { pool += 26; }
  if (/[0-9]/.test(password)) { pool += 10; }
  if (/[^a-zA-Z0-9]/.test(password)) { pool += 33; }

  const length = Array.from(password).length;
  let bits = length * Math.log2(pool);

  // Step 2: lower the score for predictable patterns.
  const baseWord = removeLeetSpeak(lower.replace(/[\d!@#$%^&*._-]+$/, "").replace(/^\d+/, ""));

  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(removeLeetSpeak(lower))) {
    bits = Math.min(bits, 8);
    tips.push("This password appears on common breach lists. Never use it.");
  } else if (COMMON_PASSWORDS.has(baseWord)) {
    bits = Math.min(bits, 20);
    tips.push("This is a common word with small changes. Attackers try these variations first.");
  }
  if (findKeyboardRun(lower)) {
    bits -= 12;
    tips.push("Avoid keyboard runs and sequences such as qwerty, abcd or 1234.");
  }
  if (new Set(password).size <= 2) {
    bits = Math.min(bits, 6);
    tips.push("This password uses only one or two different characters.");
  } else if (/(.)\1{2,}/.test(password)) {
    bits -= 8;
    tips.push("Avoid repeating the same character.");
  }
  if (/(19|20)\d{2}/.test(password)) {
    bits -= 6;
    tips.push("Avoid years and dates, which are easy to guess.");
  }
  if (/^\d+$/.test(password)) {
    tips.push("Numbers alone are quick to crack. Add words or symbols.");
  }
  if (length < 12) {
    tips.push("Use at least 12 characters. Length adds the most strength.");
  }
  if (tips.length === 0) {
    tips.push("Good work. Keep this password unique to one account and store it in a password manager.");
  }

  return { bits: Math.max(0, bits), tips: tips };
}

// Turns a number of seconds into words that are easy to read.
function formatDuration(seconds) {
  const units = [
    ["century", 3153600000], ["year", 31536000], ["day", 86400],
    ["hour", 3600], ["minute", 60], ["second", 1]
  ];
  if (seconds < 1) {
    return "Instantly";
  }
  if (seconds >= 3153600000 * 1000) {
    return "Over 1,000 centuries";
  }
  for (let i = 0; i < units.length; i += 1) {
    if (seconds >= units[i][1]) {
      const amount = Math.floor(seconds / units[i][1]);
      const name = units[i][0] === "century" && amount !== 1 ? "centuries" : units[i][0] + (amount === 1 ? "" : "s");
      return amount + " " + name;
    }
  }
  return "Instantly";
}

// Updates the meter, score and tips after every key press.
function updatePasswordReport() {
  const password = pwInput.value;
  pwTips.textContent = "";

  if (password === "") {
    pwMeter.style.width = "0";
    pwMeter.className = "meter-fill";
    pwLabel.textContent = "NO INPUT";
    pwLabel.className = "badge badge-info";
    pwBits.textContent = "0";
    pwTime.textContent = "n/a";
    return;
  }

  const result = analyzePassword(password);
  let level = { text: "VERY WEAK", badge: "badge-danger", meter: "" };
  if (result.bits >= 80) {
    level = { text: "VERY STRONG", badge: "badge-safe", meter: "is-strong" };
  } else if (result.bits >= 60) {
    level = { text: "STRONG", badge: "badge-safe", meter: "is-strong" };
  } else if (result.bits >= 40) {
    level = { text: "FAIR", badge: "badge-warn", meter: "is-fair" };
  } else if (result.bits >= 28) {
    level = { text: "WEAK", badge: "badge-danger", meter: "" };
  }

  // Assumes an offline attacker making 10 billion guesses per second.
  const seconds = Math.pow(2, result.bits - 1) / 1e10;

  pwMeter.style.width = Math.max(4, Math.min(100, result.bits)) + "%";
  pwMeter.className = "meter-fill " + level.meter;
  pwLabel.textContent = level.text;
  pwLabel.className = "badge " + level.badge;
  pwBits.textContent = result.bits.toFixed(1);
  pwTime.textContent = formatDuration(seconds);

  result.tips.forEach(function (tip) {
    pwTips.appendChild(createEl("li", "", tip));
  });
}

pwInput.addEventListener("input", updatePasswordReport);

pwToggle.addEventListener("click", function () {
  const showing = pwInput.type === "text";
  pwInput.type = showing ? "password" : "text";
  pwToggle.textContent = showing ? "Show" : "Hide";
  pwToggle.setAttribute("aria-pressed", String(!showing));
});
