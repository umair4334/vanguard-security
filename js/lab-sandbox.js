/* ==========================================================================
   lab-sandbox.js: the two live demos on lab.html
   Part A: a real XSS attack that runs inside an isolated iframe.
   Part B: a small SQL simulator that shows how injection changes a query.
   Nothing here talks to a server. All data stays in this browser tab.
   ========================================================================== */

"use strict";

/* ==========================================================================
   PART A: XSS SANDBOX
   How it stays safe:
   1. The iframe has sandbox="allow-scripts". Scripts may run, but the frame
      is treated as a separate origin, so it cannot read this page or cookies.
   2. The frame's Content-Security-Policy blocks all network requests.
   3. The meta tag in lab.html (frame-src 'none') stops the frame from
      navigating to an outside website.
   ========================================================================== */

const xssForm = document.getElementById("xssForm");
const xssInput = document.getElementById("xssInput");
const xssError = document.getElementById("xssError");
const xssFrame = document.getElementById("xssFrame");
const xssLog = document.getElementById("xssLog");
const xssStatus = document.getElementById("xssStatus");
const safeMode = document.getElementById("safeMode");

// Ready-made attacks used by the "Try a payload" buttons.
const XSS_PAYLOADS = {
  html: '<h2 style="color:#EF4444">This heading was injected</h2>',
  script: "<script>alert('This script really ran')<\/script>",
  image: "<img src=x onerror=\"alert('The onerror handler ran')\">",
  deface: "<script>document.body.innerHTML='<h1>DEFACED</h1><p>An attacker controls this box.</p>';alert('Box content replaced')<\/script>",
  cookie: "<script>try{alert('Cookies: '+document.cookie)}catch(e){alert('Cookie theft blocked: '+e.name)}<\/script>",
  escape: "<script>try{parent.document.body.innerHTML='hacked'}catch(e){alert('Escape blocked by sandbox: '+e.name)}<\/script>"
};

// Converts special HTML characters into harmless text versions.
// This one function is the whole fix for this XSS bug.
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Builds the complete mini web page that is loaded into the iframe.
function buildFrameDocument(commentHtml) {
  const policy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:";

  // Replaces alert() so a running script is reported to the execution log.
  const reporter = "window.alert=function(m){" +
    "var p=document.createElement('p');p.className='popup';p.textContent='ALERT: '+m;" +
    "document.body.appendChild(p);" +
    "parent.postMessage({vanguardXss:String(m)},'*');};";

  const styles = "body{margin:12px;font-family:Arial,sans-serif;color:#0B192C;background:#FFFDF8;overflow-wrap:anywhere}" +
    ".who{margin:0 0 6px;font:700 13px Consolas,monospace;color:#1E3E62}" +
    ".popup{padding:8px;background:#F59E0B;border:2px solid #0B192C;font-weight:700}";

  return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>" +
    "<meta http-equiv='Content-Security-Policy' content=\"" + policy + "\">" +
    "<title>Comment preview</title><style>" + styles + "</style>" +
    "<script>" + reporter + "<\/script></head><body>" +
    "<p class='who'>guest wrote:</p><div>" + commentHtml + "</div></body></html>";
}

// Adds one line to the execution log. textContent keeps the log itself safe.
function addLogLine(text, className) {
  const line = document.createElement("li");
  line.textContent = text;
  if (className) {
    line.className = className;
  }
  xssLog.appendChild(line);

  // Keep the log short even if a payload sends many messages.
  while (xssLog.children.length > 8) {
    xssLog.removeChild(xssLog.firstChild);
  }
}

// Shows the current comment in the iframe, using the selected mode.
function renderComment() {
  const comment = xssInput.value;
  xssLog.textContent = "";

  if (safeMode.checked) {
    xssFrame.srcdoc = buildFrameDocument(escapeHtml(comment));
    addLogLine("Input escaped. Displayed as plain text, so no code ran.", "log-safe");
  } else {
    xssFrame.srcdoc = buildFrameDocument(comment);
    addLogLine("Input inserted as raw HTML.");
  }
}

// Updates the VULNERABLE / SAFE badge at the top of the demo.
function updateXssStatus() {
  if (safeMode.checked) {
    xssStatus.textContent = "SAFE / ESCAPED";
    xssStatus.className = "badge badge-safe";
  } else {
    xssStatus.textContent = "VULNERABLE";
    xssStatus.className = "badge badge-danger";
  }
}

xssForm.addEventListener("submit", function (event) {
  event.preventDefault();

  if (xssInput.value.trim() === "") {
    xssError.textContent = "Type a comment or choose a payload first.";
    return;
  }
  xssError.textContent = "";
  renderComment();
});

// Each payload button fills the box and posts the comment straight away.
document.querySelectorAll("[data-payload]").forEach(function (button) {
  button.addEventListener("click", function () {
    xssInput.value = XSS_PAYLOADS[button.dataset.payload];
    xssError.textContent = "";
    renderComment();
  });
});

// Switching modes shows the same comment again in the new mode.
safeMode.addEventListener("change", function () {
  updateXssStatus();
  if (xssInput.value.trim() !== "") {
    renderComment();
  }
});

// Receives "a script ran" messages, but only from our own iframe.
window.addEventListener("message", function (event) {
  if (event.source !== xssFrame.contentWindow || !event.data || typeof event.data.vanguardXss !== "string") {
    return;
  }
  addLogLine("SCRIPT EXECUTED: " + event.data.vanguardXss.slice(0, 160), "log-hit");
});

xssFrame.srcdoc = buildFrameDocument("<em>No comments yet.</em>");


/* ==========================================================================
   PART B: SQL INJECTION SIMULATOR
   There is no real database. This code reads the WHERE part of the query,
   the same way a database would, and checks it against the FAKE_USERS array.
   ========================================================================== */

const sqliForm = document.getElementById("sqliForm");
const sqlUser = document.getElementById("sqlUser");
const sqlPass = document.getElementById("sqlPass");
const sqlQuery = document.getElementById("sqlQuery");
const sqlUsers = document.getElementById("sqlUsers");
const concatResult = document.getElementById("concatResult");
const paramResult = document.getElementById("paramResult");

// Fictional accounts used only for this demo.
const FAKE_USERS = [
  { id: 1, username: "admin", password: "T0p-S3cret!", role: "administrator" },
  { id: 2, username: "alice", password: "sunset42", role: "student" },
  { id: 3, username: "bilal", password: "cricket99", role: "student" }
];

// Ready-made inputs used by the "Try an input" buttons.
const SQL_PRESETS = {
  normal: { user: "alice", pass: "sunset42" },
  wrong: { user: "alice", pass: "not-the-password" },
  orTrue: { user: "admin' OR '1'='1", pass: "anything" },
  comment: { user: "admin' -- ", pass: "anything" },
  passField: { user: "anyone", pass: "' OR '1'='1" },
  drop: { user: "'; DROP TABLE users; -- ", pass: "anything" }
};

const QUERY_START = "SELECT * FROM users WHERE ";

// Step 1: split the WHERE text into small pieces called tokens.
// Example: username = 'admin' becomes [word, operator, string].
function tokenize(sql) {
  const tokens = [];
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];

    if (/\s/.test(ch)) {
      i += 1;
    } else if (sql.startsWith("--", i) || ch === "#") {
      // A comment hides everything after it. Attackers use this trick.
      break;
    } else if (ch === ";") {
      throw new Error("STACKED");
    } else if (ch === "'") {
      // Read a quoted string. Two quotes in a row mean one literal quote.
      let text = "";
      let closed = false;
      i += 1;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") {
          text += "'";
          i += 2;
        } else if (sql[i] === "'") {
          closed = true;
          i += 1;
          break;
        } else {
          text += sql[i];
          i += 1;
        }
      }
      if (!closed) {
        throw new Error("Syntax error: a quotation mark was never closed.");
      }
      tokens.push({ type: "value", value: text });
    } else if (/[0-9]/.test(ch)) {
      const number = sql.slice(i).match(/^[0-9]+/)[0];
      tokens.push({ type: "value", value: number });
      i += number.length;
    } else if (/[a-zA-Z_]/.test(ch)) {
      const word = sql.slice(i).match(/^[a-zA-Z_0-9]+/)[0];
      const upper = word.toUpperCase();
      if (upper === "AND" || upper === "OR") {
        tokens.push({ type: "logic", value: upper });
      } else {
        tokens.push({ type: "column", value: word.toLowerCase() });
      }
      i += word.length;
    } else if (sql.startsWith("!=", i) || sql.startsWith("<>", i)) {
      tokens.push({ type: "operator", value: "!=" });
      i += 2;
    } else if (ch === "=") {
      tokens.push({ type: "operator", value: "=" });
      i += 1;
    } else {
      throw new Error("Syntax error near: " + sql.slice(i, i + 12));
    }
  }
  return tokens;
}

// Step 2: group the tokens. AND is stronger than OR, so the result is a list
// of OR groups, and each group holds conditions joined by AND.
function parseConditions(tokens) {
  const orGroups = [[]];
  let i = 0;

  while (i < tokens.length) {
    const left = tokens[i];
    if (left.type !== "value" && left.type !== "column") {
      throw new Error("Syntax error: expected a value before " + left.value + ".");
    }

    const condition = { left: left, operator: null, right: null };
    i += 1;

    if (tokens[i] && tokens[i].type === "operator") {
      condition.operator = tokens[i].value;
      condition.right = tokens[i + 1];
      if (!condition.right || (condition.right.type !== "value" && condition.right.type !== "column")) {
        throw new Error("Syntax error: expected a value after " + condition.operator + ".");
      }
      i += 2;
    }
    orGroups[orGroups.length - 1].push(condition);

    if (i < tokens.length) {
      if (tokens[i].type !== "logic") {
        throw new Error("Syntax error near: " + tokens[i].value);
      }
      if (tokens[i].value === "OR") {
        orGroups.push([]);
      }
      i += 1;
      if (i === tokens.length) {
        throw new Error("Syntax error: the query ends unexpectedly.");
      }
    }
  }
  return orGroups;
}

// Gets the real value of a token for one row of the table.
function tokenValue(token, row) {
  if (token.type === "value") {
    return token.value;
  }
  if (!(token.value in row)) {
    throw new Error("Unknown column: " + token.value);
  }
  return String(row[token.value]);
}

// Checks whether one condition is true for one row.
function conditionIsTrue(condition, row) {
  const left = tokenValue(condition.left, row);
  if (condition.operator === null) {
    return left !== "" && left !== "0";
  }
  const right = tokenValue(condition.right, row);
  return condition.operator === "=" ? left === right : left !== right;
}

// Step 3: return every row where at least one OR group is fully true.
function runWhereClause(whereText) {
  const orGroups = parseConditions(tokenize(whereText));
  return FAKE_USERS.filter(function (row) {
    return orGroups.some(function (group) {
      return group.every(function (condition) {
        return conditionIsTrue(condition, row);
      });
    });
  });
}

// The vulnerable way: input is glued directly into the query text.
function buildWhereClause(user, pass) {
  return "username = '" + user + "' AND password = '" + pass + "'";
}

// The safe way: input is only ever compared as plain data.
function runParameterized(user, pass) {
  return FAKE_USERS.filter(function (row) {
    return row.username === user && row.password === pass;
  });
}

// Shows the query with the visitor's input highlighted in amber.
function showLiveQuery() {
  const parts = [
    { text: QUERY_START + "username = '" },
    { text: sqlUser.value, input: true },
    { text: "' AND password = '" },
    { text: sqlPass.value, input: true },
    { text: "'" }
  ];

  sqlQuery.textContent = "";
  parts.forEach(function (part) {
    const span = document.createElement("span");
    span.textContent = part.text;
    if (part.input) {
      span.className = "sql-input";
    }
    sqlQuery.appendChild(span);
  });
}

// Writes a badge and an explanation into a result box.
function showResult(box, badgeText, badgeClass, message) {
  const badge = document.createElement("span");
  const paragraph = document.createElement("p");
  badge.textContent = badgeText;
  badge.className = "badge " + badgeClass;
  paragraph.textContent = message;
  box.textContent = "";
  box.appendChild(badge);
  box.appendChild(paragraph);
}

// Draws the fake users table and highlights any rows the attack returned.
function drawUsersTable(hitIds) {
  sqlUsers.textContent = "";
  FAKE_USERS.forEach(function (user) {
    const row = sqlUsers.insertRow();
    if (hitIds.indexOf(user.id) !== -1) {
      row.className = "row-hit";
    }
    [user.id, user.username, user.password, user.role].forEach(function (value) {
      row.insertCell().textContent = value;
    });
  });
}

// Runs both versions of the login and compares the outcomes.
function testLogin() {
  const user = sqlUser.value;
  const pass = sqlPass.value;
  const safeRows = runParameterized(user, pass);
  let hitIds = [];

  try {
    const rows = runWhereClause(buildWhereClause(user, pass));
    hitIds = rows.map(function (row) {
      return row.id;
    });

    if (rows.length === 0) {
      showResult(concatResult, "ACCESS DENIED", "badge-safe", "The query returned no rows.");
    } else if (safeRows.length === 1) {
      showResult(concatResult, "ACCESS GRANTED", "badge-safe", "Correct details. Logged in as " + rows[0].username + ".");
    } else {
      showResult(concatResult, "LOGIN BYPASSED", "badge-danger",
        "The injected input changed the query. Logged in as " + rows[0].username + " (" + rows[0].role + ") without the password.");
    }
  } catch (error) {
    if (error.message === "STACKED") {
      showResult(concatResult, "DESTRUCTIVE QUERY", "badge-danger",
        "The semicolon starts a second command. On a real database that allows this, the users table could be deleted. The simulator stops here.");
    } else {
      showResult(concatResult, "SQL ERROR", "badge-warn",
        error.message + " Error messages like this tell attackers that input reaches the query.");
    }
  }

  if (safeRows.length === 1) {
    showResult(paramResult, "ACCESS GRANTED", "badge-safe", "Correct details. Logged in as " + safeRows[0].username + ".");
  } else {
    showResult(paramResult, "ACCESS DENIED", "badge-safe", "The input was treated as plain data, so it could not change the query.");
  }

  drawUsersTable(hitIds);
}

sqliForm.addEventListener("submit", function (event) {
  event.preventDefault();
  testLogin();
});

// The query preview updates on every key press.
sqlUser.addEventListener("input", showLiveQuery);
sqlPass.addEventListener("input", showLiveQuery);

// Each preset button fills both fields and runs the login.
document.querySelectorAll("[data-sql]").forEach(function (button) {
  button.addEventListener("click", function () {
    const preset = SQL_PRESETS[button.dataset.sql];
    sqlUser.value = preset.user;
    sqlPass.value = preset.pass;
    showLiveQuery();
    testLogin();
  });
});

showLiveQuery();
drawUsersTable([]);
