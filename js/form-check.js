/* ==========================================================================
   form-check.js: validates the consultation form on contact.html
   Rules:
     Name     required, 2 to 60 characters, letters and name punctuation only
     Email    required, must look like name@domain.com
     Service  one option must be selected
     Message  required, 20 to 500 characters
   GitHub Pages has no server, so valid data is never stored or sent.
   ========================================================================== */

"use strict";

const consultForm = document.getElementById("consultForm");
const formMessage = document.getElementById("formMessage");
const msgCounter = document.getElementById("msgCounter");

const MESSAGE_MIN = 20;
const MESSAGE_MAX = 500;

// Each function returns an error message, or "" when the value is valid.
const validators = {
  name: function (value) {
    const name = value.trim();
    if (name === "") {
      return "Please enter your full name.";
    }
    if (name.length < 2) {
      return "Your name must be at least 2 characters long.";
    }
    if (name.length > 60) {
      return "Your name must be 60 characters or fewer.";
    }
    // \p{L} means a letter from any language.
    if (!/^[\p{L}\s.'-]+$/u.test(name)) {
      return "Your name can only contain letters, spaces, dots, hyphens and apostrophes.";
    }
    return "";
  },

  email: function (value) {
    const email = value.trim();
    if (email === "") {
      return "Please enter your email address.";
    }
    if (email.length > 254) {
      return "Your email address must be 254 characters or fewer.";
    }
    // Pattern: some text, then @, then a domain, a dot and an ending.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return "Please enter a valid email address, such as name@example.com.";
    }
    return "";
  },

  service: function (value) {
    return value === "" ? "Please select the service you are interested in." : "";
  },

  msg: function (value) {
    const length = value.trim().length;
    if (length === 0) {
      return "Please tell us what you need.";
    }
    if (length < MESSAGE_MIN) {
      return "Your message needs " + (MESSAGE_MIN - length) + " more character(s). The minimum is " + MESSAGE_MIN + ".";
    }
    if (length > MESSAGE_MAX) {
      return "Your message is " + (length - MESSAGE_MAX) + " character(s) too long. The maximum is " + MESSAGE_MAX + ".";
    }
    return "";
  }
};

// Checks one field, then shows or clears its error message.
function validateField(fieldId) {
  const field = document.getElementById(fieldId);
  const errorBox = document.getElementById(fieldId + "Error");
  const error = validators[fieldId](field.value);

  errorBox.textContent = error;
  if (error) {
    field.setAttribute("aria-invalid", "true");
  } else {
    field.removeAttribute("aria-invalid");
  }
  return error === "";
}

// Updates the "0 / 500" counter under the message box.
function updateCounter() {
  const length = document.getElementById("msg").value.trim().length;
  msgCounter.textContent = length + " / " + MESSAGE_MAX;
  msgCounter.classList.toggle("counter-over", length > MESSAGE_MAX);
}

// Shows the summary box at the bottom of the form.
function showFormMessage(text, type) {
  formMessage.textContent = text;
  formMessage.className = "form-message form-message-" + type;
}

Object.keys(validators).forEach(function (fieldId) {
  const field = document.getElementById(fieldId);

  // Check a field when the visitor leaves it.
  field.addEventListener("blur", function () {
    validateField(fieldId);
  });

  // Once a field shows an error, clear it as soon as the value is fixed.
  field.addEventListener("input", function () {
    if (field.getAttribute("aria-invalid") === "true") {
      validateField(fieldId);
    }
    formMessage.textContent = "";
    formMessage.className = "form-message";
  });
});

document.getElementById("msg").addEventListener("input", updateCounter);

consultForm.addEventListener("submit", function (event) {
  // Stop the browser from reloading the page.
  event.preventDefault();

  const fieldIds = Object.keys(validators);
  const invalidIds = fieldIds.filter(function (fieldId) {
    return !validateField(fieldId);
  });

  if (invalidIds.length > 0) {
    const noun = invalidIds.length === 1 ? "field needs" : "fields need";
    showFormMessage(invalidIds.length + " " + noun + " attention before this request can be sent.", "error");
    document.getElementById(invalidIds[0]).focus();
    return;
  }

  const firstName = document.getElementById("name").value.trim().split(/\s+/)[0];
  consultForm.reset();
  updateCounter();
  showFormMessage("Thank you, " + firstName + ". Your request passed every check. This demo site has no server, so nothing was sent or stored.", "success");
  formMessage.focus();
});
