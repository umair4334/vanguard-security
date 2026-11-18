# Vanguard Security

Vanguard is a six-page static website for a cybersecurity training and consulting service, built for the CSC-114 Introduction to ICT project at Bahria University, Islamabad (Fall 2026). It combines a live web vulnerability lab with private OSINT self-audit tools that run entirely in the visitor's browser.

**Live site:** https://umair4334.github.io/vanguard-security/

## Team

| Member | Role | Responsibilities |
| --- | --- | --- |
| Umair Ahmad | Lead Architect and Security Lab Developer | `index.html`, `lab.html`, `style.css`, `js/lab-sandbox.js` |
| Ammar Yasir | OSINT Toolkit and UI Developer | `tools.html`, `services.html`, `js/osint-tools.js` |
| Faizan Ali | Core Pages, Form Validation and QA Lead | `about.html`, `contact.html`, `js/form-check.js` |

## How to run

1. Download or clone this repository.
2. Open `index.html` in a modern browser such as Chrome, Firefox, Edge or Brave.

No installation, build step or server is required.

## Pages

| Page | File | Purpose |
| --- | --- | --- |
| Home | `index.html` | Introduction, teaser cards and why Vanguard |
| About | `about.html` | Mission, team and breach pattern table |
| Services | `services.html` | Service list, cards and tier table |
| Security Lab | `lab.html` | Live XSS sandbox and simulated SQL injection |
| Tools | `tools.html` | Four client-side OSINT and OPSEC tools |
| Contact | `contact.html` | Consultation form with JavaScript validation |

## Features

- **XSS sandbox:** runs real payloads inside an isolated iframe, with a switch to safe escaped output.
- **SQL injection visualizer:** shows the live query and compares concatenation with parameterized queries.
- **Browser fingerprint viewer:** lists what any website can learn about a visitor's device.
- **Phishing URL analyzer:** flags punycode, homographs, lookalike brands and other warning signs.
- **EXIF inspector:** reads GPS, device and date metadata from JPEG photos on the visitor's device.
- **Password checker:** estimates entropy and detects common breach patterns.
- **Form validation:** checks every field and shows clear inline messages.

## Privacy and safety

- The site has no backend, database, cookies, analytics or third-party scripts.
- Tool input stays in the browser and is never uploaded.
- The XSS sandbox blocks access to the main page, cookies and the network.
- The lab is for education only. Test only systems you own or have written permission to test.

## Folder structure

```text
vanguard-security/
|-- index.html
|-- about.html
|-- services.html
|-- lab.html
|-- tools.html
|-- contact.html
|-- style.css
|-- README.md
|-- js/
|   |-- lab-sandbox.js
|   |-- osint-tools.js
|   `-- form-check.js
|-- images/
|   |-- vanguard-logo.png
|   `-- team-banner.jpg
`-- wireframes/
    |-- deliverable1-wireframes.pdf
    |-- sitemap.png
    `-- wireframe-*.png
```

## Technologies

HTML5, CSS3 (Flexbox, Grid and media queries), vanilla JavaScript, Git, GitHub and GitHub Pages.

## AI assistance

Code in this repository was drafted with AI assistance from Claude (Anthropic). Under the CSC-114 project policy, AI-assisted code must be understood, adapted and cited in the project report.

## Disclaimer

Vanguard is a concept company created for university coursework. The service tiers and contact details are illustrative.
