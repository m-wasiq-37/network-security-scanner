# Network Security Scanner & Firewall Visualizer

This project is a Node.js web application that scans a target host for common ports, displays services and status in a table, and lets the user create firewall rules to simulate whether traffic is allowed or denied.

## Features

- Target IP or hostname input
- Scan type selection
- Port range input
- Results table for IP, Port, Service, and Status
- Firewall rule creation with allow or deny actions
- Priority based rule matching
- Traffic flow simulation with visual feedback

## Tech Stack

- Node.js
- Express
- HTML
- CSS
- JavaScript

## How to Run

1. Install dependencies:

```bash
npm install
```

2. Start the server:

```bash
npm start
```

3. Open the app in your browser:

```bash
http://localhost:3000
```

## Notes

- Use this tool only on systems you own or have permission to test.
- The scan engine uses Node.js network sockets for a simple educational scanner.
- The firewall simulator uses rule priority, where the lowest number has the highest priority.

## Suggested Screenshots for Submission

- Main scanner page
- Scan results table after running a test scan
- Firewall rule creation form filled in
- Traffic simulation output showing allow or deny

## Folder Structure

```text
network-security-scanner/
├── package.json
├── server.js
├── README.md
└── public/
    ├── index.html
    ├── styles.css
    └── app.js
```
