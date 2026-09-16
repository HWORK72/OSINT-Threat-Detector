# OSINT Threat Analyzer

[🇷🇺 Читать на русском](README_RU.md)

---

OSINT Threat Analyzer is an asynchronous microservice designed for threat intelligence and exposure reconnaissance across domains, IP addresses, and email addresses.

It automates security investigations. Instead of manual lookups, the system queries multiple threat intelligence platforms concurrently. Currently, the primary threat intelligence feed is powered by AlienVault OTX as an open data source.

The core engine is built on FastAPI, enabling non-blocking asynchronous requests to poll external services simultaneously without bottlenecking the server. Redis caches responses to deliver instant sub-millisecond results for repeated lookups. A tuned connection pool ensures system stability during high traffic surges of thousands of concurrent users. The entire project is isolated with Docker, includes rate limiting for DDoS mitigation, and utilizes Nginx for secure HTTPS/TLS termination. Internal network ports are strictly isolated, ensuring zero direct external access to the database.

With this project, my goal was to demonstrate the architecture of a high-load, resilient, and secure system built on modern industry-standard frameworks.
