# Security Policy
CVE Policy for NanoMQ Components

We deeply value the contributions of security researchers and are committed to promptly addressing all reported vulnerabilities. However, to maintain the clarity and integrity of our security advisories, we differentiate between Core and Non-Core components in our policy for requesting and issuing CVEs (Common Vulnerabilities and Exposures).Core Components (CVE-Eligible)

We will actively request and coordinate the issuance of CVEs for vulnerabilities found in the following core, production-ready components of NanoMQ:
MQTT Broker Functionality (All trasnport)
Bridging (AWS IoT Core bridge is not include)
Webhook
HTTP RESTful APIs

If a vulnerability is found in a Core Component, we will work with the reporter to ensure a CVE is issued and the advisory is published with all due professional diligence.Non-Core and Community/Experimental Components (Non-CVE-Eligible)

Vulnerabilities reported in components that are considered non-core, are under community/experimental maintenance, or are not intended for production use will be handled as follows:
Vulnerability Fix: All reported bugs, including security-relevant issues like buffer overflows, will be fixed promptly by the maintainers.
Public Advisory: A GitHub Security Advisory (GHSA) will be published to document the issue and the fix.
CVE Status: We will not request a CVE ID for vulnerabilities found in non-core components.

Example: The Rule Engine

**The NanoMQ Rule Engine is a historically community-maintained and non-production-ready module. While we acknowledge and fix security flaws found in the Rule Engine (as demonstrated by GHSA-c5gx-vc37-5h2f), these issues are classified as bugs in an obsoleted module and will not be granted a CVE to avoid sending a false signal to our production users and to keep our CVE record focused on our core offering.**

DDS Proxy and NanoMQ commandline tool shares same policy as Rule Engine Module. But as an Open-Source project, we continously on supporting our free users, still accepting bugs report regarding non-core part, fix & release will be out when time permits.


Best,

Jaylin
