## Background

In the era of IoT, data is the lifeblood of digital transformation. A high-performance messaging bus is essential for data convergence, bridging, and re-distribution on the edge. However, it is difficult to implement such a messaging bus for edge computing due to the fragmented ecosystem and highly constrained resources of embedded hardware.

To tackle such problems,  we present NanoMQ as a lightweight edge messaging bus, which unifies data in motion and data at rest. With its elegant and powerful design, users could achieve a high level of time and space efficiency while enjoying portability and scalability when accessing the data on edge.

### Some quotes from NNG's maintainer --- Garrett:
I’m very excited about the synergy between the NanoMQ and NNG projects, and grateful for sponsorship that NNG has received from the NanoMQ team. The NanoMQ team has been able to push NNG's envelope, and the collaboration has already yielded substantial improvements for both projects. Further, the cooperation between these two project will make MQTT and SP (nanomsg) protocols easy to use within a single project as well as other capabilities (such as websockets, HTTPS clients and servers), greatly expanding the toolset within easy reach of the IoT developer. Further this comes without the usual licensing or portability/embeddability challenges that face other projects. Additional planned collaborative work will further expand on these capabilities to the benefit of our shared communities.

## NanoMQ's design principles:

Rely on Kernel, not on Human/User. We are at OS kernel’s mercy.

What you saw is what you do. Never take the overwhelming burden that overpowers NanoMQ.

Adaptive to wherever we inhabited.

Do not let it fail! Don’t accomplish everything at once!

Interoperability is the core value and common ground.

Everything is message and event

Avoid write/read IO amplify