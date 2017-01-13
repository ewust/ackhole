ackhole
=======

TCP ACKs where you least expect them.

This simple tool is meant to test what happens when you send weird packets
to servers during otherwise normal conversations. In particular, ackhole
listens on stdin for IPs of servers to connect to (maybe obtained using
zmap, for example), and connects to each one. Meanwhile, ackhole listens
to packets sent/received in order to track the connection parameters of
the connection. After a certain point (e.g. the client has sent some
data), ackhole can then inject packets (ACKs, RSTs, out-of-sequence
packets, etc), and observe what the server does.

This tool is mainly developed to test how servers will respond to TapDance
behavior; incomplete HTTP requests, followed by spurious ACKs, and how
long the server will remain silent before sending responses or tearing
down the connection due to timeout.
