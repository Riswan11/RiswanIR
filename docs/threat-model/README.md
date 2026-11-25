# Threat model

The app assumes a trusted local operator. It binds to IPv4 loopback and accepts only localhost and IPv4 loopback Host headers to reduce DNS rebinding exposure. Local access gives access to the workspace and its SQLite data.

CloudTrail exports are untrusted input. The app limits request size and event count, validates core fields, and only persists selected evidence fields. Evidence hashes identify normalized records. Trust in the source export is a separate concern.

Analyst decisions are advisory records. The app has no AWS credentials and cannot change AWS resources. Use synthetic data for any separately hosted demo.
