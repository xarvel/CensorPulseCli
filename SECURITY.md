# Security policy

The probe server is designed to sit on a public IP and answer unsolicited
traffic. Anything that lets it be used against a third party (reflection or
amplification, proxying, recursive resolution), that crashes it on malformed
input, or that leaks a client's data is a security bug.

**Report privately** to the maintainer listed on the GitHub profile of this
repository, or through GitHub's private vulnerability reporting on the
repository. Include the version (`cpprobe version`), the configuration
(`probe.yaml` without keys) and a reproduction. You will get an
acknowledgement within a few days.

Please do not run the probe client against control points you do not
operate, and do not open public issues for vulnerabilities before a fix is
released.

## What the server guarantees

See [`docs/server.md`](docs/server.md), section "Anti-abuse
guarantees": no egress code path, UDP replies never larger than the request
before the peer is validated, per-IP rate limits, no payload retention, a
24-hour in-memory retention of parsed observations only.
