FROM quay.io/frrouting/frr:10.2.1

# ponytail: vtysh as the login shell, so netmiko's stock cisco_ios driver talks
# to FRR unmodified (vtysh mimics IOS: `r1>`/`r1#` prompts, enable, conf t).
# That means these tests exercise the REAL code path, not an FRR special case.
USER root
RUN apk add --no-cache openssh-server shadow \
 && ssh-keygen -A \
 && adduser -D -s /usr/bin/vtysh netnerd \
 && echo 'netnerd:netnerd123' | chpasswd \
 && adduser netnerd frrvty \
 && adduser netnerd frr \
 # Same container, ordinary shell. Gives the lab a Linux node (spec section 5)
 # and, more usefully, a device whose output ntc-templates actually has
 # templates for — FRR has none, so this is the only way to prove the parsing
 # path end to end over real SSH rather than in a unit test.
 && adduser -D -s /bin/sh netshell \
 && echo 'netshell:netnerd123' | chpasswd \
 && apk add --no-cache iproute2 \
 && sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 # The suite opens a fresh session per test, and any connection abandoned
 # mid-handshake holds an unauthenticated slot until LoginGraceTime expires.
 # At the stock 10:30:100 that starts randomly dropping connections partway
 # through a run, which surfaces as "Error reading SSH protocol banner" on
 # tests that have nothing wrong with them. Real switches are not this
 # sensitive; this is the lab keeping up with the tests.
 # ClientAlive matters more than it looks: an SSH session whose client goes
 # away without closing keeps running, and it holds an inherited copy of the
 # listening socket. If the listener then dies, port 22 stays bound by those
 # orphans and no new sshd can take over — the container passes a port check
 # and refuses every connection. Reaping dead sessions is what makes that
 # recoverable.
 && printf '\nMaxStartups 100:30:200\nMaxSessions 100\nLoginGraceTime 20\nClientAliveInterval 15\nClientAliveCountMax 2\nTCPKeepAlive yes\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
