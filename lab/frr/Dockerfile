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
 && sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
