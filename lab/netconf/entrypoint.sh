#!/bin/sh
set -e

# Load the YANG modules netopeer2 needs into sysrepo.
if [ -x /usr/local/share/netopeer2/scripts/setup.sh ]; then
    NP2_MODULE_DIR=/usr/local/share/yang/modules/netopeer2 \
    NP2_MODULE_PERMS=600 \
    /usr/local/share/netopeer2/scripts/setup.sh || true
fi

# ietf-interfaces is installed but its mandatory `type` leaf is an
# identityref into iana-if-type, which is not. Without it every interface
# config fails validation, so the tests would be exercising an error path
# instead of the change loop.
sysrepoctl -i /usr/local/share/yang/modules/sysrepo/iana-if-type@2014-05-08.yang \
    -s /usr/local/share/yang/modules/sysrepo 2>/dev/null || true

# netopeer2 ships knowing only about root. Register the lab account so it can
# authenticate with a password — libnetconf2 calls this keyboard-interactive
# and delegates it to PAM.
cat > /tmp/np2-user.xml <<'XML'
<netconf-server xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-server">
  <listen>
    <endpoints>
      <endpoint>
        <name>default-ssh</name>
        <ssh>
          <ssh-server-parameters>
            <client-authentication>
              <users>
                <user>
                  <name>netnerd</name>
                  <keyboard-interactive xmlns="urn:cesnet:libnetconf2-netconf-server">
                    <use-system-auth/>
                  </keyboard-interactive>
                </user>
              </users>
            </client-authentication>
          </ssh-server-parameters>
        </ssh>
      </endpoint>
    </endpoints>
  </listen>
</netconf-server>
XML
sysrepocfg --edit=/tmp/np2-user.xml -m ietf-netconf-server -d running -f xml || true

# NACM defaults to denying writes to everyone but a recovery (uid 0) session.
# Switched off because this container exists to exercise a NETCONF client, and
# access control is not what is under test — a real device keeps it on.
cat > /tmp/np2-nacm.xml <<'XML'
<nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
  <enable-nacm>false</enable-nacm>
</nacm>
XML
sysrepocfg --edit=/tmp/np2-nacm.xml -m ietf-netconf-acm -d running -f xml || true

exec netopeer2-server -d -v2
