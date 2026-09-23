# A real NETCONF server for the lab.
#
# FRR speaks only an IOS-like CLI, so nothing in the lab could exercise the
# NETCONF transport — and the part that matters most, RFC 6241 confirmed
# commit, is exactly the part that cannot be verified by reading the code.
#
# Built from source because there is no published arm64 image. netopeer2 is
# CESNET's reference NETCONF server, which is the right thing to test a
# client against: if the transport works here it is the transport that is
# standards-compliant, not just compatible with one vendor's quirks.
FROM debian:trixie-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git pkg-config ca-certificates \
        libpcre2-dev libssl-dev libssh-dev zlib1g-dev libcurl4-openssl-dev libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Built in dependency order; each is a dependency of the next.
RUN git clone --depth 1 https://github.com/CESNET/libyang.git \
 && cmake -S libyang -B libyang/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build libyang/build -j"$(nproc)" && cmake --install libyang/build && ldconfig

RUN git clone --depth 1 https://github.com/sysrepo/sysrepo.git \
 && cmake -S sysrepo -B sysrepo/build -DCMAKE_BUILD_TYPE=Release -DREPO_PATH=/etc/sysrepo \
 && cmake --build sysrepo/build -j"$(nproc)" && cmake --install sysrepo/build && ldconfig

RUN git clone --depth 1 https://github.com/CESNET/libnetconf2.git \
 && cmake -S libnetconf2 -B libnetconf2/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build libnetconf2/build -j"$(nproc)" && cmake --install libnetconf2/build && ldconfig

RUN git clone --depth 1 https://github.com/CESNET/netopeer2.git \
 && cmake -S netopeer2 -B netopeer2/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build netopeer2/build -j"$(nproc)" && cmake --install netopeer2/build && ldconfig

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 libssl3 libssh-4 zlib1g libcurl4 libpam0g openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /usr/local/bin/ /usr/local/bin/
COPY --from=build /usr/local/sbin/ /usr/local/sbin/
COPY --from=build /usr/local/share/ /usr/local/share/
COPY --from=build /etc/sysrepo/ /etc/sysrepo/
RUN ldconfig

# netopeer2 authenticates against system users, so the lab gets the same
# throwaway account the FRR nodes use.
RUN useradd -m -s /bin/bash netnerd && echo 'netnerd:netnerd123' | chpasswd

COPY pam-netopeer2 /etc/pam.d/netopeer2
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 830
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
