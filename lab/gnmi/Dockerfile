# A gNMI target for the lab.
#
# Neither FRR nor netopeer2 speaks gNMI, so without this the transport would
# ship on the strength of the spec alone — and every defect found in this
# project so far was found by running something, none by reading.
#
# google/gnxi is the reference implementation from the gNMI authors. Testing a
# client against the reference means passing proves standards compliance
# rather than compatibility with one vendor's interpretation.
FROM golang:1.23-bookworm AS build

WORKDIR /src
RUN git clone --depth 1 https://github.com/google/gnxi.git . \
 && CGO_ENABLED=0 go build -o /out/gnmi_target ./gnmi_target

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/gnmi_target /usr/local/bin/gnmi_target
COPY model.json /etc/gnmi/model.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 57400
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
