FROM registry.svc.ci.openshift.org/ocp/builder:rhel-8-golang-openshift-4.6 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM registry.svc.ci.openshift.org/ocp/builder:rhel-8-base-openshift-4.6
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
