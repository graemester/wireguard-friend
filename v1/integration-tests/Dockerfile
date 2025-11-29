# Minimal Alpine container with WireGuard
FROM alpine:latest

# Install WireGuard tools and utilities
RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    iproute2 \
    iputils \
    bash \
    openssh \
    python3 \
    py3-pip

# Enable SSH for config deployment testing
RUN ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "root:wgfriend" | chpasswd

# Enable IP forwarding (for subnet router)
RUN echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf

# Create directory for WireGuard configs
RUN mkdir -p /etc/wireguard

# Default command: start SSH and keep container running
CMD ["/bin/sh", "-c", "/usr/sbin/sshd && tail -f /dev/null"]
