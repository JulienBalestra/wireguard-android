/*
 * Copyright © 2017-2019 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import com.wireguard.util.NonNullForAll;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

import androidx.annotation.Nullable;


/**
 * An external endpoint (host and port) used to connect to a WireGuard {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    @Nullable private final String[] resolvers;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port, @Nullable final String[] resolvers) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
        this.resolvers = resolvers;
    }

    public static InetEndpoint parse(String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Invalid port number");
        // it's a potential DNS SRV record
        if (uri.getPort() == -1) {
            // 8.8.8.8,1.1.1.1@123abc._wireguard._udp.domain.local:0
            final String[] parts = endpoint.split("@");
            if (parts.length > 1) {
                return new InetEndpoint(endpoint.split(":")[0], false, 0, parts[0].split(","));
            }
            return new InetEndpoint(endpoint.split(":")[0], false, 0, null);
        }
        try {
            InetAddresses.parse(uri.getHost());
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort(), null);
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort(), null);
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Generate an {@code InetEndpoint} instance with the same port and the host resolved using DNS
     * to a numeric address. If the host is already numeric, the existing instance may be returned.
     * Because this function may perform network I/O, it must not be called from the main thread.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            //TODO(zx2c4): Implement a real timeout mechanism using DNS TTL
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    final ExtendedResolver res = new ExtendedResolver();
                    if (resolvers != null) {
                        for (final String s: resolvers) {
                            res.addResolver(new SimpleResolver(s));
                        }
                    }
                    final String[] parts = host.split("@");
                    String srvQuery = parts[0];
                    if (parts.length > 1) {
                        srvQuery = parts[1];
                    }
                    Lookup l = new Lookup(srvQuery, Type.SRV, DClass.IN);
                    l.setResolver(res);
                    l.run();
                    if (l.getResult() == Lookup.SUCCESSFUL && l.getAnswers().length == 1) {
                        final SRVRecord srv = (SRVRecord) l.getAnswers()[0];
                        l = new Lookup(srv.getAdditionalName(), Type.A, DClass.IN);
                        l.setResolver(res);
                        l.run();
                        if (l.getResult() == Lookup.SUCCESSFUL && l.getAnswers().length == 1) {
                            final ARecord a = (ARecord) l.getAnswers()[0];
                            resolved = new InetEndpoint(a.getAddress().getHostAddress(), true, srv.getPort(), resolvers);
                            lastResolution = Instant.now();
                            return Optional.ofNullable(resolved);
                        }
                    }
                    // Prefer v4 endpoints over v6 to work around DNS64 and IPv6 NAT issues.
                    final InetAddress[] candidates = InetAddress.getAllByName(host);
                    InetAddress address = candidates[0];
                    for (final InetAddress candidate : candidates) {
                        if (candidate instanceof Inet4Address) {
                            address = candidate;
                            break;
                        }
                    }
                    resolved = new InetEndpoint(address.getHostAddress(), true, port, resolvers);
                    lastResolution = Instant.now();
                } catch (final UnknownHostException | TextParseException e) {
                    resolved = null;
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
