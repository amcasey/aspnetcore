// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Server.Kestrel.Core;

internal sealed class KestrelServerImpl : KestrelServerBase
{
    public KestrelServerImpl(
        IOptions<KestrelServerOptions> options,
        IEnumerable<IConnectionListenerFactory> transportFactories,
        ILoggerFactory loggerFactory)
        : this(transportFactories, Array.Empty<IMultiplexedConnectionListenerFactory>(), CreateServiceContext(options, loggerFactory, diagnosticSource: null))
    {
    }

    public KestrelServerImpl(
        IOptions<KestrelServerOptions> options,
        IEnumerable<IConnectionListenerFactory> transportFactories,
        IEnumerable<IMultiplexedConnectionListenerFactory> multiplexedFactories,
        ILoggerFactory loggerFactory)
        : this(transportFactories, multiplexedFactories, CreateServiceContext(options, loggerFactory, diagnosticSource: null))
    {
    }

    public KestrelServerImpl(
        IOptions<KestrelServerOptions> options,
        IEnumerable<IConnectionListenerFactory> transportFactories,
        IEnumerable<IMultiplexedConnectionListenerFactory> multiplexedFactories,
        ILoggerFactory loggerFactory,
        DiagnosticSource diagnosticSource)
        : this(transportFactories, multiplexedFactories, CreateServiceContext(options, loggerFactory, diagnosticSource))
    {
    }

    // For testing

    internal KestrelServerImpl(
        IEnumerable<IConnectionListenerFactory> transportFactories,
        IEnumerable<IMultiplexedConnectionListenerFactory> multiplexedFactories,
        ServiceContext serviceContext)
        : base(transportFactories, multiplexedFactories, serviceContext)
    {
    }

    protected override async Task OnBind<TContext>(IHttpApplication<TContext> application, ListenOptions options, CancellationToken onBindCancellationToken)
    {
        var hasHttp1 = options.Protocols.HasFlag(HttpProtocols.Http1);
        var hasHttp2 = options.Protocols.HasFlag(HttpProtocols.Http2);
        var hasHttp3 = options.Protocols.HasFlag(HttpProtocols.Http3);
        var hasTls = options.IsTls;

        // Filter out invalid combinations.

        if (!hasTls)
        {
            // Http/1 without TLS, no-op HTTP/2 and 3.
            if (hasHttp1)
            {
                if (options.ProtocolsSetExplicitly)
                {
                    if (hasHttp2)
                    {
                        Trace.Http2DisabledWithHttp1AndNoTls(options.EndPoint);
                    }
                    if (hasHttp3)
                    {
                        Trace.Http3DisabledWithHttp1AndNoTls(options.EndPoint);
                    }
                }

                hasHttp2 = false;
                hasHttp3 = false;
            }
            // Http/3 requires TLS. Note we only let it fall back to HTTP/1, not HTTP/2
            else if (hasHttp3)
            {
                throw new InvalidOperationException("HTTP/3 requires HTTPS.");
            }
        }

        // Quic isn't registered if it's not supported, throw if we can't fall back to 1 or 2
        if (hasHttp3 && !HasMultiplexedTransportFactories && !(hasHttp1 || hasHttp2))
        {
            throw new InvalidOperationException("This platform doesn't support QUIC or HTTP/3.");
        }

        // Disable adding alt-svc header if endpoint has configured not to or there is no
        // multiplexed transport factory, which happens if QUIC isn't supported.
        var addAltSvcHeader = !options.DisableAltSvcHeader && HasMultiplexedTransportFactories;

        var configuredEndpoint = options.EndPoint;

        // Add the HTTP middleware as the terminal connection middleware
        if (hasHttp1 || hasHttp2
            || options.Protocols == HttpProtocols.None) // TODO a test fails because it doesn't throw an exception in the right place
                                                        // when there is no HttpProtocols in KestrelServer, can we remove/change the test?
        {
            if (!HasTransportFactories)
            {
                throw new InvalidOperationException($"Cannot start HTTP/1.x or HTTP/2 server if no {nameof(IConnectionListenerFactory)} is registered.");
            }

            options.UseHttpServer(ServiceContext, application, options.Protocols, addAltSvcHeader);
            var connectionDelegate = options.Build();

            // Add the connection limit middleware
            connectionDelegate = EnforceConnectionLimit(connectionDelegate, Options.Limits.MaxConcurrentConnections, Trace);

            options.EndPoint = await TransportManager.BindAsync(configuredEndpoint, connectionDelegate, options.EndpointConfig, onBindCancellationToken).ConfigureAwait(false);
        }

        if (hasHttp3 && HasMultiplexedTransportFactories)
        {
            // Check if a previous transport has changed the endpoint. If it has then the endpoint is dynamic and we can't guarantee it will work for other transports.
            // For more details, see https://github.com/dotnet/aspnetcore/issues/42982
            if (!configuredEndpoint.Equals(options.EndPoint))
            {
                Trace.LogError(CoreStrings.DynamicPortOnMultipleTransportsNotSupported);
            }
            else
            {
                options.UseHttp3Server(ServiceContext, application, options.Protocols, addAltSvcHeader);
                var multiplexedConnectionDelegate = ((IMultiplexedConnectionBuilder)options).Build();

                // Add the connection limit middleware
                multiplexedConnectionDelegate = EnforceConnectionLimit(multiplexedConnectionDelegate, Options.Limits.MaxConcurrentConnections, Trace);

                options.EndPoint = await TransportManager.BindAsync(configuredEndpoint, multiplexedConnectionDelegate, options, onBindCancellationToken).ConfigureAwait(false);
            }
        }
    }

    protected override void UseHttps(ListenOptions listenOptions)
    {
        if (!listenOptions.IsTls)
        {
            listenOptions.UseHttps();
        }
    }
}
