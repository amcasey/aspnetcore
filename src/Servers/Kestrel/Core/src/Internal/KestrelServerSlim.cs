// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Server.Kestrel.Core;

// TODO (acasey): Need an intermediate type that supports https but not quic
internal sealed class KestrelServerSlim : KestrelServerBase
{
    public KestrelServerSlim(
        IOptions<KestrelServerOptions> options,
        IEnumerable<IConnectionListenerFactory> transportFactories,
        ILoggerFactory loggerFactory)
        : base(transportFactories, Array.Empty<IMultiplexedConnectionListenerFactory>(), CreateServiceContext(options, loggerFactory, diagnosticSource: null, disableDefaultCertificate: true))
    {
    }

    protected override async Task OnBind<TContext>(IHttpApplication<TContext> application, ListenOptions options, CancellationToken onBindCancellationToken)
    {
        var hasHttp1 = options.Protocols.HasFlag(HttpProtocols.Http1);
        var hasHttp2 = options.Protocols.HasFlag(HttpProtocols.Http2);
        var hasHttp3 = options.Protocols.HasFlag(HttpProtocols.Http3);
        var hasTls = options.IsTls; // May be true if the user has called UseHttps and explicitly configured a cert

        if (hasHttp3)
        {
            throw new InvalidOperationException("Nope"); // TODO (acasey): message
        }

        // Filter out invalid combinations.

        if (!hasTls)
        {
            // Http/1 without TLS, no-op HTTP/2.
            if (hasHttp1)
            {
                if (options.ProtocolsSetExplicitly && hasHttp2)
                {
                    Trace.Http2DisabledWithHttp1AndNoTls(options.EndPoint);
                }

                hasHttp2 = false;
            }
        }

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

            options.UseHttpServer(ServiceContext, application, options.Protocols, addAltSvcHeader: false);
            var connectionDelegate = options.Build();

            // Add the connection limit middleware
            connectionDelegate = EnforceConnectionLimit(connectionDelegate, Options.Limits.MaxConcurrentConnections, Trace);

            options.EndPoint = await TransportManager.BindAsync(configuredEndpoint, connectionDelegate, options.EndpointConfig, onBindCancellationToken).ConfigureAwait(false);
        }
    }

    protected override void UseHttps(ListenOptions options)
    {
        // If IsTls is true, it's possible the user made their own, valid UseHttps call.
        // However, if that's the case, then this method should not have been called.
        Debug.Assert(!options.IsTls);

        throw new InvalidOperationException("Nope"); // TODO (acasey): message
    }
}
