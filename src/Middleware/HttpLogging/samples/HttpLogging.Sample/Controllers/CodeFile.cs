// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebApplication1.Controllers;

public class EchoPayload
{
    public string Message { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}

[Route("echo")]
[ApiController]
public class EchoController : ControllerBase
{
    ILogger<EchoController> _logger;

    public EchoController(ILogger<EchoController> logger)
    {
        _logger = logger;
        _logger.LogInformation($"Constructor called");
    }

    // POST api/<TestController>
    [HttpGet]
    public string Get()
    {
        _logger.LogInformation($"Get called");
        return $"Hello from {this.GetType().FullName}.  Send me a post.";
    }

    // POST api/<TestController>
    [HttpPost]
    public EchoPayload Post([FromBody] EchoPayload thePayload)
    {
        _logger.LogInformation($"Post called");
        return thePayload;
    }
}
