using Microsoft.AspNetCore.Mvc;

namespace SecureRequest.Sample.Controllers;

/// <summary>
/// Example controller — SecureRequestMiddleware decrypts and verifies the body
/// BEFORE it reaches here. The action receives plain JSON as if no encryption occurred.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    /// <summary>
    /// Creates an order. Body is transparently decrypted by SecureRequestMiddleware.
    /// </summary>
    [HttpPost]
    public IActionResult Create([FromBody] CreateOrderRequest request)
    {
        // At this point the body is already decrypted — work with it normally.
        return Ok(new
        {
            id        = Guid.NewGuid(),
            product   = request.Product,
            quantity  = request.Quantity,
            createdAt = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET is not in SecuredMethods — bypassed automatically, no headers needed.
    /// </summary>
    [HttpGet("{id}")]
    public IActionResult Get(Guid id) => Ok(new { id, status = "shipped" });
}

public record CreateOrderRequest(string Product, int Quantity);
