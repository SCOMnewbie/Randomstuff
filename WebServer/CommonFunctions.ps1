# Return a 404
function NotFound {
    param($context, $Event)
    $Context.Response.StatusCode = 404
    $Context.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

# Return a 403 (I know who you are but not allowed)
function Forbidden {
    param($context, $Event)
    $Context.Response.StatusCode = 403
    $Context.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

# Return a 401 (I don't know you get out)
function Unauthorized {
    param($context, $Event)
    $Context.Response.StatusCode = 401
    $Context.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}