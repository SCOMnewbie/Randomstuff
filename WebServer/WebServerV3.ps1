[CmdletBinding()]
param(
    [string[]]$ListenerPrefix = @('http://localhost:6161/'),
    $TenantId = 'e192cada-a04d-4cfc-8b90-d14338b2c7ec', # Azure Tenant Id
    $Audience = 'api://fca4cdf3-031d-41a2-a0be-ecd854b2f201' # Each application has a singla audience
)

# If we're running in a container and the listener prefix is not http://*:80/,
if ($env:IN_CONTAINER -and $listenerPrefix -ne 'http://*:80/') {
    # then set the listener prefix to http://*:80/ (listen to all incoming requests on port 80).
    $listenerPrefix = 'http://*:80/'
}

function Invoke-Middleware {
    param($context, $Event)
    
    # Log request details
    Write-Host "Received request: $($context.Request.HttpMethod) $($context.Request.Url)"

    $AllowedURLRegex = '^(?<urlwithport>https?:\/\/[^\s\/]+:\d+)\/(?<route>[^\s\/?]*)\/{0,1}(?<parameters>[^\s?]*)$'
    $Context.Request.Url -match $AllowedURLRegex | out-null
    $UrlWithPort = $matches["urlwithport"]
    $Route = $matches["route"] # Is null for /
    $parameters = $matches["parameters"] # Can be for now /blah/blih/bloh
    $IsAdminRequired = $false
    $AdminRole = 'NoAuthZ'

    #Validate valide route
    switch ($Route) {
        '' {
            Write-host "Route / has been request" -ForegroundColor Yellow
        }
        'blah' {
            Write-host "Route /blah has been request" -ForegroundColor Yellow
        }
        'admin' {
            $IsAdminRequired = $true
            $AdminRole = 'SuperAdmin'
            Write-host "Route /admin has been request" -ForegroundColor Yellow
            break
        }
        Default {
            Write-host "$Route is not an allowed route" -ForegroundColor Red
            $Context.Response.StatusCode = 404
            $Context.Response.Close()
            # Remove unwanted events
            $Event | Remove-Event
            break
        }
    }

    if ($IsAdminRequired) {
        $AuthorizationHeader = $context.Request.Headers['Authorization']
        # Test signature first will always return true or false. False means this is a forged token not an official one.
        if (Test-AADJWTSignature -Token $AuthorizationHeader -TenantId $TenanId) {
            $DecodedToken = ConvertFrom-Jwt -Token $AuthorizationHeader
            # This token is not for another app
            if ($DecodedToken.Tokenpayload.aud -ne $Audience) {
                $Context.Response.StatusCode = 403
                $Context.Response.Close()
                # Remove unwanted events
                $Event | Remove-Event
                break
            }

            switch ($AdminRole) {
                'SuperAdmin' {
                    try {
                        if ('SuperAdmin' -notin $DecodedToken.TokenPayload.roles) {
                            # If role is not in the list drop
                            $Context.Response.StatusCode = 403
                            $Context.Response.Close()
                            # Remove unwanted events
                            $Event | Remove-Event
                            break
                        }
                    }
                    catch {
                        $_.Exception.Message
                    }
                    
                    write-host "Authz : $AuthZ"
                }
                Default {
    
                }
            }
        }
        else {
            Write-host "Forged token is not allowed" -ForegroundColor Red
            $Context.Response.StatusCode = 404
            $Context.Response.Close()
            # Remove unwanted events
            $Event | Remove-Event
            break
        }
    }
    else {
        Write-host "Route does not require AuthN/AuthZ" -ForegroundColor Red
    }

    return $context
}

# If we do not have a global HttpListener object,   
if (-not $global:HttpListener) {
    # then create a new HttpListener object.
    $global:HttpListener = [Net.HttpListener]::new()
    # and add the listener prefixes.
    foreach ($prefix in $ListenerPrefix) {
        if ($global:HttpListener.Prefixes -notcontains $prefix) {
            $global:HttpListener.Prefixes.Add($prefix)
        }    
    }
}

if ($global:HttpListener.Prefixes -gt 1) {
    $Jobname = $global:HttpListener.Prefixes[0]
}
else {
    $Jobname = $global:HttpListener.Prefixes
}

# Start the listener.
try { $Httplistener.Start() }
# If the listener cannot start, write a warning and return.
catch { Write-Warning "Could not start listener: $_" ; return }

Write-verbose "Jobname: $Jobname"
Write-verbose "HttpListener: $HttpListener"

# The ServerJob will start the HttpListener and listen for incoming requests.
$script:ServerJob = Start-ThreadJob -ScriptBlock {
    param($MainRunspace, $Httplistener, $SourceIdentifier = 'http')
    while ($Httplistener.IsListening) {
        $ContextAsync = $Httplistener.GetContextAsync()
        while (-not $ContextAsync.IsCompleted -or $ContextAsync.IsFaulted -or $ContextAsync.IsCanceled) {}
        if ($ContextAsync.IsFaulted) {
            Write-Error -Exception $ContextAsync.Exception -Category ProtocolError
            continue
        }
        $Context = $(try { $ContextAsync.Result }catch { $_ })

        $MainRunspace.Events.GenerateEvent(
            $SourceIdentifier, $Httplistener, @($Context, $Context.Request, $Context.Response),
            [ordered]@{Url = $Context.Request.Url; Context = $Context; Request = $Context.Request; Response = $Context.Response }
        )
    }
} -Name $Jobname -ArgumentList ([runspace]::DefaultRunspace, $Httplistener) -ThrottleLimit 100 | 
Add-Member -NotePropertyMembers ([Ordered]@{HttpListener = $Httplistener }) -PassThru

Write-host "Now serving $Jobname" -ForegroundColor Green

# If PowerShell is exiting, close the HttpListener.
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    $global:Httplistener.Close()
}

# Keep track of the creation time of the DiceServerJob.
$ServerJob | Add-Member -MemberType NoteProperty Created -Value ([DateTime]::now) -Force

$Rng = [System.Random]::new()

while ($Httplistener.IsListening) {
    foreach ($Event in @(Get-Event HTTP*)) {
        $Context, $Request, $Response = $Event.SourceArgs

        $context = Invoke-Middleware -context $context -Event $Event

        #If not processed, let's keep it into the buffer
        if (-not $Response.OutputStream) { continue }

        $Response.Close($OutputEncoding.GetBytes("$($Rng.Next())"), $false)
        Write-host "Responded to $($Request.Url) in $([datetime]::Now - $Event.TimeGenerated)" -ForegroundColor Cyan
        $Event | Remove-Event
    }
}