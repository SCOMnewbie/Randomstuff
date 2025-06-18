<#
  This function is an web API protected by Entra Id without dependencies other than Powershell 7.
#>
[CmdletBinding()]
param(
    [string[]]$ListenerPrefix = @('http://localhost:6161/'),
    $TenantId = 'e192cada-a04d-4cfc-8b90-d14338b2c7ec', # Azure Tenant Id
    $Audience = 'api://fca4cdf3-031d-41a2-a0be-ecd854b2f201' # Each application has a singla audience
)

# Load function in memory
. $PSScriptRoot\useexternalfunction.ps1

# If we're running in a container and the listener prefix is not http://*:80/,
if ($env:IN_CONTAINER -and $listenerPrefix -ne 'http://*:80/') {
    # then set the listener prefix to http://*:80/ (listen to all incoming requests on port 80).
    $listenerPrefix = 'http://*:80/'
}

# Return a 404
function NotFound {
    param($context, $Event)
    $Context.Response.StatusCode = 404
    $Context.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

# Return a 403
function NotAllowed {
    param($context, $Event)
    $Context.Response.StatusCode = 403
    $Context.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

function Invoke-Middleware {
    param($context, $Event)
    
    # Log request details
    Write-Host "Received request: $($context.Request.HttpMethod) $($context.Request.Url)"

    $AllowedURLRegex = '^(?<urlwithport>https?:\/\/[^\s\/]+:\d+)\/(?<route>[^\s\/?]*)\/{0,1}(?<parameters>[^\s?]*)$'
    #Get URL information
    $Context.Request.Url -match $AllowedURLRegex | out-null
    $UrlWithPort = $matches["urlwithport"]
    $Route = $matches["route"] # Is null for /
    $Parameters = $matches["parameters"] # Can be for now /blah/blih/bloh
    $IsAdminRequired = $false
    $AdminRole = 'NoAuthZ'

    #Declare all your routes. This pattern avoid security hole (all routes must be declared).
    # This is where you defined if you need AuthZ
    switch ($Route) {
        '' {
            Write-host "Call / function" -ForegroundColor Yellow
            break
        }
        'useexternalfunction' {
            Write-host "Call /useexternalfunction function" -ForegroundColor Yellow
            break
        }
        'admin' {
            # This is how we declare this route require AuthZ
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token
            $AdminRole = 'SuperAdmin'
            Write-host "Call /admin function" -ForegroundColor Yellow
            break
        }
        'fakeAdmin' {
            # This is how we declare this route require AuthZ
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token. For demo purpose, the role does not exist in the application.
            $AdminRole = 'FakeSuperAdmin'
            Write-host "Call /fakeAdmin function" -ForegroundColor Yellow
            break
        }
        Default {
            Write-host "$Route is not an allowed route" -ForegroundColor Red
            NotFound -context $context -Event $Event
        }
    }

    # This is where you validate the required AuthZ
    if ($IsAdminRequired) {
        # This is an admin route (AuthZ required)
        # Let's grab the Authorization header (Entra token)
        $AuthorizationHeader = $context.Request.Headers['Authorization']
        # Test signature first will always return true or false. False means this is a forged token not an official one.
        #TODO: bulletproof the test signature to not kill the webserver
        if (Test-AADJWTSignature -Token $AuthorizationHeader -TenantId $TenantId -ErrorAction SilentlyContinue) {
            $DecodedToken = ConvertFrom-Jwt -Token $AuthorizationHeader
            # Let's make sure this token is not for another app. If this is the case, drop the request
            if ($DecodedToken.Tokenpayload.aud -ne $Audience) {
                NotAllowed -context $context -Event $Event
            }

            # For this application, we may have multiple roles exposed by Entra Id
            switch ($AdminRole) {
                # Make sure you declare all you application roles. If not 403 will be return with a small log on server side.
                'SuperAdmin' {
                    if ('SuperAdmin' -notin $DecodedToken.TokenPayload.roles) {
                        NotAllowed -context $context -Event $Event
                    }
                }
                Default {
                    Write-host "Admin role $AdminRole is not defined in the API make sure to proper configure your API" -ForegroundColor Red
                    NotAllowed -context $context -Event $Event
                }
            }
        }
        else {
            Write-host "Forged token is not allowed" -ForegroundColor Red
            NotFound -context $context -Event $Event
        }
    }
    
    return [pscustomobject]@{
        Context     = $context
        UrlWithPort = $UrlWithPort
        Route       = $Route
        Parameters  = $Parameters
    }
    #return $context
}

# If we do not have a global HttpListener object
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

<#
# If PowerShell is exiting, close the HttpListener.
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    $global:Httplistener.Close()
}
#>

# Keep track of the creation time of the DiceServerJob.
$ServerJob | Add-Member -MemberType NoteProperty Created -Value ([DateTime]::now) -Force

while ($Httplistener.IsListening) {
    foreach ($Event in @(Get-Event HTTP*)) {
        $Context, $Request, $Response = $Event.SourceArgs

        $ShouldExit = $false

        # Modify the middleware function to return both context And the extra properties route/UrlWithPort/parameters to avoid duplicate the code
        $RequestInfo = Invoke-Middleware -context $context -Event $Event

        #If not processed, let's keep it into the buffer
        # continue if 404/403 is return
        if (-not $Response.OutputStream) { continue }

        switch ($RequestInfo.Route) {
            '' {
                # / Can't have parameter (become a route if provided)
                # Generate a random JSON object because why not
                $randomObject = @{
                    Id        = [guid]::NewGuid().ToString()
                    Timestamp = (Get-Date).ToString("o")
                    Status    = Get-Random -InputObject @("Active", "Inactive", "Pending")
                    Score     = Get-Random -Minimum 1 -Maximum 100
                    Tags      = @("alpha", "beta", "gamma") | Get-Random -Count 2
                } | ConvertTo-Json -Depth 3

                $Response.Close($OutputEncoding.GetBytes($randomObject), $false)
                break
            }
            'useexternalfunction' {
                # Load an external function from an external file
                if($RequestInfo.Parameters -match '^\d+$' ){
                    # This function accept only integer
                    $Json = useexternalfunction -ItemCount $RequestInfo.Parameters
                    $Response.Close($OutputEncoding.GetBytes($Json), $false)
                    # Don't forget to log the result somewhere
                }
                else{
                    # Parameter is not validated
                    # IMPORTANT make sure this variable is assigned BEFORE the NotFound function
                    $ShouldExit = $true
                    # return 404 if user provide bad parameters
                    NotFound -context $context -Event $Event
                }
                
                
            }
            Default {
                # Should never go there. A none declared route is managed by the middleware (default)
                $Response.Close($OutputEncoding.GetBytes("Should never go there"), $false)
            }
        }

        # If parameter is not validated, skip this step
        if(-not $ShouldExit){
            Write-host "Responded to $($Request.Url) in $([datetime]::Now - $Event.TimeGenerated)" -ForegroundColor Cyan
            $Event | Remove-Event
        } 
    }

    <#
    # Wait for the PowerShell.Exiting event.
    $exiting = Wait-Event -SourceIdentifier PowerShell.Exiting -Timeout (Get-Random -Minimum 1 -Maximum 5)
    if ($exiting) {
        # If the Stop the web server is still running, stop it.
        $Jobname | Stop-Job
        # and break out of the loop.
        break
    }
    #>
}