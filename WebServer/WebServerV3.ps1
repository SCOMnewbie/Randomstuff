<#
  This function is an web API protected by Entra Id without dependencies other than Powershell 7, ValidateAADJWT for token validation.
#>
[CmdletBinding()]
param(
    [string[]]$ListenerPrefix = @('http://localhost:6161/'),
    $TenantId = 'e192cada-a04d-4cfc-8b90-d14338b2c7ec', # Azure Tenant Id
    $Audience = 'api://fca4cdf3-031d-41a2-a0be-ecd854b2f201', # Each application has a single audience
    $LogFolderName = 'myapi', # This is where we will store the logs under a temp folder
    $ClientId = 'fca4cdf3-031d-41a2-a0be-ecd854b2f201', # The Client Id of the application
    $ClientSecret = $env:DEMOClientSecret # The secret used to call the Graph API (On Behalf flow)
)

# Load Module
Import-Module -Name 'ValidateAadJwt' -Force -ErrorAction Stop
Import-Module -Name 'PSMsalNet' -Force -ErrorAction Stop

# Load function in memory
. $PSScriptRoot\CommonFunctions.ps1
. $PSScriptRoot\useexternalfunction.ps1
. $PSScriptRoot\calluserinfofromgraphapi.ps1

$BackendLogFileName = 'Backend_{0}.log' -f $(Get-Date -Format 'yyyy-MM-dd')
$RequestLogFileName = 'Request_{0}.log' -f $(Get-Date -Format 'yyyy-MM-dd')
$Global:BackendLogFilePath = Join-Path $([System.IO.Path]::GetTempPath()) $LogFolderName $BackendLogFileName
$Global:RequestLogFilePath = Join-Path $([System.IO.Path]::GetTempPath()) $LogFolderName $RequestLogFileName

Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Green -Message "All logs will be generated in $BackendLogFilePath file for backend logs and $RequestLogFilePath for request logs"

function Invoke-Middleware {
    param($Event)
    
    # Log request details
    Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor White -Message "Received request: $($Event.MessageData.Request.HttpMethod) $($Event.MessageData.Request.Url)"
    
    $Authority = $Event.MessageData.Request.Url.Authority #localhost:6161
    $AbsolutePath = $Event.MessageData.Request.Url.AbsolutePath #/admin/54325345 or /
    $AbsoluteUri = $Event.MessageData.Request.Url.AbsoluteUri #http://localhost:6161/admin/54325345
    #$QueryParameter = $Event.MessageData.Request.Url.Query.ToString().replace('?','') #?param1=value1&param2=value2 can be empty
    $PathAndQuery = $Event.MessageData.Request.Url.PathAndQuery #/admin/54325345?param1=value1&param2=value2, /, /admin

    $Route = $Event.MessageData.Request.Url.Segments[1]
    if($null -ne $Route){
        $Route = $Route.TrimEnd('/') # Remove trailing slash if any
    }
    else {
        $Route = '' # If no segment, set to empty string
    } # This is the first segment of the URL after the host, e.g., 'admin' or 'useexternalfunction'

    $IsAdminRequired = $false
    $AdminRole = 'NoAuthZ' # Hardcode dummy value to avoid unmanaged variable error

    # Declare all your routes. This pattern avoid security hole 
    # IMPORTANT: All routes must be declared
    # This is where you defined if you need AuthZ. If you need admin role, make sure you set $IsAdminRequired to $true and define $AdminRole with the proper role.
    switch ($Route) {
        '' {
            # Example to use the root route. No AuthZ required
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message '[middleware] Call / default route Admin role not required'
            break
        }
        'useexternalfunction' {
            # Example to use an external function No AuthZ required
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message '[middleware] Call /useexternalfunction route Admin role not required'
            break
        }
        'calluserinfofromgraphapi' {
            # Exemple to use an admin route. This is how we declare this route require AuthZ
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token. This part is validated bellow
            $AdminRole = 'SuperAdmin'
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message "[middleware] Call /admin route $AdminRole role is required"
            break
        }
        'UndeclaredRouteWithAuthZ' {
            # Example to use an undeclared route. This is how we declare this route require AuthZ
            # This should answer a 403
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token. For demo purpose, the role does not exist in the application.
            $AdminRole = 'DummyRole'
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message "[middleware] Call /UndeclaredRouteWithAuthZ function $AdminRole role is required"
            break
        }
        'UndeclaredRouteWithoutAuthZ' {
            # Example to use an undeclared route. This is how we declare this route require AuthZ
            # This should answer a 404
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message "[middleware] Call /UndeclaredRouteWithoutAuthZ function $AdminRole role is required"
            break
        }
        default {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel WARNING -HostColor Red -Message "[middleware] $Route is not an allowed route"
            NotFound -Event $Event -RequestLogFilePath $RequestLogFilePath
        }
    }

    # This is where you validate the required AuthZ
    if ($IsAdminRequired) {
        # This is an admin route (AuthZ required)
        # Let's grab the Authorization header (Entra token)
        $AuthorizationHeader = $Event.MessageData.Request.Headers['Authorization']
        # Test signature first will always return true or false. False means this is a forged token not an official one. Try catch to avoid blocking the webserver.
        $IsValidToken = try { Test-AADJWTSignature -Token $AuthorizationHeader -TenantId $TenantId }catch { $IsValidToken = $false }
        if ($IsValidToken) {
            $DecodedToken = ConvertFrom-Jwt -Token $AuthorizationHeader
            # Let's make sure this token is not for another app. If this is the case, drop the request
            if ($DecodedToken.Tokenpayload.aud -ne $Audience) {
                Forbidden -Event $Event -RequestLogFilePath $RequestLogFilePath
            }

            # For this application, we may have multiple roles exposed by Entra Id
            switch ($AdminRole) {
                # Make sure you declare all you application roles. If not 403 will be return with a small log on server side.
                'SuperAdmin' {
                    if ('SuperAdmin' -notin $DecodedToken.TokenPayload.roles) {
                        Forbidden -Event $Event -RequestLogFilePath $RequestLogFilePath
                    }
                }
                default {
                    Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel ERROR -HostColor Red -Message "Admin role $AdminRole is not defined in the API make sure to proper configure your API"
                    Forbidden -Event $Event -RequestLogFilePath $RequestLogFilePath
                }
            }
        }
        else {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel WARNING -HostColor Red -Message 'Forged token is not allowed'
            Unauthorized -Event $Event -RequestLogFilePath $RequestLogFilePath
        }
    }
    
    return [pscustomobject]@{
        Event      = $Event
        Route        = $Route
        Authority    = $Authority
        AbsolutePath = $AbsolutePath
        AbsoluteUri  = $AbsoluteUri
        PathAndQuery = $PathAndQuery
    }
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
catch { Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel ERROR -HostColor Red -Message "Could not start listener: $_" ; return } 

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

#Write-host "Now serving $Jobname" -ForegroundColor Green
Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Green -Message "Now serving $Jobname at $([DateTime]::now)"

while ($Httplistener.IsListening) {
    foreach ($Event in @(Get-Event HTTP*)) {
        #$Context, $Request, $Response = $Event.SourceArgs

        $ShouldExit = $false

        # Modify the middleware function to return both context And the extra properties route/UrlWithPort/parameters to avoid duplicate the code
        $RequestInfo = Invoke-Middleware -Event $Event

        #If not processed, let's keep it into the buffer
        # continue if 404/403 is return
        if (-not $Event.MessageData.Response.OutputStream) { continue }

        switch ($RequestInfo.Route) {
            '' {
                # / Can't have parameter (become a route if provided)
                # Generate a random JSON object because why not
                $randomObject = @{
                    Id        = [guid]::NewGuid().ToString()
                    Timestamp = (Get-Date).ToString('o')
                    Status    = Get-Random -InputObject @('Active', 'Inactive', 'Pending')
                    Score     = Get-Random -Minimum 1 -Maximum 100
                    Tags      = @('alpha', 'beta', 'gamma') | Get-Random -Count 2
                } | ConvertTo-Json -Depth 3

                $Event.MessageData.Response.Close($OutputEncoding.GetBytes($randomObject), $false)
                break
            }
            'useexternalfunction' {
                # Load an external function from an external file
                if ($RequestInfo.Parameters -match '^\d+$' ) {
                    # This function accept only integer
                    $Json = useexternalfunction -ItemCount $RequestInfo.Parameters
                    $Event.MessageData.Response.Close($OutputEncoding.GetBytes($Json), $false)
                    # Don't forget to log the result somewhere
                }
                else {
                    # Parameter is not validated
                    # IMPORTANT make sure this variable is assigned BEFORE the NotFound function
                    $ShouldExit = $true
                    # return 404 if user provide bad parameters
                    NotFound -Event $Event -RequestLogFilePath $RequestLogFilePath
                }
            }
            'calluserinfofromgraphapi'{
                # validate query parameters
                $QueryParameters = $($Event.MessageData.Request.Url.Query.ToString().replace('?',''))
                if($QueryParameters -match 'UserPrincipalName=([\w-\.]+@([\w-]+\.)+[\w-]{2,4})') {
                    $UserPrincipalName = $matches[1]
                    $UserId = $null
                    $Json = calluserinfofromgraphapi -UserPrincipalName $UserPrincipalName -OBOToken $Event.MessageData.Request.Headers['Authorization'] -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId | ConvertTo-Json -Depth 3
                    $Event.MessageData.Response.Close($OutputEncoding.GetBytes($Json), $false)
                }
                elseif($QueryParameters -match 'UserId=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
                    $UserId = [guid]$matches[1]
                    $UserPrincipalName = $null
                }
                else {
                    #TODO:Validate this part
                    # Parameter is not validated
                    # IMPORTANT make sure this variable is assigned BEFORE the NotFound function
                    $ShouldExit = $true
                    # return 404 if user provide bad parameters
                    NotFound -Event $Event -RequestLogFilePath $RequestLogFilePath
                }
            }
            default {
                # Should never go there. A none declared route is managed by the middleware (default)
                $Event.MessageData.Response.Close($OutputEncoding.GetBytes('Should never go there'), $false)
            }
        }

        # If parameter is not validated, skip this step
        if (-not $ShouldExit) {
            # Close the response stream and write the response
            $TimeTakenInMs = [Math]::Round($($([datetime]::Now - $Event.TimeGenerated).TotalMilliseconds),0)
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Cyan -Message "Responded to $($RequestInfo.AbsolutePath) in $TimeTakenInMs ms"
            Write-RequestLog -Event $Event -LogFilePath $RequestLogFilePath -TimeTakenInMs $TimeTakenInMs
            $Event | Remove-Event
        }
    }
}