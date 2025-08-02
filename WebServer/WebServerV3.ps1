<#
  This function is an web API protected by Entra Id without dependencies other than Powershell 7, ValidateAADJWT for token validation.
#>
[CmdletBinding()]
param(
    [string[]]$ListenerPrefix = @('http://localhost:6161/'),
    $TenantId = 'e192cada-a04d-4cfc-8b90-d14338b2c7ec', # Azure Tenant Id
    $Audience = 'api://fca4cdf3-031d-41a2-a0be-ecd854b2f201', # Each application has a single audience
    $LogFolderName = 'myapi' # This is where we will store the logs under a temp folder
)

# Load function in memory
. $PSScriptRoot\CommonFunctions.ps1
. $PSScriptRoot\useexternalfunction.ps1

$BackendLogFileName = 'Backend_{0}.log' -f $(Get-Date -Format 'yyyy-MM-dd')
$RequestLogFileName = 'Request_{0}.log' -f $(Get-Date -Format 'yyyy-MM-dd')
$BackendLogFilePath = Join-Path $([System.IO.Path]::GetTempPath()) $LogFolderName $BackendLogFileName
$RequestLogFilePath = Join-Path $([System.IO.Path]::GetTempPath()) $LogFolderName $RequestLogFileName

Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Green -Message "All logs will be generated in $BackendLogFilePath file for backend logs and $RequestLogFilePath for request logs"


function Invoke-Middleware {
    param($context, $Event)
    
    # Log request details
    Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor White -Message "Received request: $($context.Request.HttpMethod) $($context.Request.Url)"
    
    $Authority = $context.Request.Url.Authority #localhost:6161
    $AbsolutePath = $context.Request.Url.AbsolutePath #/admin/54325345 or /
    $AbsoluteUri = $context.Request.Url.AbsoluteUri #http://localhost:6161/admin/54325345
    $QueryParameter = $context.Request.Url.Query.ToString().replace('?','') #?param1=value1&param2=value2 can be empty
    $PathAndQuery = $context.Request.Url.PathAndQuery #/admin/54325345?param1=value1&param2=value2, /, /admin

    $Route = $context.Request.Url.Segments[1]
    if($null -ne $Route){
        $Route = $Route.TrimEnd('/') # Remove trailing slash if any
    }
    else {
        $Route = '' # If no segment, set to empty string
    } # This is the first segment of the URL after the host, e.g., 'admin' or 'useexternalfunction'

    $IsAdminRequired = $false
    $AdminRole = 'NoAuthZ'

    # Declare all your routes. This pattern avoid security hole (all routes must be declared).
    # This is where you defined if you need AuthZ. If you need admin role, make sure you set $IsAdminRequired to $true and define $AdminRole with the proper role.
    switch ($Route) {
        '' {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message '[middleware] Call / function Admin role not required'
            break
        }
        'useexternalfunction' {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message '[middleware] Call /useexternalfunction function Admin role not required'
            break
        }
        'admin' {
            # This is how we declare this route require AuthZ
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token
            $AdminRole = 'SuperAdmin'
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message "[middleware] Call /admin function $AdminRole role is required"
            break
        }
        'fakeAdmin' {
            # This is how we declare this route require AuthZ
            $IsAdminRequired = $true
            # This is the role claim we're waiting for in the token. For demo purpose, the role does not exist in the application.
            $AdminRole = 'FakeSuperAdmin'
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Yellow -Message "[middleware] Call /fakeAdmin function $AdminRole role is required"
            break
        }
        default {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel WARNING -HostColor Red -Message "[middleware] $Route is not an allowed route"
            NotFound -context $context -Event $Event -QueryParameter $QueryParameter -RequestLogFilePath $RequestLogFilePath
        }
    }

    # This is where you validate the required AuthZ
    if ($IsAdminRequired) {
        # This is an admin route (AuthZ required)
        # Let's grab the Authorization header (Entra token)
        $AuthorizationHeader = $context.Request.Headers['Authorization']
        # Test signature first will always return true or false. False means this is a forged token not an official one. Try catch to avoid blocking the webserver.
        $IsValidToken = try { Test-AADJWTSignature -Token $AuthorizationHeader -TenantId $TenantId }catch { $IsValidToken = $false }
        if ($IsValidToken) {
            $DecodedToken = ConvertFrom-Jwt -Token $AuthorizationHeader
            # Let's make sure this token is not for another app. If this is the case, drop the request
            if ($DecodedToken.Tokenpayload.aud -ne $Audience) {
                Forbidden -context $context -Event $Event -QueryParameter $QueryParameter -RequestLogFilePath $RequestLogFilePath
            }

            # For this application, we may have multiple roles exposed by Entra Id
            switch ($AdminRole) {
                # Make sure you declare all you application roles. If not 403 will be return with a small log on server side.
                'SuperAdmin' {
                    if ('SuperAdmin' -notin $DecodedToken.TokenPayload.roles) {
                        Forbidden -context $context -Event $Event -QueryParameter $QueryParameter -RequestLogFilePath $RequestLogFilePath
                    }
                }
                default {
                    Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel ERROR -HostColor Red -Message "Admin role $AdminRole is not defined in the API make sure to proper configure your API"
                    Forbidden -context $context -Event $Event -QueryParameter $QueryParameter -RequestLogFilePath $RequestLogFilePath
                }
            }
        }
        else {
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel WARNING -HostColor Red -Message 'Forged token is not allowed'
            Unauthorized -context $context -Event $Event -QueryParameter $QueryParameter -RequestLogFilePath $RequestLogFilePath
        }
    }
    
    return [pscustomobject]@{
        Context      = $context
        Route        = $Route
        Authority    = $Authority
        AbsolutePath = $AbsolutePath
        AbsoluteUri  = $AbsoluteUri
        Query        = $Query
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
                    Timestamp = (Get-Date).ToString('o')
                    Status    = Get-Random -InputObject @('Active', 'Inactive', 'Pending')
                    Score     = Get-Random -Minimum 1 -Maximum 100
                    Tags      = @('alpha', 'beta', 'gamma') | Get-Random -Count 2
                } | ConvertTo-Json -Depth 3

                $Response.Close($OutputEncoding.GetBytes($randomObject), $false)
                break
            }
            'useexternalfunction' {
                # Load an external function from an external file
                if ($RequestInfo.Parameters -match '^\d+$' ) {
                    # This function accept only integer
                    $Json = useexternalfunction -ItemCount $RequestInfo.Parameters
                    $Response.Close($OutputEncoding.GetBytes($Json), $false)
                    # Don't forget to log the result somewhere
                }
                else {
                    # Parameter is not validated
                    # IMPORTANT make sure this variable is assigned BEFORE the NotFound function
                    $ShouldExit = $true
                    # return 404 if user provide bad parameters
                    NotFound -context $context -Event $Event
                }
            }
            default {
                # Should never go there. A none declared route is managed by the middleware (default)
                $Response.Close($OutputEncoding.GetBytes('Should never go there'), $false)
            }
        }

        # If parameter is not validated, skip this step
        if (-not $ShouldExit) {
            #Write-host "Responded to $($Request.Url) in $([datetime]::Now - $Event.TimeGenerated)" -ForegroundColor Cyan
            Write-BackendLog -LogFilePath $BackendLogFilePath -LogLevel INFO -HostColor Cyan -Message "Responded to $($Request.Url) in $([datetime]::Now - $Event.TimeGenerated)"
            Write-RequestLog -Context $Context -QueryParameter $QueryParameter -LogFilePath $RequestLogFilePath
            $Event | Remove-Event
        }
    }
}

# Measure-Command -Expression{ (0..1000).ForEach({irm http://localhost:6161/})}

<#
{
  "timestamp": "2025-07-15T21:34:00Z",
  "level": "INFO",
  "message": "User logged in",
  "method": "POST",
  "path": "/api/login",
  "status": 200,
  "ip": "192.168.0.1",
  "userAgent": "Mozilla/5.0",
  "durationMs": 128,
  "authUser": "jdoe",
  "requestId": "abc123"
#>

# Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,ProtocolVersion,Host,HttpSubStatus"


<#
Date (date) : La date de la requête en temps UTC (cf. point suivant)
Time (time) : L’heure requête au format UTC. Il n’y a aucun moyen de forcer un horodatage en heure locale (La rotation des logs à minuit heure locale est toutefois possible). Pensez bien au décalage en analysant vos logs IIS (H+2 en été / H+1 en hiver pour la France).
Client IP Address (c-ip) : L’adresse IP du client. En réalité plutôt l’adresse IP de l’équipement ayant émis la requête. Dans le cadre d’un environnement avec repartition de charge vous risquez de voir uniquement les adresses IP de vos load-balancers. Il existe des moyens de relayer la veritable adresse IP des clients comme ici et ici.
User Name (cs-username) : L’utilisateur authentifié lorsque cela est possible. Un « – » signifie généralement une authentification anonyme.
Service Name (s-sitename) : L’identifiant du site ayant pris en charge la requête (1 pour le « Default Web Site » puis de manière séquentielle pour les autres – Il est toutefois possible de changer l’identifiant d’un site de manière programmatique).
Server Name (s-computername) : Le nom du serveur ayant pris en charge la requête. Si vous analysez les logs d’un site hébergé dans une ferme de serveurs, cette information est capitale.
Server IP (s-ip) : L’adresse IP ayant pris en charge la requête. En effet un site web peut écouter sur plusieurs adresses IP.
Server Port (s-port) : Le port d’écoute qui a pris en charge la requête. En effet un site web peut écouter sur plusieurs ports.
Method (cs-method) : Le « verbe » HTTP associé à la requête.
URI Stem (cs-uri-stem) : L’URI demandée sans le nom de domaine (/images/logo.png pour l’URI http://www.contoso.com/images/logo.png)
URI Query (cs-uri-query) : La query string si applicable (param1=value1&param2=value2 pour l’URI http://www.contoso.com/forms/default.aspx?param1=value1&param2=value2)
Protocol Status (sc-status) : Le code statut de la réponse (« 200 » indiquant que tout va bien)
Protocol Substatus (sc-substatus) : Le code de sous-statut de la réponse (2 dans la réponse « 401.2« )
Win32 Status (sc-win32-status) : Le statut Windows de la réponse (Statut propre à Windows)
Bytes Sent (sc-bytes) : La volumétrie sortante en octets. Information cruciale pour évaluer les gains en termes de compression(s) statique/dynamique et les effets des niveau de compression (allant de 0 à 10 – Ne jamais dépasser 9, en effet le gain entre 9 et 10 est minime en comparaison de la surcharge CPU engendrée. Une petite lecture intéressante est disponible ici. – Moyen mnémotechnique : sc-bytes – SC pour Server to Client)
Bytes Received (cs-bytes) : La volumétrie entrante (taille de la requête – Moyen mnémotechnique : cs-bytes – CS pour Client to Server)
Time Taken (time-taken) : Le temps de traitement de la requête (en millisecondes) dans sa totalité : incluant le temps d’attente dans la file d’attente HTTP.sys, le temps de traitement par les serveurs Middle-Office, Back-Office (si applicable) et le temps réseau entre les équipements. Le compteur ne s’arrêtera que lorsque le client acquittera la trame réseau (« ACK ») comme précisé ici. Ce qui implique qu’un time-taken élevé n’est pas forcément un problème au niveau du serveur IIS (les causes peuvent être multiples : latence réseau, requêtes SQL non optimisées …)
Procol Version (cs-version) : La version du protocole HTTP utilisée : 0.9, 1.0, 1.1, 2.0 …
Host (cs-host) : Le host header name (si applicable). Un host header name est utilisé pour différencier deux sites qui écoutent sur le même couple IP/Port de manière à router le trafic sur le bon site. En effet le host-header name doit correspondre à l’entrée DNS demandait par les clients pour chaque site. Si on a deux sites correspondant aux entrée DNS www.contoso.com et www.northwindtraders.com écoutant sur le même couple IP:Port, il est necessaire de valoriser le host header name de chaque site avec la valeur DNS associée (www.contoso.com ou www.northwindtraders.com) de manière à être sûr que le trafic est routé sur le bon site.
User Agent(cs(User-Agent)) : La chaîne d’identification du navigateur / client
Cookie (cs(Cookie)) : Le cookie reçu ou envoyé associé à la requête.
Referer(cs(Referer)) : La page où l’on a cliqué précédemment pour arriver à cette page.
#>

##Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
#2025-07-15 21:34:00 192.168.1.10 GET /index.html - 80 - 203.0.113.45 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 123


<#
{
  "ComputerName": null,
  "RunspaceId": "6f4dbdb6-f888-4c26-a7b4-3cfed08458ec",
  "EventIdentifier": 13,
  "Sender": {
    "AuthenticationSchemeSelectorDelegate": null,
    "ExtendedProtectionSelectorDelegate": null,
    "AuthenticationSchemes": 32768,
    "ExtendedProtectionPolicy": {
      "CustomServiceNames": null,
      "PolicyEnforcement": 0,
      "ProtectionScenario": 0,
      "CustomChannelBinding": null
    },
    "DefaultServiceNames": [
      "HTTP/localhost",
      "HTTP/FLO-LAP-109033.ubisoft.org"
    ],
    "Prefixes": [
      "http://localhost:6161/"
    ],
    "Realm": null,
    "IsListening": true,
    "IgnoreWriteExceptions": false,
    "UnsafeConnectionNtlmAuthentication": false,
    "TimeoutManager": {
      "EntityBody": {
        "Ticks": 0,
        "Days": 0,
        "Hours": 0,
        "Milliseconds": 0,
        "Microseconds": 0,
        "Nanoseconds": 0,
        "Minutes": 0,
        "Seconds": 0,
        "TotalDays": 0.0,
        "TotalHours": 0.0,
        "TotalMilliseconds": 0.0,
        "TotalMicroseconds": 0.0,
        "TotalNanoseconds": 0.0,
        "TotalMinutes": 0.0,
        "TotalSeconds": 0.0
      },
      "DrainEntityBody": {
        "Ticks": 0,
        "Days": 0,
        "Hours": 0,
        "Milliseconds": 0,
        "Microseconds": 0,
        "Nanoseconds": 0,
        "Minutes": 0,
        "Seconds": 0,
        "TotalDays": 0.0,
        "TotalHours": 0.0,
        "TotalMilliseconds": 0.0,
        "TotalMicroseconds": 0.0,
        "TotalNanoseconds": 0.0,
        "TotalMinutes": 0.0,
        "TotalSeconds": 0.0
      },
      "RequestQueue": {
        "Ticks": 0,
        "Days": 0,
        "Hours": 0,
        "Milliseconds": 0,
        "Microseconds": 0,
        "Nanoseconds": 0,
        "Minutes": 0,
        "Seconds": 0,
        "TotalDays": 0.0,
        "TotalHours": 0.0,
        "TotalMilliseconds": 0.0,
        "TotalMicroseconds": 0.0,
        "TotalNanoseconds": 0.0,
        "TotalMinutes": 0.0,
        "TotalSeconds": 0.0
      },
      "IdleConnection": {
        "Ticks": 0,
        "Days": 0,
        "Hours": 0,
        "Milliseconds": 0,
        "Microseconds": 0,
        "Nanoseconds": 0,
        "Minutes": 0,
        "Seconds": 0,
        "TotalDays": 0.0,
        "TotalHours": 0.0,
        "TotalMilliseconds": 0.0,
        "TotalMicroseconds": 0.0,
        "TotalNanoseconds": 0.0,
        "TotalMinutes": 0.0,
        "TotalSeconds": 0.0
      },
      "HeaderWait": {
        "Ticks": 0,
        "Days": 0,
        "Hours": 0,
        "Milliseconds": 0,
        "Microseconds": 0,
        "Nanoseconds": 0,
        "Minutes": 0,
        "Seconds": 0,
        "TotalDays": 0.0,
        "TotalHours": 0.0,
        "TotalMilliseconds": 0.0,
        "TotalMicroseconds": 0.0,
        "TotalNanoseconds": 0.0,
        "TotalMinutes": 0.0,
        "TotalSeconds": 0.0
      },
      "MinSendBytesPerSecond": 0
    }
  },
  "SourceEventArgs": null,
  "SourceArgs": [
    {
      "Request": {
        "AcceptTypes": null,
        "UserLanguages": null,
        "Cookies": [],
        "ContentEncoding": {
          "Preamble": null,
          "BodyName": "utf-8",
          "EncodingName": "Unicode (UTF-8)",
          "HeaderName": "utf-8",
          "WebName": "utf-8",
          "WindowsCodePage": 1200,
          "IsBrowserDisplay": true,
          "IsBrowserSave": true,
          "IsMailNewsDisplay": true,
          "IsMailNewsSave": true,
          "IsSingleByte": false,
          "EncoderFallback": {
            "DefaultString": "�",
            "MaxCharCount": 1
          },
          "DecoderFallback": {
            "DefaultString": "�",
            "MaxCharCount": 1
          },
          "IsReadOnly": true,
          "CodePage": 65001
        },
        "ContentType": null,
        "IsLocal": true,
        "IsWebSocketRequest": false,
        "KeepAlive": true,
        "QueryString": [],
        "RawUrl": "/",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; fr-FR) PowerShell/7.5.2",
        "UserHostAddress": "[::1]:6161",
        "UserHostName": "localhost:6161",
        "UrlReferrer": null,
        "Url": "http://localhost:6161/",
        "ProtocolVersion": {
          "Major": 1,
          "Minor": 1,
          "Build": -1,
          "Revision": -1,
          "MajorRevision": -1,
          "MinorRevision": -1
        },
        "ClientCertificateError": null,
        "RequestTraceIdentifier": "00000000-0000-0000-0400-0040080000ff",
        "ContentLength64": 0,
        "Headers": [
          "Accept-Encoding",
          "Host",
          "User-Agent"
        ],
        "HttpMethod": "GET",
        "InputStream": {
          "CanRead": true,
          "CanWrite": true,
          "CanSeek": true,
          "Length": 0,
          "Position": 0,
          "CanTimeout": false,
          "ReadTimeout": null,
          "WriteTimeout": null
        },
        "IsAuthenticated": false,
        "IsSecureConnection": false,
        "ServiceName": null,
        "TransportContext": {},
        "HasEntityBody": false,
        "RemoteEndPoint": {
          "AddressFamily": 23,
          "Address": {
            "AddressFamily": 23,
            "ScopeId": 0,
            "IsIPv6Multicast": false,
            "IsIPv6LinkLocal": false,
            "IsIPv6SiteLocal": false,
            "IsIPv6Teredo": false,
            "IsIPv6UniqueLocal": false,
            "IsIPv4MappedToIPv6": false,
            "Address": null
          },
          "Port": 51882
        },
        "LocalEndPoint": {
          "AddressFamily": 23,
          "Address": {
            "AddressFamily": 23,
            "ScopeId": 0,
            "IsIPv6Multicast": false,
            "IsIPv6LinkLocal": false,
            "IsIPv6SiteLocal": false,
            "IsIPv6Teredo": false,
            "IsIPv6UniqueLocal": false,
            "IsIPv4MappedToIPv6": false,
            "Address": null
          },
          "Port": 6161
        }
      },
      "User": null,
      "Response": {
        "Headers": [
          "Content-Length"
        ],
        "ContentEncoding": null,
        "ContentType": null,
        "SendChunked": false,
        "ContentLength64": 189,
        "Cookies": [],
        "KeepAlive": true,
        "OutputStream": null,
        "RedirectLocation": null,
        "StatusDescription": "OK",
        "StatusCode": 200,
        "ProtocolVersion": {
          "Major": 1,
          "Minor": 1,
          "Build": -1,
          "Revision": -1,
          "MajorRevision": -1,
          "MinorRevision": -1
        }
      }
    },
    {
      "AcceptTypes": null,
      "UserLanguages": null,
      "Cookies": [],
      "ContentEncoding": {
        "Preamble": null,
        "BodyName": "utf-8",
        "EncodingName": "Unicode (UTF-8)",
        "HeaderName": "utf-8",
        "WebName": "utf-8",
        "WindowsCodePage": 1200,
        "IsBrowserDisplay": true,
        "IsBrowserSave": true,
        "IsMailNewsDisplay": true,
        "IsMailNewsSave": true,
        "IsSingleByte": false,
        "EncoderFallback": {
          "DefaultString": "�",
          "MaxCharCount": 1
        },
        "DecoderFallback": {
          "DefaultString": "�",
          "MaxCharCount": 1
        },
        "IsReadOnly": true,
        "CodePage": 65001
      },
      "ContentType": null,
      "IsLocal": true,
      "IsWebSocketRequest": false,
      "KeepAlive": true,
      "QueryString": [],
      "RawUrl": "/",
      "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; fr-FR) PowerShell/7.5.2",
      "UserHostAddress": "[::1]:6161",
      "UserHostName": "localhost:6161",
      "UrlReferrer": null,
      "Url": "http://localhost:6161/",
      "ProtocolVersion": {
        "Major": 1,
        "Minor": 1,
        "Build": -1,
        "Revision": -1,
        "MajorRevision": -1,
        "MinorRevision": -1
      },
      "ClientCertificateError": null,
      "RequestTraceIdentifier": "00000000-0000-0000-0400-0040080000ff",
      "ContentLength64": 0,
      "Headers": [
        "Accept-Encoding",
        "Host",
        "User-Agent"
      ],
      "HttpMethod": "GET",
      "InputStream": {
        "CanRead": true,
        "CanWrite": true,
        "CanSeek": true,
        "Length": 0,
        "Position": 0,
        "CanTimeout": false,
        "ReadTimeout": null,
        "WriteTimeout": null
      },
      "IsAuthenticated": false,
      "IsSecureConnection": false,
      "ServiceName": null,
      "TransportContext": {},
      "HasEntityBody": false,
      "RemoteEndPoint": {
        "AddressFamily": 23,
        "Address": {
          "AddressFamily": 23,
          "ScopeId": 0,
          "IsIPv6Multicast": false,
          "IsIPv6LinkLocal": false,
          "IsIPv6SiteLocal": false,
          "IsIPv6Teredo": false,
          "IsIPv6UniqueLocal": false,
          "IsIPv4MappedToIPv6": false,
          "Address": null
        },
        "Port": 51882
      },
      "LocalEndPoint": {
        "AddressFamily": 23,
        "Address": {
          "AddressFamily": 23,
          "ScopeId": 0,
          "IsIPv6Multicast": false,
          "IsIPv6LinkLocal": false,
          "IsIPv6SiteLocal": false,
          "IsIPv6Teredo": false,
          "IsIPv6UniqueLocal": false,
          "IsIPv4MappedToIPv6": false,
          "Address": null
        },
        "Port": 6161
      }
    },
    {
      "Headers": [
        "Content-Length"
      ],
      "ContentEncoding": null,
      "ContentType": null,
      "SendChunked": false,
      "ContentLength64": 189,
      "Cookies": [],
      "KeepAlive": true,
      "OutputStream": null,
      "RedirectLocation": null,
      "StatusDescription": "OK",
      "StatusCode": 200,
      "ProtocolVersion": {
        "Major": 1,
        "Minor": 1,
        "Build": -1,
        "Revision": -1,
        "MajorRevision": -1,
        "MinorRevision": -1
      }
    }
  ],
  "SourceIdentifier": "http",
  "TimeGenerated": "2025-08-02T21:55:04.1930022+02:00",
  "MessageData": {
    "Url": "http://localhost:6161/",
    "Context": {
      "Request": {
        "AcceptTypes": null,
        "UserLanguages": null,
        "Cookies": [],
        "ContentEncoding": {
          "Preamble": null,
          "BodyName": "utf-8",
          "EncodingName": "Unicode (UTF-8)",
          "HeaderName": "utf-8",
          "WebName": "utf-8",
          "WindowsCodePage": 1200,
          "IsBrowserDisplay": true,
          "IsBrowserSave": true,
          "IsMailNewsDisplay": true,
          "IsMailNewsSave": true,
          "IsSingleByte": false,
          "EncoderFallback": {
            "DefaultString": "�",
            "MaxCharCount": 1
          },
          "DecoderFallback": {
            "DefaultString": "�",
            "MaxCharCount": 1
          },
          "IsReadOnly": true,
          "CodePage": 65001
        },
        "ContentType": null,
        "IsLocal": true,
        "IsWebSocketRequest": false,
        "KeepAlive": true,
        "QueryString": [],
        "RawUrl": "/",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; fr-FR) PowerShell/7.5.2",
        "UserHostAddress": "[::1]:6161",
        "UserHostName": "localhost:6161",
        "UrlReferrer": null,
        "Url": "http://localhost:6161/",
        "ProtocolVersion": {
          "Major": 1,
          "Minor": 1,
          "Build": -1,
          "Revision": -1,
          "MajorRevision": -1,
          "MinorRevision": -1
        },
        "ClientCertificateError": null,
        "RequestTraceIdentifier": "00000000-0000-0000-0400-0040080000ff",
        "ContentLength64": 0,
        "Headers": [
          "Accept-Encoding",
          "Host",
          "User-Agent"
        ],
        "HttpMethod": "GET",
        "InputStream": {
          "CanRead": true,
          "CanWrite": true,
          "CanSeek": true,
          "Length": 0,
          "Position": 0,
          "CanTimeout": false,
          "ReadTimeout": null,
          "WriteTimeout": null
        },
        "IsAuthenticated": false,
        "IsSecureConnection": false,
        "ServiceName": null,
        "TransportContext": {},
        "HasEntityBody": false,
        "RemoteEndPoint": {
          "AddressFamily": 23,
          "Address": {
            "AddressFamily": 23,
            "ScopeId": 0,
            "IsIPv6Multicast": false,
            "IsIPv6LinkLocal": false,
            "IsIPv6SiteLocal": false,
            "IsIPv6Teredo": false,
            "IsIPv6UniqueLocal": false,
            "IsIPv4MappedToIPv6": false,
            "Address": null
          },
          "Port": 51882
        },
        "LocalEndPoint": {
          "AddressFamily": 23,
          "Address": {
            "AddressFamily": 23,
            "ScopeId": 0,
            "IsIPv6Multicast": false,
            "IsIPv6LinkLocal": false,
            "IsIPv6SiteLocal": false,
            "IsIPv6Teredo": false,
            "IsIPv6UniqueLocal": false,
            "IsIPv4MappedToIPv6": false,
            "Address": null
          },
          "Port": 6161
        }
      },
      "User": null,
      "Response": {
        "Headers": [
          "Content-Length"
        ],
        "ContentEncoding": null,
        "ContentType": null,
        "SendChunked": false,
        "ContentLength64": 189,
        "Cookies": [],
        "KeepAlive": true,
        "OutputStream": null,
        "RedirectLocation": null,
        "StatusDescription": "OK",
        "StatusCode": 200,
        "ProtocolVersion": {
          "Major": 1,
          "Minor": 1,
          "Build": -1,
          "Revision": -1,
          "MajorRevision": -1,
          "MinorRevision": -1
        }
      }
    },
    "Request": {
      "AcceptTypes": null,
      "UserLanguages": null,
      "Cookies": [],
      "ContentEncoding": {
        "Preamble": null,
        "BodyName": "utf-8",
        "EncodingName": "Unicode (UTF-8)",
        "HeaderName": "utf-8",
        "WebName": "utf-8",
        "WindowsCodePage": 1200,
        "IsBrowserDisplay": true,
        "IsBrowserSave": true,
        "IsMailNewsDisplay": true,
        "IsMailNewsSave": true,
        "IsSingleByte": false,
        "EncoderFallback": {
          "DefaultString": "�",
          "MaxCharCount": 1
        },
        "DecoderFallback": {
          "DefaultString": "�",
          "MaxCharCount": 1
        },
        "IsReadOnly": true,
        "CodePage": 65001
      },
      "ContentType": null,
      "IsLocal": true,
      "IsWebSocketRequest": false,
      "KeepAlive": true,
      "QueryString": [],
      "RawUrl": "/",
      "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; fr-FR) PowerShell/7.5.2",
      "UserHostAddress": "[::1]:6161",
      "UserHostName": "localhost:6161",
      "UrlReferrer": null,
      "Url": "http://localhost:6161/",
      "ProtocolVersion": {
        "Major": 1,
        "Minor": 1,
        "Build": -1,
        "Revision": -1,
        "MajorRevision": -1,
        "MinorRevision": -1
      },
      "ClientCertificateError": null,
      "RequestTraceIdentifier": "00000000-0000-0000-0400-0040080000ff",
      "ContentLength64": 0,
      "Headers": [
        "Accept-Encoding",
        "Host",
        "User-Agent"
      ],
      "HttpMethod": "GET",
      "InputStream": {
        "CanRead": true,
        "CanWrite": true,
        "CanSeek": true,
        "Length": 0,
        "Position": 0,
        "CanTimeout": false,
        "ReadTimeout": null,
        "WriteTimeout": null
      },
      "IsAuthenticated": false,
      "IsSecureConnection": false,
      "ServiceName": null,
      "TransportContext": {},
      "HasEntityBody": false,
      "RemoteEndPoint": {
        "AddressFamily": 23,
        "Address": {
          "AddressFamily": 23,
          "ScopeId": 0,
          "IsIPv6Multicast": false,
          "IsIPv6LinkLocal": false,
          "IsIPv6SiteLocal": false,
          "IsIPv6Teredo": false,
          "IsIPv6UniqueLocal": false,
          "IsIPv4MappedToIPv6": false,
          "Address": null
        },
        "Port": 51882
      },
      "LocalEndPoint": {
        "AddressFamily": 23,
        "Address": {
          "AddressFamily": 23,
          "ScopeId": 0,
          "IsIPv6Multicast": false,
          "IsIPv6LinkLocal": false,
          "IsIPv6SiteLocal": false,
          "IsIPv6Teredo": false,
          "IsIPv6UniqueLocal": false,
          "IsIPv4MappedToIPv6": false,
          "Address": null
        },
        "Port": 6161
      }
    },
    "Response": {
      "Headers": [
        "Content-Length"
      ],
      "ContentEncoding": null,
      "ContentType": null,
      "SendChunked": false,
      "ContentLength64": 189,
      "Cookies": [],
      "KeepAlive": true,
      "OutputStream": null,
      "RedirectLocation": null,
      "StatusDescription": "OK",
      "StatusCode": 200,
      "ProtocolVersion": {
        "Major": 1,
        "Minor": 1,
        "Build": -1,
        "Revision": -1,
        "MajorRevision": -1,
        "MinorRevision": -1
      }
    }
  }
}
#>