[CmdletBinding()]
param(
    [string[]]$ListenerPrefix = @('http://localhost:6161/')
)

# If we're running in a container and the listener prefix is not http://*:80/,
if ($env:IN_CONTAINER -and $listenerPrefix -ne 'http://*:80/') {
    # then set the listener prefix to http://*:80/ (listen to all incoming requests on port 80).
    $listenerPrefix = 'http://*:80/'
}

Write-verbose "listenerPrefix: $listenerPrefix"

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

if($global:HttpListener.Prefixes -gt 1){
    $Jobname = $global:HttpListener.Prefixes[0]
}
else{
    $Jobname = $global:HttpListener.Prefixes
}

# Start the listener.
try { $Httplistener.Start() }
# If the listener cannot start, write a warning and return.
catch { Write-Warning "Could not start listener: $_" ;return }

Write-verbose "Jobname: $Jobname"
Write-verbose "HttpListener: $HttpListener"

# The ServerJob will start the HttpListener and listen for incoming requests.
$script:ServerJob = Start-ThreadJob -ScriptBlock{
    param($MainRunspace, $Httplistener, $SourceIdentifier = 'http')
    while($Httplistener.IsListening){
        $ContextAsync = $Httplistener.GetContextAsync()
        while(-not $ContextAsync.IsCompleted -or $ContextAsync.IsFaulted -or $ContextAsync.IsCanceled){}
        if($ContextAsync.IsFaulted){
            Write-Error -Exception $ContextAsync.Exception -Category ProtocolError
            continue
        }
        $Context = $(try {$ContextAsync.Result}catch{$_})

        $Url = $Context.Request.Url
        #Executed outside the debugger
        if($Url -match '/favicon.ico$'){
            $Context.Response.StatusCode = 404
            $Context.Response.Close()
            continue
        }
        $MainRunspace.Events.GenerateEvent(
            $SourceIdentifier, $Httplistener, @($Context,$Context.Request,$Context.Response),
            [ordered]@{Url = $Context.Request.Url;Context = $Context; Request = $Context.Request; Response = $Context.Response}
        )
    }
} -Name $Jobname -ArgumentList ([runspace]::DefaultRunspace, $Httplistener) -ThrottleLimit 100 | 
Add-Member -NotePropertyMembers ([Ordered]@{HttpListener = $Httplistener}) -PassThru

Write-host "Now serving $Jobname" -ForegroundColor Green

# If PowerShell is exiting, close the HttpListener.
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    $global:Httplistener.Close()
}

# Keep track of the creation time of the DiceServerJob.
$ServerJob | Add-Member -MemberType NoteProperty Created -Value ([DateTime]::now) -Force

$Rng = [System.Random]::new()

while($Httplistener.IsListening){
    foreach($Event in @(Get-Event HTTP*)){
        $Context,$Request,$Response = $Event.SourceArgs
        #If not processed, let's keep it into the buffer
        if(-not $Response.OutputStream){continue}

        $Response.Close($OutputEncoding.GetBytes("$($Rng.Next())"),$false)
        Write-host "Responded to $($Request.Url) in $([datetime]::Now - $Event.TimeGenerated)" -ForegroundColor Cyan
        $Event | Remove-Event
    }
}