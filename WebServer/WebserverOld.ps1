$JobName = "http://localhost:$(Get-Random -Minimum 4200 -Maximum 42000)/"
$Httplistener = [Net.Httplistener]::new()
$Httplistener.Prefixes.Add($JobName)
$Httplistener.Start()

Start-ThreadJob -ScriptBlock{
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
} -Name $JobName -ArgumentList ([runspace]::DefaultRunspace, $Httplistener) -ThrottleLimit 100 | 
Add-Member -NotePropertyMembers ([Ordered]@{HttpListener = $Httplistener}) -PassThru

Write-host "Now serving $Jobname" -ForegroundColor Green

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