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

function Write-RequestLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilePath,
        $Context,
        [Parameter()]
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$HostColor = 'White'
    )

    begin {
        $mutexName = "Global\Request" + ($LogFilePath -replace '[\\/:]', '_')
        $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    }

    process {
        if ($mutex.WaitOne(10000)) {
            try {

                $logDir = Split-Path $LogFilePath
                if (!(Test-Path $logDir)) {
                    Write-Verbose "Folder doesn't exist, let's create it"
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }

                if (!(Test-Path $LogFilePath)) {
                    #File does not exist, create header
                    Write-Verbose "File doesn't exist, let's create it with header"
                    "##Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken" | Out-File -FilePath $LogFilePath -Force -Encoding utf8
                }

                ##Fields: date,time,s-ip,cs-method,cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
                $LogEntry = "{0},{1},{2},{3},{4}" -f $(get-date -Format yyyy-MM-dd),$(get-date -Format HH:mm:ss),$context.Request.UserHostAddress,$context.Request.HttpMethod,$Context.Request.RawUrl

                Add-Content -Path $LogFilePath -Value $LogEntry
                Write-Host $logEntry -ForegroundColor $HostColor
            }
            finally {
                $mutex.ReleaseMutex()
            }
        }
        else {
            Write-Warning "Could not acquire mutex for $LogFilePath. Log message was skipped."
        }
    }

    end {
        $mutex.Dispose()
    }
}

function Write-BackendLog {
    <#
        This function is used to log stuff on the console and on disk. This logfile focus on backend logs.
        Write-BackendLog -LogFilePath $BackendFilePath -LogLevel ERROR -HostColor Red -Message "This is an impoertant error"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilePath,
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$LogLevel = "INFO",
        [Parameter()]
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$HostColor = 'White',
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    begin {
        $mutexName = "Global\Backend" + ($LogFilePath -replace '[\\/:]', '_')
        $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    }

    process {
        if ($mutex.WaitOne(10000)) {
            try {

                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logEntry = "$timestamp [$LogLevel] - $Message"

                $logDir = Split-Path $LogFilePath
                if (!(Test-Path $logDir)) {
                    Write-Verbose "Folder doesn't exist, let's create it"
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }

                Add-Content -Path $LogFilePath -Value $LogEntry
                Write-Host $logEntry -ForegroundColor $HostColor
            }
            finally {
                $mutex.ReleaseMutex()
            }
        }
        else {
            Write-Warning "Could not acquire mutex for $LogFilePath. Log message was skipped."
        }
    }

    end {
        $mutex.Dispose()
    }
}


