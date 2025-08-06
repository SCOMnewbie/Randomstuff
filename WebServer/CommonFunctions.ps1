# Return a 404
function NotFound {
    param($Event, $RequestLogFilePath)
    $Event.MessageData.Response.StatusCode = 404
    Write-RequestLog -Event $Event -LogFilePath $RequestLogFilePath
    $Event.MessageData.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

# Return a 403 (I know who you are but not allowed)
function Forbidden {
    param($Event, $RequestLogFilePath)
    $Event.MessageData.Response.StatusCode  = 403
    Write-RequestLog -Event $Event -LogFilePath $RequestLogFilePath
    $Event.MessageData.Response.Close()
    # Remove unwanted events
    $Event | Remove-Event
    break
}

# Return a 401 (I don't know you get out)
function Unauthorized {
    param($Event, $RequestLogFilePath)
    $Event.MessageData.Response.StatusCode  = 401
    Write-RequestLog -Event $Event -LogFilePath $RequestLogFilePath
    $Event.MessageData.Response.Close()
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
        $Event,
        [Parameter()]
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$HostColor = 'Magenta'
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
                    "date,time,s-ip,cs-method,cs-uri-stem,cs-uri-query,s-port,cs(User-Agent),sc-status" | Out-File -FilePath $LogFilePath -Force -Encoding utf8
                }

                $LogEntry = "{0},{1},{2},{3},{4},{5},{6},{7},{8}" -f $(get-date -Format yyyy-MM-dd),$(get-date -Format HH:mm:ss),$Event.MessageData.Request.UserHostAddress,$Event.MessageData.Request.HttpMethod,$Event.MessageData.Request.RawUrl,$($Event.MessageData.Request.Url.Query.ToString().replace('?','')),$Event.MessageData.Request.LocalEndPoint.port,$Event.MessageData.Request.UserAgent,$Event.MessageData.Response.StatusCode

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


