# Define the module manifest
@{
    ModuleName = "Retry"
    RootModule = "$ModuleName.psm1"
    ModuleVersion = "1.0.0"
    Author = "aaron.hebert@agilecloud.ai"
    Description = "A PowerShell module that implements retry logic for transient failures."
    PowerShellVersion = "5.1"
    FunctionsToExport = @("Invoke-Retry", "Invoke-RestMethodWithRetry")
}

function Invoke-Retry 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)]
        [int]$DelaySeconds = 5
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) 
    {
        try 
        {
            return Invoke-Command $ScriptBlock
        } 
        catch [System.Net.WebException], [System.Net.Sockets.SocketException], [System.IO.IOException]
        {
            $retryCount++
            $delaySeconds = [Math]::Pow(2, $retryCount) * $DelaySeconds
            Write-Warning "WebException encountered. ${$_.Status.ToString()}. Attempt ${retryCount}"
            Write-Warning "Message: ${$_.Message}"
            Write-Warning "Retrying in ${delaySeconds} seconds..."
            Start-Sleep -Seconds $delaySeconds
        }
    }

    throw "Max retries exceeded."
}

function Invoke-RestMethodWithRetry 
{
    param 
    (
        [System.Uri]$Uri,
        [string]$Method = "GET",
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [string]$Body = $null,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json"
    )
    
    return Invoke-Retry -ScriptBlock {

        if($null -eq $Body)
        {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ContentType $ContentType
        }
        else
        {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ContentType $ContentType -Body $Body
        }

        return $response
    }
}