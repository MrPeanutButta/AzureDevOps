Import-Module $PSScriptRoot/Retry.psm1 -Force
Import-Module Az.Accounts

@{
    # Define the module manifest
    ModuleName = "AzureDevOps"
    RootModule = "$ModuleName.psm1"
    ModuleVersion = "1.0.0"
    Author = "aaron.hebert@agilecloud.ai"
    Description = "A PowerShell module that wraps the Azure DevOps REST API."
    PowerShellVersion = "7.4.0"
    RequiredModules = @("Retry.psm1, Az.Accounts")
    FunctionsToExport = @(
        "Get-AdoSecurityAlertInstances",
        "Get-AdoSecurityAlerts",
        "Get-AdoRepoCloneUrl",
        "Get-AdoEntitySet",
        "Get-AdoProjectRepositories",
        "Get-AdoOrganization",
        "Get-AdoServiceHealth",
        "Get-AdoPipelines",
        "Get-AdoProfile",
        "Get-AdoProjects",
        "Set-AdoOrganization",
        "Connect-AdoAccount"
    )
}

$AdoContext = @{
    Services = @{
        Pipelines = "Pipelines"
        Boards = "Boards"
        Repos = "Repos"
        Artifacts = "Artifacts"
        TestPlans = "Test Plans"
        Analytics = "Core services"
        OtherServices = "Other services"
        AdvancedSecurity = "Advanced Security"
    }

    Geographies = @{
        US = "US"
        EU = "EU"
        AU = "AU"
        IN = "IN"
        APAC = "APAC"
        BR = "BR"
        CA = "CA"
    }

    Api = @{
        ApiVersion = "api-version=7.1-preview.3"
        BaseUrl = "https://dev.azure.com"
        StatusUrl = "https://status.dev.azure.com/_apis/status/health"
        AccountsUrl = "https://app.vssps.visualstudio.com/_apis/accounts" 
        ProfilesUrl = "https://app.vssps.visualstudio.com/_apis/profile/profiles"
        ArtifactsUrl = "https://feeds.dev.azure.com"
        AnalyticsUrl = "https://analytics.dev.azure.com"
        AdvancedSecurityUrl = "https://advsec.dev.azure.com"
        Geopragphy = ""
        PersonalAccessToken = ""
        OrganizationName = ""
        TenantId = ""
        Headers = @{
            ContentType = "application/json"
            Authorization = ""
        }  
    }

    Analytics = @{
        ParallelPipelineJobs = "ParallelPipelineJobsSnapshot"
        PipelineJobs = "PipelineJobs"
        PipelineRuns = "PipelineRuns"
        PipelineRunActivityResults = "PipelineRunActivityResults"
        Pipelines = "Pipelines"
        Branches = "Branches"
        PipelineTasks = "PipelineTasks"

        Areas = "Areas"
        Dates = "Dates"
        Iterations = "Iterations"
        BoardLocations = "BoardLocations"
        Processes = "Processes"
        Projects = "Projects"
        Tags = "Tags"
        Teams = "Teams"
        Users = "Users"
        WorkItemBoardSnapshot = "WorkItemBoardSnapshot"
        WorkItemLinks = "WorkItemLinks"
        WorkItemRevisions = "WorkItemRevisions"
        WorkItems = "WorkItems"
        WorkItemSnapshot = "WorkItemSnapshot"
        WorkItemTypeFields = "WorkItemTypeFields"
    }

    Boards = @{
        ProcessTemplate = @{
            Scrum = @{
                op = "add"
                path = "/fields/System.ProcessTemplateType"
                value = "Scrum"
            }
            Agile = @{
                op = "add"
                path = "/fields/System.ProcessTemplateType"
                value = "Agile"
            }
            Basic = @{
                op = "add"
                path = "/fields/System.ProcessTemplateType"
                value = "Basic"
            }
            CMMI = @{
                op = "add"
                path = "/fields/System.ProcessTemplateType"
                value = "CMMI"
            }
        }
        WorkItemType = @{
            UserStory = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.UserStory"
            }
            Epic = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Epic"
            }
            Risk = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Risk"
            }
            Bug = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Bug"
            }
            Task = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Task"
            }
            ChangeRequest = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.ChangeRequest"
            }
            Feature = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Feature"
            }
            Issue = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Issue"
            }
            Impediment = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Impediment"
            }
            ProductBacklogItem = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.ProductBacklogItem"
            }
            Requirement = @{
                op = "add"
                path = "/fields/System.WorkItemType"
                value = "Microsoft.VSTS.WorkItemTypes.Requirement"
            }
        }
    }

    Profile = $null
}

function Connect-AdoAccount 
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$OrganizationName,
        [Parameter(Mandatory = $false)]
        [string]$PersonalAccessToken = $($(Get-AzAccessToken).Token),
        [Parameter(Mandatory = $false)]
        [ValidateScript(
            {
                $_ -in $AdoContext.Geographies.Values
            }
        )]
        [string]$Geography = $AdoContext.Geographies.US,
        [Parameter(Mandatory = $false)]
        [string]$TenantId = $(Get-AzContext).Tenant.Id
    )

    $AdoContext.Api.PersonalAccessToken = $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($(":$PersonalAccessToken"))))

    $AdoContext.Api.Headers = @{Authorization=("Basic {0}" -f $AdoContext.Api.PersonalAccessToken)}
    $AdoContext.Api.OrganizationName = $OrganizationName
    $AdoContext.Api.TenantId = $TenantId
    $AdoContext.Api.Geography = $Geography

    $uri = "$($AdoContext.Api.ProfilesUrl)/me"
    $AdoContext.Profile = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)

    $uri = "$($AdoContext.Api.StatusUrl)"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).status
}

function Set-AdoTenantId
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $AdoContext.Api.TenantId = $TenantId
    Set-AzContext -TenantId $TenantId -
}

function Set-AdoOrganization
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$OrganizationName
    )

    $AdoContext.Api.OrganizationName = $OrganizationName
}

# Define the module functions
function Get-AdoProjects
{
    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/projects?$($AdoContext.Api.ApiVersion)"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
}

function Get-AdoProject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectIdOrName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/projects/$($ProjectIdOrName)?$($AdoContext.Api.ApiVersion)"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
}

function Get-AdoProjectProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$Project
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/projects/$($Project.id)/properties"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoProfile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [guid]$MemberId,
        [string]$CoreAttributes = "AvatarUrl,DisplayName,EmailAddress,Descriptor,Id,IsContainer,ProviderDisplayName,SubjectDescriptor",
        [Parameter(Mandatory = $false)]
        [bool]$Details = $false,
        [Parameter(Mandatory = $false)]
        [string]$Partiion = "me"
    )

    $uri = "$($AdoContext.Api.ProfilesUrl)/$($MemberId)?&details=$($Details)&coreAttributes=$($CoreAttributes)&partition=$($Partiion)"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
}

function Get-AdoPipelines
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/pipelines"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
}

function Get-AdoServiceHealth
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateScript(
            {
                $_ -in $AdoContext.Geographies.Values
            }
        )]
        [object]$Geographies = $($AdoContext.Geographies.GetEnumerator() | % { $_.Value }) -join ",",
        
        [Parameter(Mandatory = $false)]
        [ValidateScript(
            {
                $_ -in $AdoContext.Services.Values
            }
        )]        
        [object]$Services = $($AdoContext.Services.GetEnumerator() | % { $_.Value }) -join ","
    )

    $uri = "$($AdoContext.Api.StatusUrl)?&services=$($Services -join ",")&geographies=$($Geographies -join ",")"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
}

function Get-AdoOrganization
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$OwnerId = $AdoContext.Profile.id,
        [Parameter(Mandatory = $false)]
        [string]$MemberId = $AdoContext.Profile.id,
        [Parameter(Mandatory = $false)]
        [string]$Properties = $AdoContext.Profile.coreAttributes
    )

    $AdoContext.Profile.coreAttributes
    $uri = "$($AdoContext.Api.AccountsUrl)?&ownerId=$($OwnerId)&memberId=$($MemberId)&properties=$($Properties)"

    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
}

function Get-AdoProjectRepositories
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/git/repositories"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)

    return $response.value
}

function Get-AdoProjectProcessConfiguration
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Project
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($Project.name)/_apis/work/processconfiguration"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
    return $response
}

function Get-AdoProjectWorkItemTypes
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Project
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($Project.name)/_apis/wit/workitemtypes"

    $response = $($(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers) | ConvertFrom-Json -AsHashtable)["value"]
    return $response
}

function Get-AdoWorkItemProcess
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [guid]$ProcessTypeId
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/work/processes/$($ProcessTypeId)"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
    return $response
}

function Get-AdoWorkItemProcesses
{
    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/work/processes"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoWorkItemTypes
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [guid]$ProcessTypeId
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/work/processes/$($ProcessTypeId)/workitemtypes"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoWorkItemFields
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [guid]$ProcessTypeId,
        [Parameter(Mandatory = $true)]
        [string]$WorkItemTypeName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/work/processes/$($ProcessTypeId)/workItemTypes/$($WorkItemTypeName)/fields"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoEntitySet
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [Parameter(Mandatory = $true)]
        [ValidateScript(
            {
                $_ -in $AdoContext.Analytics.Values
            }
        )]
        [object]$EntitySetName
    )

    $uri = "$($AdoContext.Api.AnalyticsUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_odata/v4.0-preview/$($EntitySetName)"
    return $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
}

function Get-AdoRepoCloneUrl
{
    param (
        [Parameter(Mandatory = $true)]
        [object]$Repository
    )
    
    $url = $Repository.remoteUrl.Replace($AdoContext.Api.OrganizationName + "@", $($(Get-AzAccessToken).Token) + "@")

    return $url
}

function Get-AdoSecurityAlerts
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$Repository
    )

    $uri = "$($AdoContext.Api.AdvancedSecurityUrl)/$($AdoContext.Api.OrganizationName)/$($Repository.project.name)/_apis/alert/repositories/$($Repository.name)/alerts?api-version=7.2-preview.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoSecurityAlertInstances
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$Repository,
        [Parameter(Mandatory = $true)]
        [object]$Alert
    )

    $uri = "$($AdoContext.Api.AdvancedSecurityUrl)/$($AdoContext.Api.OrganizationName)/$($Repository.project.name)/_apis/alert/repositories/$($Repository.name)/alerts/$($Alert.alertId)/instances?api-version=7.2-preview.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

# todo: finish
function New-AdoAlertToRiskItem
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Repository,
        [Parameter(Mandatory = $true)]
        [object]$Alert,
        [Parameter(Mandatory = $false)]
        [object]$Fields = @{}
    )

    $Severity = @{
        Critical = '1'
        High = '2'
        Medium = '3'
        Low = '4'
    }

    $riskFields = @(     
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.Common.Severity"
            value = $Severity[$Alert.severity] + " - $($Alert.severity[0].ToString().ToUpper() + $Alert.severity.Substring(1))"
        },
        @{
            op = "add"
            path = "/fields/System.State"
            value = "Proposed"
        }, 
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.CMMI.MitigationPlan"
            value = $($Alert.tools.rules.helpMessage | Convertfrom-markdown).Html
        }, 
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.CMMI.Probability"
            value = (1/[int]::Parse($Severity[$Alert.severity])) * 100
        }
    )
    
    if($Fields.Count -gt 0)
    {
        foreach($item in $Fields)
        {
            $riskFields += $item
        }
    }

    return New-AdoWorkItem -Project $Repository.project -Title $Alert.title -Description $Alert.tools.rules.description -WorkItemTypeName Risk -Fields $riskFields
}

function Get-AzureComplianceTrigger
{

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Alert
    )

    return $($Alert | Select-Object -Property complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup, resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName)
}

function New-AzureAlertToRiskItem
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Repository,
        [Parameter(Mandatory = $true)]
        [object]$Alert,
        [Parameter(Mandatory = $false)]
        [object]$Fields = @{}
    )

    $Severity = @{
        Critical = '1'
        High = '2'
        Medium = '3'
        Low = '4'
    }

    $riskFields = @(     
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.Common.Severity"
            value = $Severity[$Alert.severity] + " - $($Alert.severity[0].ToString().ToUpper() + $Alert.severity.Substring(1))"
        },
        @{
            op = "add"
            path = "/fields/System.State"
            value = "Proposed"
        }, 
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.CMMI.MitigationPlan"
            value = $($Alert.remediationSteps)
        }, 
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.CMMI.Probability"
            value = (1/[int]::Parse($Severity[$Alert.severity])) * 100
        },
        @{
            op = "add"
            path = "/fields/Microsoft.VSTS.CMMI.MitigationTriggers"
            value = "<pre>" + $(Get-AzureComplianceTrigger -Alert $Alert | Out-String) + "</pre>"
        }
    )
    
    if($Fields.Count -gt 0)
    {
        foreach($item in $Fields)
        {
            $riskFields += $item
        }
    }

    return New-AdoWorkItem -Project $Repository.project -Title $Alert.controlName -Description $Alert.description -WorkItemTypeName Risk -Fields $riskFields
}

function New-AdoWorkItem
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Project,
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [ValidateScript(
            {
                $processWorkTemTypes = $(Get-AdoProjectWorkItemTypes -Project $project) | % { $_.name }
                $_ -in $processWorkTemTypes
            }
        , ErrorMessage = "Work item type parameter value is not supported for the projects current item tracking process.")]
        [string]$WorkItemTypeName,
        [Parameter(Mandatory = $false)]
        [object]$Fields = @{}
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($Project.name)/_apis/wit/workitems/`$$($WorkItemTypeName)?api-version=7.1-preview.3"

    $body = @(
        @{
            op = "add"
            path = "/fields/System.Title"
            value = $Title
        },
        @{
            op = "add"
            path = "/fields/System.Description"
            value = $Description
        },
        $AdoContext.Boards.WorkItemType[$WorkItemTypeName]
    )

    if($Fields.Count -gt 0)
    {
        foreach($item in $Fields)
        {
            $body += $item
        }
    }

    $body = $body | ConvertTo-Json -Depth 3

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers -ContentType "application/json-patch+json" -Body $body -Method POST)    
    return $response
}

function Get-AdoIteration
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Project,
        [Parameter(Mandatory = $true)]
        [guid]$TeamId
    )        
    
    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($Project.name)/$($TeamId)/_apis/work/teamsettings/iterations?api-version=5.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoTeam
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Project,
        [Parameter(Mandatory = $true)]
        [string]$TeamName
    )

        $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/projects/$($Project.name)/teams?api-version=7.1-preview.3"

        $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
 
        return $response
}

function Get-AdoIterationWorkItems
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Project,
        [Parameter(Mandatory = $true)]
        [guid]$TeamId,
        [Parameter(Mandatory = $true)]
        [guid]$IterationId
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($Project.name)/$($TeamId)/_apis/work/teamsettings/iterations/$($IterationId)/workitems?api-version=7.1-preview.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers)
    return $response
}

function Get-AdoEnvironments()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/pipelines/environments?api-version=7.2-preview.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value
    return $response
}

function Get-AdoEnvironment()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName
    )

    $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/pipelines/environments?name=$($EnvironmentName)&api-version=7.2-preview.1"

    $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers).value

    return $response
}

function New-AdoEnvironment([string]$EnvironmentName, [string]$ProjectName, [string]$Description)
{
  $body = @"
  {"description":"$($Description)","name":"$($EnvironmentName)"}
"@ | ConvertFrom-Json

  $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/distributedtask/environments?api-version=7.1-preview.1"

  $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5) -Method POST)

  return $response
}

function New-AdoAksEnvironmentResource([string] $projectName, [string] $adoEnvironmentName, [string] $aksServerUrl, [string] $namespace, [object] $certificate)
{
  $body = @"
  {
    "data": {
      "authorizationType": "ServiceAccount",
      "acceptUntrustedCerts": true
    },
    "name": "",
    "type": "kubernetes",
    "url": "",
    "authorization": {
      "scheme": "Token",
      "parameters": {
        "apiToken": "",
        "serviceAccountCertificate": "",
        "isCreatedFromSecretYaml": false
      }
    },
    "serviceEndpointProjectReferences": [
      {
        "name": "",
        "projectReference": {
          "id": "",
          "name": ""
        }
      }
    ]
  }
"@ | ConvertFrom-Json

  $serviceConnectionName = "$($adoEnvironmentName)-$namespace-$(Get-Random -Maximum 1000000)"
  $environment = Get-AdoEnvironment -ProjectName $projectName -EnvironmentName $adoEnvironmentName

  if ($null -eq $environment)
  {
    $environment = New-AdoEnvironment -EnvironmentName $adoEnvironmentName -ProjectName $projectName -Description "Auto-created environment for $adoEnvironmentName."
  }

  $body.name = "$serviceConnectionName"
  $body.url = $aksServerUrl
  $body.authorization.parameters.apiToken = $certificate.data.token
  $body.authorization.parameters.serviceAccountCertificate = $certificate.data."ca.crt"
  $body.serviceEndpointProjectReferences[0].name = "$serviceConnectionName"
  $body.serviceEndpointProjectReferences[0].projectReference.id = $environment.project.id

  $serviceEndpointUri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"

  $response = $(Invoke-RestMethodWithRetry -Uri $serviceEndpointUri -Headers $AdoContext.Api.Headers -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5) -Method POST)

  $body = @"
  {
    "name": "",
    "namespace": "",
    "clusterName": "",
    "serviceEndpointId": ""
  }
"@ | ConvertFrom-Json

  $body.name = "$namespace"
  $body.namespace = "$namespace"
  $body.clusterName = "$adoEnvironmentName"
  $body.serviceEndpointId = $response.id

  $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($projectName)/_apis/pipelines/environments/$($environment.id)/providers/kubernetes?api-version=7.2-preview.2"

  $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5) -Method POST)

  return $response
}

function Trigger-AdoPipeline([string]$ProjectName, [int]$PipelineId, [string]$BranchName, [object]$Parameters)
{
  $params = $($Parameters | ConvertTo-Json -Depth 5)
  $body = @"
  {
    "stagesToSkip": [],
    "resources": {
      "repositories": {
        "self": {
          "refName": "refs/heads/$BranchName"
        }
      }
    },
    "templateParameters": $params,
    "variables": {}
  }
"@ | ConvertFrom-Json -Depth 5

  $uri = "$($AdoContext.Api.BaseUrl)/$($AdoContext.Api.OrganizationName)/$($ProjectName)/_apis/pipelines/$PipelineId/runs?api-version=5.1-preview.1"

  Write-Host $uri

  $response = $(Invoke-RestMethodWithRetry -Uri $uri -Headers $AdoContext.Api.Headers -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5) -Method POST)

  return $response
}

function New-ServiceConnection()
{
}