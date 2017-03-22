#   ===========================================
#   IIS-Deploy script using Powershell DSC
#   ============================================
#
#   Copyright (c) Petr Altman
#
#   Project website:
#   https://github.com/altick/iis-deploy
#

Param(
  [Parameter(Mandatory=$True, Position=0)]
  [string]$projectId,
  [Parameter(Mandatory=$True, Position=1)]
  [string]$profileId,
  [Parameter(Mandatory=$True, Position=2)]
  [string]$buildId
)

#
#   Constants
#
$targetNode = $env:computername
$archivePath = "C:\Drop\$projectId\$profileId\$buildId.zip"
$buildPath = "$PSScriptRoot\build\$projectId\$profileId\$buildId"
$configOutputPath = $PSScriptRoot
$dscConfigName = "IISDeploy-$projectId-$profileId"
$appBuildPath = "$buildPath"


#
#   Helpers
#

function Get-ProjectConfig() {
    return ConvertFrom-json -InputObject $(Get-Content -Path $appBuildPath\iis-deploy.json -raw)
}

function StartDscConfig($configName, [System.Collections.Hashtable]$configData) {    
    write-host ""
    write-host "* Starting DSC: $configName"    
    write-host "==================================="  
    
    $outputPath = "$configOutputPath\$configName"

    if(Test-path $outputPath) {
        rm $outputPath -Recurse -Force
    }
    & $configName -OutputPath $outputPath -ConfigurationData $configData

    try {
        Start-DscConfiguration $outputPath -wait -Verbose -force -ErrorAction Stop # -Debug
    } catch {
        write-host "DSC config error:" -BackgroundColor Red -ForegroundColor White
        write-error "$($_.Exception.Message)"
    }
}


#
#   Prepare Build Files
# 
write-host "Cleaning build directory"
Remove-Item $buildPath -Recurse -Force -ErrorAction SilentlyContinue
new-Item $buildPath -ItemType Directory -Force
write-host "Extracting build archive, id: $buildId"
Expand-Archive -Path $archivePath -DestinationPath $buildPath -Force


#
#   Read deploy.json file
#
write-host "Reading deploy.json file"
$project = Get-ProjectConfig
write-host "Getting profile $profileId"
$profile = $project.$profileId

#
#   Initialization
#
$decodedUserPassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($($profile.appUserPassword)))
$appUserSecPswd = (ConvertTo-SecureString $decodedUserPassword -asplaintext -force)
$appUserCred = (New-Object System.Management.Automation.PSCredential ($($profile.appUserName), $appUserSecPswd))
$webSitePath = "C:\inetpub\wwwroot\$($profile.webSiteName)"

#
#   DSC configuration
#
configuration $dscConfigName {
    #
    #   DSC Modules Imports
    #
    Import-DscResource –Module PSDesiredStateConfiguration, cNtfsAccessControl, xWebAdministration

    Node $targetNode {
        $Node.PSDscAllowPlainTextPassword = $true

        User AppUser {
            UserName = $($profile.appUserName)
            Ensure = "Present"
            Password = $appUserCred
            PasswordNeverExpires = $true
        }

        File WebSiteFiles
        {
            Ensure = "Present" 
            Type = "Directory“
            Recurse = $true
            SourcePath = "$appBuildPath"
            DestinationPath = $webSitePath
            MatchSource = $true
            Checksum = "modifiedDate"
        }

        xWebAppPool WebAppPool
        {
            Name   = $($profile.webAppPoolName)
            Ensure = "Present"
            State  = "Started"
            autoStart = $true
            identityType = "SpecificUser"
            Credential = $appUserCred
            startMode = 'AlwaysRunning'
            DependsOn = @('[User]AppUser')
        }

        xWebsite NewWebSite 
        { 
            Name   = $($profile.webSiteName)
            Ensure = "Present" 
            PhysicalPath = $webSitePath 
            State = "Started"
            ApplicationPool = $($profile.webAppPoolName)
            BindingInfo     = @(
                MSFT_xWebBindingInformation
                {
                    Protocol              = "HTTP"
                    Port                  = $($profile.bindingPort)
                    #CertificateThumbprint = "71AD93562316F21F74606F1096B85D66289ED60F"
                    #CertificateStoreName  = "WebHosting"
                }
            )
            DependsOn = @("[xWebAppPool]WebAppPool", "[File]WebsiteFiles") 
        }

        cNtfsPermissionEntry WebSiteDirPermissions {
            Ensure = 'Present'
            Principal = $($profile.appUserName)
            Path = $webSitePath
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'FullControl'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = @("[File]WebsiteFiles") 
        }
    }
}

write-host "Starting DSC configuration for $dscConfigName"
StartDSCConfig -configName $dscConfigName