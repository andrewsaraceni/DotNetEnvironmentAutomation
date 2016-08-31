<#
PowerShell Functions Used to Automate the Creation of .NET Environments
Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
Date: 8/24/16
#>

function New-IISAppPool
{
    <#
    .SYNOPSIS
    Function used for the creation of application pools in IIS for .NET.
    .DESCRIPTION
    This function provides the following functionality:
    - Creation of a new application pool in IIS
    - Sets the default runtime version and pieline mode for the application pool
    - Sets the application pool identity to a domain-based credential
    .PARAMETER AppPoolName
    The name of the application pool to create.
    .PARAMETER AppPoolIdentityCredential
    A PSCredential object used to define the application pool identity credentials for the application pool.
    .EXAMPLE
    $creds = Get-Credential
    New-IISAppPool -AppPoolName "testAppPool" -AppPoolIdentityCredential $creds

    Creates a new application pool "testAppPool" with the credential in $creds as the application pool identity.
    .NOTES
    Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$AppPoolName,
        [Parameter(Mandatory=$false)]
        [PSCredential]$AppPoolIdentityCredential
    )

    Import-Module -Name WebAdministration -ErrorAction Stop

    $appPoolIISPath = "IIS:\AppPools\$AppPoolName"

    if (!(Test-Path -Path $appPoolIISPath))
    {
        "Creating Application Pool {0} at {1}" -f $AppPoolName, $appPoolIISPath | Write-Verbose
        [Void](New-Item -Path $appPoolIISPath -ErrorAction Stop)

        "Setting .NET Runtime and Pipeline Mode Defaults on {0}" -f $appPoolIISPath | Write-Verbose

        Set-ItemProperty -Path $appPoolIISPath -Name "managedRuntimeVersion" -Value "v4.0" -ErrorAction Stop
        Set-ItemProperty -Path $appPoolIISPath -Name "managedPipelineMode" -Value "Integrated" -ErrorAction Stop

        if ($AppPoolIdentityCredential)
        {
            "Setting Application Pool Identity on {0}" -f $appPoolIISPath | Write-Verbose
        
            $appPoolCreds = @{
                userName = $AppPoolIdentityCredential.UserName
                password = $AppPoolIdentityCredential.GetNetworkCredential().Password
                identityType = 3
            }
            Set-ItemProperty -Path $appPoolIISPath -Name "processModel" -Value $appPoolCreds -ErrorAction Stop
        }
    }
    else
    {
        throw "$appPoolIISPath Already Exists - Aborting"
    }


}

function New-IISSite
{
    <#
    .SYNOPSIS
    Function used for the creation of sites in IIS for .NET.
    .DESCRIPTION
    This function provides the following functionality:
    - Creation of a new site in IIS
    - Sets the physical path and site bindings for the site
    - Sets the path credential to a domain-based credential
    - Sets the default application pool for the site
    - Sets the site to use the application pool identity for anonymous authentication
    .PARAMETER SiteName
    The name of the site to create.
    .PARAMETER ApplicationPool
    The name of the application pool to set as the default for the site.
    .PARAMETER SiteBindings
    Accepts an array of hashtables with key-value pairs for setting site bindings.
    .PARAMETER DirectoryPath
    The path (e.g. local, UNC) to the folder the site points to as a root.
    .PARAMETER PathCredential
    A PSCredential object used to define the physical path credentials for the site.
    .PARAMETER AppPoolIDAsAnonymousAuth
    Boolean value for determining whether to set the site to use the application pool identity as anonymous authentication.
    .EXAMPLE
    $creds = Get-Credential
    $siteParams = @{
        SiteName = "testSite"
        ApplicationPool = "testAppPool"
        SiteBindings = @(
            @{
                protocol = "http"
                bindingInformation = "*:80:garbagesite.wharton.upenn.edu"
            },
            @{
                protocol = "https"
                bindingInformation = "*:443:garbagesite.wharton.upenn.edu"
            }
        )
        DirectoryPath = "C:\RandomPath"
        PathCredential = $creds
        AppPoolIDAsAnonymousAuth = $true
    }
    New-IISSite @siteParams

    Creates a new site "testSite" pointing to "C:\RandomPath" (connecting via $creds), using the "testAppPool" application pool and anonymous authentication as the AppPoolID, binding to http and https for garbagesite.wharton.upenn.edu.
    .NOTES
    Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$SiteName,
        [Parameter(Mandatory=$true)]
        [String]$ApplicationPool,
        [Parameter(Mandatory=$true)]
        [Array]$SiteBindings,
        [Parameter(Mandatory=$true)]
        [String]$DirectoryPath,
        [Parameter(Mandatory=$true)]
        [PSCredential]$PathCredential,
        [Parameter(Mandatory=$false)]
        [Boolean]$AppPoolIDAsAnonymousAuth
    )

    Import-Module -Name WebAdministration -ErrorAction Stop

    $siteIISPath = "IIS:\Sites\$SiteName"

    if (!(Test-Path -Path $siteIISPath))
    {
        "Creating Site {0} at {1} and Setting Physical Path and Bindings" -f $SiteName, $siteIISPath | Write-Verbose
        [Void](New-Item -Path $siteIISPath -PhysicalPath $DirectoryPath -Bindings $SiteBindings -ErrorAction Stop)

        "Setting Physical Path Credentials on {0}" -f $siteIISPath | Write-Verbose

        Set-ItemProperty -Path $siteIISPath -Name userName -Value $PathCredential.UserName -ErrorAction Stop
        Set-ItemProperty -Path $siteIISPath -Name password -Value $PathCredential.GetNetworkCredential().Password -ErrorAction Stop

        "Setting Application Pool on {0}" -f $siteIISPath | Write-Verbose

        Set-ItemProperty -Path $siteIISPath -Name applicationPool -Value $ApplicationPool -ErrorAction Stop

        if ($AppPoolIDAsAnonymousAuth)
        {
            "Setting Anonymous Authentication to Applicaiton Pool Identity on {0}" -f $siteIISPath | Write-Verbose

            Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location $siteIISPath -Name userName -Value "" -ErrorAction Stop
        }
    }
    else
    {
        throw "$siteIISPath Already Exists - Aborting"
    }
}

function New-IISVirtualDirectory
{
    <#
    .SYNOPSIS
    Function used for the creation of virtual directories in IIS for .NET.
    .DESCRIPTION
    This function provides the following functionality:
    - Creation of a new virtual directory (VD) in IIS
    - Sets the VD IIS path depending on its nesting structure (e.g. inside a containing application or not)
    - Sets the physical path and path credential to a domain-based credential for the VD
    - Sets the VD to use the application pool identity for anonymous authentication
    .PARAMETER VDName
    The name of the virtual directory to create.
    .PARAMETER Site
    The name of the site where the virtual directory will reside under.
    .PARAMETER DirectoryPath
    The path (e.g. local, UNC) to the folder the virtual directory points to.
    .PARAMETER PathCredential
    A PSCredential object used to define the physical path credentials for the virtual directory.
    .PARAMETER AppPoolIDAsAnonymousAuth
    Boolean value for determining whether to set the virtual directory to use the application pool identity as anonymous authentication.
    .PARAMETER Application
    The name of the application the virtual directory lives within (if applicable).
    .EXAMPLE
    $creds = Get-Credential
    $vdParams = @{
        VDName = "testVD"
        Site = "testSite"
        DirectoryPath = "C:\RandomPath\testApp\testVD"
        PathCredential = $creds
        AppPoolIDAsAnonymousAuth = $true
        Application = "testApp"
    }
    New-IISVirtualDirectory @vdParams

    Creates a new virtual directory "testVD" pointing to "C:\RandomPath\testApp\testVD" (connecting via $creds), residing under the "testSite" site and using anonymous authentication as the AppPoolID.
    .NOTES
    Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$VDName,
        [Parameter(Mandatory=$true)]
        [String]$Site,
        [Parameter(Mandatory=$true)]
        [String]$DirectoryPath,
        [Parameter(Mandatory=$true)]
        [PSCredential]$PathCredential,
        [Parameter(Mandatory=$false)]
        [Boolean]$AppPoolIDAsAnonymousAuth,
        [Parameter(Mandatory=$false)]
        [String]$Application
    )

    Import-Module -Name WebAdministration -ErrorAction Stop

    if ($Application)
    {
        $vdIISPath = "IIS:\Sites\$Site\$Application\$VDName"
    }
    else
    {
        $vdIISPath = "IIS:\Sites\$Site\$VDName"
    }

    if ((Get-Item -Path $vdIISPath -ErrorAction SilentlyContinue).ElementTagName -ne "virtualDirectory")
    {
        "Creating Virtual Directory {0} Mapped to {1}" -f $vdIISPath, $DirectoryPath | Write-Verbose
        [Void](New-Item -Path $vdIISPath -ItemType VirtualDirectory -PhysicalPath $DirectoryPath -ErrorAction Stop)

        "Setting Physical Path Credentials on {0}" -f $vdIISPath | Write-Verbose

        Set-ItemProperty -Path $vdIISPath -Name userName -Value $PathCredential.UserName -ErrorAction Stop
        Set-ItemProperty -Path $vdIISPath -Name password -Value $PathCredential.GetNetworkCredential().Password -ErrorAction Stop

        if ($AppPoolIDAsAnonymousAuth)
        {
            "Setting Anonymous Authentication to Applicaiton Pool Identity on {0}" -f $vdIISPath | Write-Verbose

            Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location $vdIISPath -Name userName -Value "" -ErrorAction Stop
        }
    }
    else
    {
        throw "$vdIISPath Already Exists - Aborting"
    }
    

}

function New-IISApplication
{
    <#
    .SYNOPSIS
    Function used for the creation of applications in IIS for .NET.
    .DESCRIPTION
    This function provides the following functionality:
    - Creation of a new application in IIS
    - Sets the physical path, application pool and site for the application
    - Sets the physical path credential to a domain-based credential for the application
    - Sets the application to use the application pool identity for anonymous authentication
    .PARAMETER AppName
    The name of the application to create.
    .PARAMETER Site
    The name of the site where the application will reside under.
    .PARAMETER Application Pool
    The name of the application pool to use for the application.
    .PARAMETER DirectoryPath
    The path (e.g. local, UNC) to the folder the application points to.
    .PARAMETER PathCredential
    A PSCredential object used to define the physical path credentials for the application.
    .PARAMETER AppPoolIDAsAnonymousAuth
    Boolean value for determining whether to set the application to use the application pool identity as anonymous authentication.
    .EXAMPLE
    $creds = Get-Credential
    $appParams = @{
        AppName = "testApp"
        Site = "testSite"
        ApplicationPool = "testAppPool"
        DirectoryPath = "C:\RandomPath\testApp"
        PathCredential = $creds
        AppPoolIDAsAnonymousAuth = $true
    }
    New-IISApplication @appParams

    Creates a new application "testApp" pointing to "C:\RandomPath\testApp" (connecting via $creds), residing under the "testSite" site and "testAppPool" application pool, while also using anonymous authentication as the AppPoolID.
    .NOTES
    Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)

    Due to issues with using UNC-based physical paths with New-WebApplication, a random, temporary path is initially set, replaced later with its proper path and the temporary path removed.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$AppName,
        [Parameter(Mandatory=$true)]
        [String]$Site,
        [Parameter(Mandatory=$true)]
        [String]$ApplicationPool,
        [Parameter(Mandatory=$true)]
        [String]$DirectoryPath,
        [Parameter(Mandatory=$true)]
        [PSCredential]$PathCredential,
        [Parameter(Mandatory=$false)]
        [Boolean]$AppPoolIDAsAnonymousAuth
    )

    Import-Module -Name WebAdministration -ErrorAction Stop

    $appIISPath = "IIS:\Sites\$Site\$AppName"
    $tempPhysicalPath = "$HOME\IISAppGen$(Get-Random)"

    if ((Get-Item -Path $appIISPath -ErrorAction SilentlyContinue).ElementTagName -ne "application")
    {
        "Creating Application {0} Mapped to {1}" -f $appIISPath, $DirectoryPath | Write-Verbose

        [Void](New-Item -Path $tempPhysicalPath -ItemType Directory -ErrorAction Stop)
        [Void](New-WebApplication -Site $Site -Name $AppName -PhysicalPath $tempPhysicalPath -ApplicationPool $ApplicationPool -ErrorAction Stop)
        Set-ItemProperty -Path "IIS:\Sites\$Site\$AppName" -Name physicalPath -Value $DirectoryPath -ErrorAction Stop
        Remove-Item -Path $tempPhysicalPath -Force -ErrorAction Continue

        # Physical path credentials will override using the AppPoolID/anonymous authentication, so it's an either/or for IIS applications

        if ($AppPoolIDAsAnonymousAuth)
        {
            "Setting Anonymous Authentication to Applicaiton Pool Identity on {0}" -f $appIISPath | Write-Verbose

            Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location $appIISPath -Name userName -Value "" -ErrorAction Stop
        }
        else
        {
            "Setting Physical Path Credentials on {0}" -f $appIISPath | Write-Verbose

            Set-ItemProperty -Path $appIISPath -Name userName -Value $PathCredential.UserName -ErrorAction Stop
            Set-ItemProperty -Path $appIISPath -Name password -Value $PathCredential.GetNetworkCredential().Password -ErrorAction Stop
        }
    }
    else
    {
        throw "$appIISPath Already Exists - Aborting"
    }
}



function New-DotNetEnvironment
{
    <#
    .SYNOPSIS
    Function used for the creation of virtual directories and applications in development and production for Wharton's .NET environment.
    .DESCRIPTION
    Used as a wrapper function for remotely invoking other IIS-related functions and building environment setups via a single command.

    Overall, this function provides the following functionality:
    - Creation of a new UNC-based folder if one doesn't exist (e.g. on cfiles)
    - Set permissions on the UNC-based directory for specified users/groups and FileSystemRights types
    - Set the changes to be made/environment to be created in either development or production systems
    - Has the option to create new application pools and/or sites, or use existing ones when deploying new virtual directories and applications
    - Creation of a new virtual directory or application with a variety of additional options
    .PARAMETER ResourceName
    The name of the virtual directory or application to create.
    .PARAMETER ResourceDirectoryPath
    The path (e.g. local, UNC) to the folder the virtual directory or application points to.
    .PARAMETER DeploymentEnvironment
    Configures the virtual directory or application either for Wharton's "Development" or "Production" .NET environment.
    .PARAMETER ResourceType
    Creates either a "VirtualDirectory" or "Application" in IIS in the specified deployment environment.
    .PARAMETER AppPool
    Either the name of the application pool if using an existing one, or a PSObject containing matching properties/values to parameters (of New-IISAppPool) for creating a new one.
    .PARAMETER Site
    Either the name of the site if using an existing one, or a PSObject containing matching properties/values to parameters (of New-IISSite) for creating a new one.
    .PARAMETER PathCredential
    A PSCredential object used to define the physical path credentials for the virtual directory or application.
    .PARAMETER ResourceDirectoryPermissions
    Hashtable of key-value pairs of users/groups and FileSystemRights types to set additional permissions on the $ResourceDirectoryPath.
    .PARAMETER AppPoolIDAsAnonymousAuth
    Boolean value for determining whether to set the virtual directory or application to use the application pool identity as anonymous authentication.
    .PARAMETER NestedApp
    For virtual directories, the name of the application the virtual directory lives within (if applicable).
    .EXAMPLE
    $appPoolCred = Get-Credential
    $pathCred = Get-Credential

    $apps = @("Engage", "EngageAdmin", "EngageMaterials")

    foreach ($app in $apps)
    {
        $appPoolProps = New-Object -TypeName PSObject -Property @{
            AppPoolName = $app
            AppPoolIdentityCredential = $appPoolCred
        }

        $dotNetParams = @{
            ResourceName = $app
            ResourceDirectoryPath = "\\cfiles\dotnet_dev\$app"
            DeploymentEnvironment = "Development"
            ResourceType = "Application"
            AppPool = $appPoolProps
            Site = "dotnet-dev"
            PathCredential = $pathCred
            ResourceDirectoryPermissions = @{
                "Execed-Dev-Admins" = "Modify"
                "engage-dev-apppool" = "Modify"
            }
            AppPoolIDAsAnonymousAuth = $true
            Verbose = $true
        }
        New-DotNetEnvironment @dotNetParams
    }

    $dotNetParams = @{
        ResourceName = "PayeeImages"
        ResourceDirectoryPath = "\\cfiles\dotnet_dev\EngageMaterials\PayeeImages"
        DeploymentEnvironment = "Development"
        ResourceType = "VirtualDirectory"
        AppPool = "EngageMaterials"
        Site = "dotnet-dev"
        PathCredential = $pathCred
        ResourceDirectoryPermissions = @{
            "Execed-Dev-Admins" = "Modify"
            "engage-dev-apppool" = "Modify"
        }
        AppPoolIDAsAnonymousAuth = $true
        NestedApp = "EngageMaterials"
        Verbose = $true
    }
    New-DotNetEnvironment @dotNetParams
    
    Making heavy use of New-DotNetEnvironment, the code above does the following:
    - Creates new IIS applications for Engage, EngageAdmin and EngageMaterials in the development .NET environment
    - Creates individual application pools per app, setting each app to use its respective application pool
    - Creates a virtual directory (PayeeImages) side of the EngageMaterials app, utilizing the app's containing application pool
    - Sets additional features as desired (e.g. custom directory permissions for the UNC-based directory paths)
    .NOTES
    Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)

    This function assumes running under the context of an ESS admin account from a management box (e.g. Admin-RDS).

    Further information on possible FileSystemRights types for the DirectoryPermissions hashtable can be found at the following link:
    https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights%28v=vs.110%29.aspx
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$ResourceName,
        [Parameter(Mandatory=$true)]
        [String]$ResourceDirectoryPath,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Development", "Production")]
        [String]$DeploymentEnvironment,
        [Parameter(Mandatory=$true)]
        [ValidateSet("VirtualDirectory", "Application")]
        [String]$ResourceType,
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            ($_.GetType().FullName -eq "System.String") -or 
            ($_.GetType().FullName -eq "System.Management.Automation.PSCustomObject")
        })]
        [Object]$AppPool,
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            ($_.GetType().FullName -eq "System.String") -or 
            ($_.GetType().FullName -eq "System.Management.Automation.PSCustomObject")
        })]
        [Object]$Site,
        [Parameter(Mandatory=$true)]
        [PSCredential]$PathCredential,
        [Parameter(Mandatory=$false)]
        [Hashtable]$ResourceDirectoryPermissions,
        [Parameter(Mandatory=$false)]
        [Boolean]$AppPoolIDAsAnonymousAuth,
        [Parameter(Mandatory=$false)]
        [String]$NestedApp
    )

    # Create directory for resource if necessary, and its a UNC path

    if ((!(Test-Path -Path $ResourceDirectoryPath)) -and ($ResourceDirectoryPath.StartsWith("\\")))
    {
        "{0} Does Not Exist - Creating New Directory" -f $ResourceDirectoryPath | Write-Verbose

        [Void](New-Item -Path $ResourceDirectoryPath -ItemType Directory -ErrorAction Stop)
    }

    # Set permissions on directory for each passed in user/group and permission key-value pair

    if ($ResourceDirectoryPermissions -and $ResourceDirectoryPath.StartsWith("\\"))
    {
        $acl = Get-Acl -Path $ResourceDirectoryPath
        foreach ($permission in $ResourceDirectoryPermissions.GetEnumerator())
        {
            "Setting {0} Permissions for {1} on {2}" -f $permission.Value, $permission.Name, $ResourceDirectoryPath | Write-Verbose
            
            $newAcl = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
                $permission.Name, $permission.Value, "ContainerInherit, ObjectInherit", "None", "Allow"
            )
            $acl.SetAccessRule($newAcl)
        }
        Set-Acl -Path $ResourceDirectoryPath -AclObject $acl
    }

    # Establish dev and prod nodes (hard-coded)

    "Setting Nodes to Work on for {0} .NET Environment" -f $DeploymentEnvironment | Write-Verbose

    if ($DeploymentEnvironment -eq "Development")
    {
        $nodes = @(,"dotnet-dev")
    }
    elseif ($DeploymentEnvironment -eq "Production")
    {
        $nodes = @("dotnet-p1", "dotnet-p2")
    }
    
    # For application pool and site, if PSCustomObject passed in, create from scratch via object properties
    # Else, String passed in and assume it already exists

    if ($AppPool.GetType().FullName -eq "System.Management.Automation.PSCustomObject")
    {
        foreach ($node in $nodes)
        {
            "Creating AppPool {0} on {1}" -f $AppPool.AppPoolName, $node | Write-Verbose
            
            [Void](Invoke-Command -ComputerName $node -ScriptBlock ${function:New-IISAppPool} -ArgumentList @(
                $AppPool.AppPoolName, $AppPool.AppPoolIdentityCredential
            ) -ErrorAction Stop)
        }

        $appPoolName = $AppPool.AppPoolName
    }
    else
    {
        "AppPool {0} Assumed to Already Exist - Moving On..." -f $AppPool | Write-Verbose
        
        $appPoolName = $AppPool
    }

    if ($Site.GetType().FullName -eq "System.Management.Automation.PSCustomObject")
    {
        foreach ($node in $nodes)
        {
            "Creating Site {0} on {1}" -f $Site.SiteName, $node | Write-Verbose
            
            [Void](Invoke-Command -ComputerName $node -ScriptBlock ${function:New-IISSite} -ArgumentList @(
                $Site.SiteName, $Site.ApplicationPool, $Site.SiteBindings, $Site.DirectoryPath, $SIte.PathCredential, $Site.AppPoolIDAsAnonymousAuth
            ) -ErrorAction Stop)
        }

        $siteName = $Site.SiteName
    }
    else
    {
        "Site {0} Assumed to Already Exist - Moving On..." -f $Site | Write-Verbose
        
        $siteName = $Site
    }

    # Establish remote function to invoke for virtual directory or app creation
    # Build array of arguments (in order of parameter declarations) to pass to the remote function invocations

    if ($ResourceType -eq "VirtualDirectory")
    {
        $remoteFunction = ${function:New-IISVirtualDirectory}
        $remoteArguments = @($ResourceName, $siteName, $ResourceDirectoryPath, $PathCredential)

        if ($AppPoolIDAsAnonymousAuth)
        {
            $remoteArguments += $true
        }
        else
        {
            $remoteArguments += $false
        }

        if ($NestedApp)
        {
            $remoteArguments += $NestedApp
        }
    }
    elseif ($ResourceType -eq "Application")
    {
        $remoteFunction = ${function:New-IISApplication}
        $remoteArguments = @($ResourceName, $siteName, $appPoolName, $ResourceDirectoryPath, $PathCredential)

        if ($AppPoolIDAsAnonymousAuth)
        {
            $remoteArguments += $true
        }
        else
        {
            $remoteArguments += $false
        }
    }
    
    # Create virtual directory or app remotely on dev/prod servers

    foreach ($node in $nodes)
    {
        "{0} {1} Being Created on {2}" -f $ResourceType, $ResourceName, $node | Write-Verbose
        
        [Void](Invoke-Command -ComputerName $node -ScriptBlock $remoteFunction -ArgumentList $remoteArguments -ErrorAction Stop)
    }
}