<#
Pester Code Containing Integration Tests for .NET Environment Automation Functions
Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
Date: 8/24/16
#>

<#
The following article was used as the basis for structuring/invoking integration tests in a remote context:
https://4sysops.com/archives/powershell-integration-tests-with-pester/

Note that for most tests (all "New-IIS*" functions), the WebAdministration module is not imported prior to the tests explicitly.
- This is because PSSessions are utilized, and the function runs themselves prior to the tests import the module

These tests assume running under the context of an ESS admin account from a management box (e.g. Admin-RDS).

Note that for Invoke-Command runs, the array passed to ArgumentList positionally references the parameters of the function(s) its invoking remotely.

Also, these tests could certainly be DRYer, but this will do for now...
#>

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here\$sut"

$Script:password = Read-Host -Prompt "Enter the password for dotnet-dev-user to run tests" -AsSecureString

Describe “New-IISAppPool" {
    BeforeAll {
        $appPoolIdentityCredential = New-Object -TypeName System.Management.Automation.PSCredential("wharton\dotnet-dev-user", $Script:password)
        $session = New-PSSession -ComputerName "dotnet-dev" -Name "testSession"
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISAppPool} -ArgumentList @("testAppPool", $appPoolIdentityCredential)
    }

    Context "Successful Application Pool Creation" {
        It "Creates an Application Pool" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem -Path "IIS:\AppPools" | Select-Object -Property Name}
            $appPool.Name -contains "testAppPool" | Should Be $true
        }

        It "Sets the Proper Managed Runtime Version" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\AppPools\testAppPool" | Select-Object -Property managedRuntimeVersion}
            $appPool.managedRuntimeVersion | Should Be "v4.0"
        }

        It "Sets the Correct Managed Pipeline Mode" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\AppPools\testAppPool" | Select-Object -Property managedPipelineMode}
            $appPool.managedPipelineMode | Should Be "Integrated"
        }

        It "Correctly Sets Application Pool Identity" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\AppPools\testAppPool" | Select-Object -ExpandProperty processModel}
            $appPool.identityType | Should Be "SpecificUser"
            $appPool.userName | Should Be "wharton\dotnet-dev-user"
            $appPool.password | Should Not Be ""
        }

        It "Auto-Starts the AppPool After Creation" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\AppPools\testAppPool" | Select-Object -Property state, autoStart}
            $appPool.state | Should Be "Started"
            $appPool.autoStart | Should Be $true
        }
    }

    Context "Failed Application Pool Creation" {
        It "Fails to Create an Already Existing Application Pool" {
            {Invoke-Command -Session $session -ScriptBlock ${function:New-IISAppPool} -ArgumentList @("testAppPool", $appPoolIdentityCredential)} | Should Throw "Already Exists - Aborting"
        }
    }

    AfterAll {
        Invoke-Command -Session $session -ScriptBlock {Remove-Item -Path "IIS:\AppPools\testAppPool" -Recurse}
        Remove-PSSession -Session $session
    }
}

Describe "New-IISSite" {
    BeforeAll {
        $credential = New-Object -TypeName System.Management.Automation.PSCredential("wharton\dotnet-dev-user", $Script:password)
        $session = New-PSSession -ComputerName "dotnet-dev" -Name "testSession"
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISAppPool} -ArgumentList @("testAppPool", $credential)

        $siteBindings = @(
            @{
                protocol = "http"
                bindingInformation = "*:80:garbagesite.wharton.upenn.edu"
            },
            @{
                protocol = "https"
                bindingInformation = "*:443:garbagesite.wharton.upenn.edu"
            }
        )
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISSite} -ArgumentList @(
            "testSite", "testAppPool", $siteBindings, $env:TMP, $credential, $true
        )
    }

    Context "Successful Site Creation" {
        It "Creates a Site" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem -Path "IIS:\Sites" | Select-Object -Property Name}
            $site.Name -contains "testSite" | Should Be $true
        }

        It "Sets the Correct Physical Path" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite" | Select-Object -Property physicalPath}
            $site.physicalPath | Should Be $env:TMP
        }

        It "Sets the Specified Site Bindings" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite" | Select-Object -ExpandProperty bindings}
            $bindings = $site | Select-Object -ExpandProperty Collection
            $bindings.protocol -contains "http" | Should Be $true
            $bindings.protocol -contains "https" | Should Be $true
            $bindings.bindingInformation -contains "*:80:garbagesite.wharton.upenn.edu" | Should Be $true
            $bindings.bindingInformation -contains "*:443:garbagesite.wharton.upenn.edu" | Should Be $true
        }

        It "Sets the Correct Physical Path Credentials" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite" | Select-Object -Property userName, password}
            $site.userName | Should Be "wharton\dotnet-dev-user"
            $site.password | Should Not Be ""
        }

        It "Sets the Specified Application Pool" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite" | Select-Object -Property applicationPool}
            $site.applicationPool | Should Be "testAppPool"
        }

        It "Sets Anonymous Authentication to Use the AppPoolId" {
            $site = Invoke-Command -Session $session -ScriptBlock {
                Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location "IIS:\Sites\testSite" -Name userName
            }
            $site.Value | Should Be ""
        }
    }

    Context "Failed Site Creation" {
        It "Fails to Create an Already Existing Site" {
            {Invoke-Command -Session $session -ScriptBlock ${function:New-IISSite} -ArgumentList @(
                "testSite", "testAppPool", $siteBindings, $env:TMP, $credential, $true
            )} | Should Throw "Already Exists - Aborting"
        }
    }

    AfterAll {
        $scriptBlock = {
            Remove-Item -Path "IIS:\Sites\testSite" -Recurse
            Remove-Item -Path "IIS:\AppPools\testAppPool" -Recurse
        }
        Invoke-Command -Session $session -ScriptBlock $scriptBlock
        Remove-PSSession -Session $session
    }
}

Describe "New-IISVirtualDirectory" {
    BeforeAll {
        $credential = New-Object -TypeName System.Management.Automation.PSCredential("wharton\dotnet-dev-user", $Script:password)
        $session = New-PSSession -ComputerName "dotnet-dev" -Name "testSession"
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISAppPool} -ArgumentList @("testAppPool", $credential)

        $siteBindings = @(
            @{
                protocol = "http"
                bindingInformation = "*:80:garbagesite.wharton.upenn.edu"
            },
            @{
                protocol = "https"
                bindingInformation = "*:443:garbagesite.wharton.upenn.edu"
            }
        )
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISSite} -ArgumentList @(
            "testSite", "testAppPool", $siteBindings, $env:TMP, $credential, $true
        )
        
        Invoke-Command -Session $session -ScriptBlock {New-Item -Path "$env:TMP\testVD" -ItemType Directory}
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISVirtualDirectory} -ArgumentList @(
            "testVD", "testSite", "$env:TMP\testVD", $credential, $true
        )
    }
    
    Context "Successful Virtual Directory Creation" {
        It "Creates a Virtual Directory" {
            $vd = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testVD" | Select-Object -Property Name, ElementTagName}
            $vd.Name | Should Be "testVD"
            $vd.ElementTagName | Should Be "virtualDirectory"
        }

        It "Sets the Correct Physical Path" {
            $vd = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testVD" | Select-Object -Property physicalPath}
            $vd.physicalPath | Should Be "$env:TMP\testVD"
        }

        It "Sets the Correct Physical Path Credentials" {
            $vd = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testVD" | Select-Object -Property userName, password}
            $vd.userName | Should Be "wharton\dotnet-dev-user"
            $vd.password | Should Not Be ""
        }

        It "Sets Anonymous Authentication to Use the AppPoolId" {
            $vd = Invoke-Command -Session $session -ScriptBlock {
                Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location "IIS:\Sites\testSite\testVD" -Name userName
            }
            $vd.Value | Should Be ""
        }
    }

    Context "Failed Virtual Directory Creation" {
        It "Fails to Create an Already Existing Virtual Directory" {
            {Invoke-Command -Session $session -ScriptBlock ${function:New-IISVirtualDirectory} -ArgumentList @(
                "testVD", "testSite", "$env:TMP\testVD", $credential, $true
            )} | Should Throw "Already Exists - Aborting"
        }
    }

    AfterAll {
        $scriptBlock = {
            Remove-Item -Path "$env:TMP\testVD" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite\testVD" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite" -Recurse
            Remove-Item -Path "IIS:\AppPools\testAppPool" -Recurse
        }
        Invoke-Command -Session $session -ScriptBlock $scriptBlock
        Remove-PSSession -Session $session
    }
}

Describe "New-IISApplication" {
    BeforeAll {
        $credential = New-Object -TypeName System.Management.Automation.PSCredential("wharton\dotnet-dev-user", $Script:password)
        $session = New-PSSession -ComputerName "dotnet-dev" -Name "testSession"
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISAppPool} -ArgumentList @("testAppPool", $credential)

        $siteBindings = @(
            @{
                protocol = "http"
                bindingInformation = "*:80:garbagesite.wharton.upenn.edu"
            },
            @{
                protocol = "https"
                bindingInformation = "*:443:garbagesite.wharton.upenn.edu"
            }
        )
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISSite} -ArgumentList @(
            "testSite", "testAppPool", $siteBindings, $env:TMP, $credential, $true
        )

        Invoke-Command -Session $session -ScriptBlock {New-Item -Path "$env:TMP\testApp" -ItemType Directory}
        Invoke-Command -Session $session -ScriptBlock ${function:New-IISApplication} -ArgumentList @(
            "testApp", "testSite", "testAppPool", "$env:TMP\testApp", $credential, $true
        )
    }

    Context "Successful Application Creation" {
        It "Creates an Application" {
            $app = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp" | Select-Object -Property Name, ElementTagName}
            $app.Name | Should Be "testApp"
            $app.ElementTagName | Should Be "application"
        }

        It "Sets the Correct Physical Path" {
            $app = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp" | Select-Object -Property PhysicalPath}
            $app.PhysicalPath | Should Be "$env:TMP\testApp"
        }

        It "Assigns the Correct Application Pool" {
            $app = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp" | Select-Object -Property applicationPool}
            $app.applicationPool | Should Be "testAppPool"
        }

        It "Does Not Set Physical Path Credentials" {
            $app = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp" | Select-Object -Property userName, password}
            $app.userName | Should Be ""
            $app.password | Should Be ""
        }

        It "Sets Anonymous Authentication to Use the AppPoolId" {
            $app = Invoke-Command -Session $session -ScriptBlock {
                Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Location "IIS:\Sites\testSite\testApp" -Name userName
            }
            $app.Value | Should Be ""
        }
    }

    Context "Failed Application Creation" {
        It "Fails to Create an Already Existing Application" {
            {Invoke-Command -Session $session -ScriptBlock ${function:New-IISApplication} -ArgumentList @(
                "testApp", "testSite", "testAppPool", "$env:TMP\testApp", $credential, $true
            )} | Should Throw "Already Exists - Aborting"
        }
    }

    AfterAll {
        $scriptBlock = {
            Remove-Item -Path "$env:TMP\testApp" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite\testApp" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite" -Recurse
            Remove-Item -Path "IIS:\AppPools\testAppPool" -Recurse
        }
        Invoke-Command -Session $session -ScriptBlock $scriptBlock
        Remove-PSSession -Session $session
    }
}

Describe "New-DotNetEnvironment" {
    BeforeAll {
        $session = New-PSSession -ComputerName "dotnet-dev" -Name "testSession"
        Invoke-Command -Session $session -ScriptBlock {Import-Module -Name WebAdministration -ErrorAction Stop}

        $credential = New-Object -TypeName System.Management.Automation.PSCredential("wharton\dotnet-dev-user", $Script:password)
    }

    Context "First Successful Environment Creation" {
        BeforeAll {
            $appPoolProps = New-Object -TypeName PSObject -Property @{
                AppPoolName = "testAppPool"
                AppPoolIdentityCredential = $credential
            }

            $siteProps = New-Object -TypeName PSObject -Property @{
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
                DirectoryPath = $env:TMP
                PathCredential = $credential
                AppPoolIDAsAnonymousAuth = $true
            }

            Invoke-Command -Session $session -ScriptBlock {New-Item -Path "$env:TMP\testApp" -ItemType Directory}

            $dotNetParams = @{
                ResourceName = "testApp"
                ResourceDirectoryPath = "$env:TMP\testApp"
                DeploymentEnvironment = "Development"
                ResourceType = "Application"
                AppPool = $appPoolProps
                Site = $siteProps
                PathCredential = $credential
                ResourceDirectoryPermissions = @{
                    "dotnet-dev-user" = "Modify"
                }
                AppPoolIDAsAnonymousAuth = $true
            }
            New-DotNetEnvironment @dotNetParams
        }

        It "Creates an Application Pool" {
            $appPool = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem -Path "IIS:\AppPools" | Select-Object -Property Name}
            $appPool.Name -contains "testAppPool" | Should Be $true
        }

        It "Creates a Site" {
            $site = Invoke-Command -Session $session -ScriptBlock {Get-ChildItem -Path "IIS:\Sites" | Select-Object -Property Name}
            $site.Name -contains "testSite" | Should Be $true
        }

        It "Creates an Application" {
            $app = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp" | Select-Object -Property Name, ElementTagName}
            $app.Name | Should Be "testApp"
            $app.ElementTagName | Should Be "application"
        }
    }

    Context "Second Successful Environment Creation" {
        BeforeAll {
            Invoke-Command -Session $session -ScriptBlock {New-Item -Path "$env:TMP\testApp\testVD" -ItemType Directory}

            $dotNetParams = @{
                ResourceName = "testVD"
                ResourceDirectoryPath = "$env:TMP\testApp\testVD"
                DeploymentEnvironment = "Development"
                ResourceType = "VirtualDirectory"
                AppPool = "testAppPool"
                Site = "testSite"
                PathCredential = $credential
                AppPoolIDAsAnonymousAuth = $true
                NestedApp = "testApp"
            }
            New-DotNetEnvironment @dotNetParams
        }

        It "Creates a Virtual Directory" {
            $vd = Invoke-Command -Session $session -ScriptBlock {Get-Item -Path "IIS:\Sites\testSite\testApp\testVD" | Select-Object -Property Name, ElementTagName}
            $vd.Name | Should Be "testVD"
            $vd.ElementTagName | Should Be "virtualDirectory"
        }
    }

    Context "First Failed Environment Creation" {
        It "Fails to Create an Already Existing Application Environment" {
            $appPoolProps = New-Object -TypeName PSObject -Property @{
                AppPoolName = "testAppPool"
                AppPoolIdentityCredential = $credential
            }

            $dotNetParams = @{
                ResourceName = "testApp"
                ResourceDirectoryPath = "$env:TMP\testApp"
                DeploymentEnvironment = "Development"
                ResourceType = "Application"
                AppPool = $appPoolProps
                Site = "testSite"
                PathCredential = $credential
                ResourceDirectoryPermissions = @{
                    "dotnet-dev-user" = "Modify"
                }
                AppPoolIDAsAnonymousAuth = $true
            }
            {New-DotNetEnvironment @dotNetParams} | Should Throw "Already Exists - Aborting"
        }
    }

    Context "Second Failed Environment Creation" {
        It "Fails to Create an Already Existing Virtual Directory Environment" {
            $dotNetParams = @{
                ResourceName = "testVD"
                ResourceDirectoryPath = "$env:TMP\testApp\testVD"
                DeploymentEnvironment = "Development"
                ResourceType = "VirtualDirectory"
                AppPool = "testAppPool"
                Site = "testSite"
                PathCredential = $credential
                AppPoolIDAsAnonymousAuth = $true
                NestedApp = "testApp"
            }
            {New-DotNetEnvironment @dotNetParams} | Should Throw "Already Exists - Aborting"
        }
    }

    AfterAll {
        $scriptBlock = {
            Remove-Item -Path "$env:TMP\testApp" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite\testApp\testVD" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite\testApp" -Recurse
            Remove-Item -Path "IIS:\Sites\testSite" -Recurse
            Remove-Item -Path "IIS:\AppPools\testAppPool" -Recurse
        }
        Invoke-Command -Session $session -ScriptBlock $scriptBlock
        Remove-PSSession -Session $session
    }
}