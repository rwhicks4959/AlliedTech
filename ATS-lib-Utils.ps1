<#
	.DESCRIPTION
        Collection of Functions Used by Allied Technologies Services

		Author: Rwhicks@AlliedTechUsa.com
		Copyright 2019 Allied Technology Services L.L.C.

	.LINKS
		1. https://devblogs.microsoft.com/powershell/resolve-error/
		2. https://social.technet.microsoft.com/Forums/en-US/843e2734-d96f-4ce4-96d5-7b5a00b85eb9/check-object-property-existance?forum=winserverpowershell
		3. https://4sysops.com/archives/the-powershell-function-	parameters-data-types-return-values/
		4. https://mcpmag.com/articles/2016/03/31/timing-powershell-automations.aspx
		5. https://devblogs.microsoft.com/scripting/the-powershell-5-nonewline-	parameter/


	.REVISON
		1.0 	02/01/2019

		1.1		02/23/2019
			Minor fixes to several Functions

		1.2		02/02/2024
			Added: Remove-LocalUserCompletely, Test-RegPropertyExists

		1.3		02/12/2024
			Added:	Get-PendingRebootStatus

	.NOTES
		Includes:
		Exit-WithCode
		Get-AppxExePath
		Get-AppInstallPath
		Get-ItemExists
		Get-PendingRebootStatus
		New-EventTimerDots
		New-Folder
		Remove-EmptyFolders
		Remove-LocalUserCompletely
		Resolve-Error ( $ErrorRecord=$Error[0] )
		Start-Operations
		Stop-Operations
		Stop-RunningProcess
		Test-IsFolderEmpty
		Test-RegPropertyExists
		Write-HostLog
		Write-HostLogError
		Write-HostLogWarning

#>

Set-StrictMode -Version 2.0

#Global Variables
$Error.Clear()
$Global:WriteErrorCount = 0


<#################
# Function Examples
#################
function Simple_Binding
{
		param
	(
		# 	param Definitions
	)

}

<#
function CmdLet_Example
{
	<#
		.SYNOPSIS

		.DESCRIPTION

		.EXAMPLE

		.LINK

		.NOTES
			Author: Rwhicks@AlliedTechUsa.com
			Copyright 2025 Allied Technology Services L.L.C.

		.REVISION
			1.0		06/07/2025		Rwhicks@AlliedTechUsa.com
	>

	[cmdletbinding()]
	[OutputType([string])]

	param
	(

	)

	begin {	Write-HostLog "`nBegin: $( $MyInvocation.Mycommand )`n" }

	process {} # required
}
#>

function Get-AppxExePath
{
	<#
		.SYNOPSIS
			Finds the Executable for an Installed Appx Application

		.DESCRIPTION

		.EXAMPLE

		.LINK

		.NOTES
			Author: Rwhicks@AlliedTechUsa.com
			Copyright 2025 Allied Technology Services L.L.C.

			Based on Code from Action1 Script Library

		.REVISION
			1.0		06/17/2025		Rwhicks@AlliedTechUsa.com
	#>

	[cmdletbinding()]
	[OutputType([System.IO.FileInfo])]

	param
	(
		[parameter ( Mandatory = $true )]
		[String] $AppxName
	)

	begin {	Write-HostLog "`nBegin: $( $MyInvocation.Mycommand )`n" }

	process
	{
		[Object[]] $AppxPackage = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $AppxName } -ErrorAction SilentlyContinue

		if ( $null -ne $AppxPackage )
		{
			if ( $AppxPackage.Length -gt 1 )
			{
				$TheList = New-Object System.Collections.Hashtable

				# Find Highest Version
				foreach ($Item in $AppxPackage)
				{
					$SplitLine = $Item.PackageFullName.Split( '_' )
					$Rslt = @($Splitline[1], $Item)

					$TheList.Add( $Rslt[0], $Rslt[1] )
				}

				[System.Version] $Newest = '0.0'
				foreach ( $Item in $TheList.Keys )
				{
					[System.Version] $ItemVersion = [System.Version] $Item
					If ( $ItemVersion -gt $Newest )
					{
						$Newest = $ItemVersion
					}
				}
			}

			$ParentPath = $TheList.Item($Newest.ToString()).InstallLocation

			return [String] ( Join-Path -Path $ParentPath -ChildPath 'Winget.Exe').ToString()
		}
		else
		{
			Write-ErrorHostLog "The $($AppxName) Executable is Not Detected."
			throw [System.IO.FileNotFoundException]  "The $($AppxName ) Executable is Not Detected."
		}
	}
}


function Get-AppInstallPathList
{
	<#
		.SYNOPSIS

		.DESCRIPTION

		.EXAMPLE

		.LINK
			https://stackoverflow.com/questions/47884710/how-to-get-a-programs-installation-path-using-powershell
			# Answer 2

		.NOTES
			Author: Rwhicks@AlliedTechUsa.com
			Copyright 2025 Allied Technology Services L.L.C.

		.REVISION
			1.0		06/04/2025		Rwhicks@AlliedTechUsa.com
	#>

	[cmdletbinding()]

	param
	(
		[parameter ( Mandatory = $false )]
		[bool] $x64 = $true,

		[parameter ( Mandatory = $false )]
		[bool] $x32 = $false

	)

	begin
	{
		Write-HostLog "`nBegin: $( $MyInvocation.Mycommand )`n"
 }

	process
	{
		if ( $x32 -eq $true )
		{
			$x64 = $false
		}

		if ($x64 -eq $true )
		{
			$rslt = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object DisplayName, InstallLocation | Sort-Object Displayname -Descending

		}

		if ($x32 -eq $true)
		{
			$rslt = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object DisplayName, InstallLocation | Sort-Object Displayname -Descending
		}

		return $rslt
	}
}



function Stop-RunningProcess
{
	<#
		.SYNOPSIS
			Stops a Process if it is Running

		.DESCRIPTION

		.EXAMPLE

		.LINK
			https://superuser.com/questions/1682641/how-to-check-if-process-is-running-properly-in-powershell

		.NOTES
			Author: Rwhicks@AlliedTechUsa.com
			Copyright 2024 Allied Technology Services L.L.C.

		.Revision
			1.0		02/11/2024		Rwhicks@AlliedTechUsa.com

	#>

	[CmdletBinding()]
	param
	(
		[parameter ( Mandatory = $true )]
		[String] $Name,

		[parameter ( Mandatory = $false )]
		[ValidateRange( 5, 30 )]
		[Int32] $WaitTime = 10
	)

	Begin
	{
		Write-HostLog "`nBegin: $( $MyInvocation.Mycommand )`n"
	}

	Process
	{
		Write-HostLog "`nChecking if Program is Open"

		$SplitId = $Id.Split( '.')

		$ProcessID = Get-Process $SplitId[1] -erroraction Continue

		if ( $null -ne $ProcessID )
		{
			Write-HostLog "`nClosing Open Program"

			# try gracefully first
			$ProcessID.CloseMainThread()

			# kill after 10 seconds
			[Int32] $Count = 0
			DO
			{
				if ( $ProcessID.HasExited )
    {
					Continue
    }

				Start-Sleep( 1 )
				$Count++

			} Until (( $Count + 5 ) -ge $WaitTime )

			if ( -not $ProcessID.HasExited )
			{
				$ProcessID | Stop-Process -Force

				$Count = 0
				DO
				{
					if ( $ProcessID.HasExited )
     {
						Continue
     }

					Start-Sleep( 1 )
					$Count++

				} Until ( $Count -ge $WaitTime )

				if ( -not $ProcessID.HasExited )
				{
					Write-HostLog "`nFailed To Stop Running Process"
					return $false
				}
			}
		}

		return $true
	}

	End
	{
		Write-HostLog "`nEnded: $( $MyInvocation.Mycommand )`n"
	}
}



function Get-AppVersion
{
	<#
	.SYNOPSIS
		Searches for an Application using the 'DisplayName' Property.
        If the Appliction is found, Returns an Object with Propertys:
            'DisplayName', 'DisplayVersion', 'InstallDate'

	.EXAMPLE
        $MinVersion = '5.6.7'
		$IsInstalled = Get-AppVersion -Name "Sophos Endpoint"
        # Check if Update is Needed
        if ( $IsInstalled )
        {
            if ( $IsInstalled.DisplayVersion -lt $MinVersion )
            { .\SophosSetup.exe --products=antivirus,intercept --quiet }
        }
        # Check if Not Installed
		if ( -not $IsInstalled ) { .\SophosSetup.exe --products=antivirus,intercept --quiet }

	.LINK
		https://superuser.com/questions/1523092/determining-software-that-is-already-installed

	.NOTES
		Author: https://superuser.com/users/458113/simons, Rwhicks@AlliedTechUsa.com
		Copyright 2024 Allied Technology Services L.L.C.

	.REVISON
		1.1      08/20/2024		Rwhicks@AlliedTechUsa.com
            Added Check to Prevent Object Not Found Error on $_.DisplayId Property

	#>

	[CmdletBinding( )]
	param (
		[Parameter( Position = 0,
			HelpMessage = 'Display Name of the Application. Wild Card Characters Allowed' )]
		[Alias( 'Name', 'Application' )]
		[string] $filter = '*',

		[Parameter( Mandatory = $false,
			HelpMessage = 'List of Properties to Return' )]
		[string[]] $properties = @('DisplayName', 'DisplayVersion', 'InstallDate'),

		[Parameter( Mandatory = $false,
			HelpMessage = 'Name Of the Computer to Run the Script On' )]
		[string[]] $ComputerName
	)

	try
	{
		$regpath = @(
			'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
		)

		$ScriptBlock = {
			[Object[]] $Rslt_1 = $regpath | ForEach-Object { Get-ItemProperty $_ }

			[Object[]] $Rslt_2 = $null

			$Rslt_1 | ForEach-Object { if ( [bool]( Get-member -Name DisplayName -InputObject $_ ))
				{
					$Rslt_2 += $_
				} }

			$Rslt_2 | Where-Object { $null -ne $_.DisplayName -and $_.DisplayName -like $filter } | Select-Object $properties
		}

		$splat = @{}

		if ( $ComputerName )
		{
			$splat['ComputerName'] = $ComputerName
  }

		return ( Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $regpath, $filter, $properties @splat )
	}
	catch
	{
		Write-Error "$( $MyInvocation.Mycommand ) Encountered Errors: `n`t$( $PSItem.Exception )" -ErrorAction Stop
	}
}



Function Get-PendingRebootStatus
{
	<#
	.Synopsis
		This will check to see if a server or computer has a reboot pending.
		For updated help and examples refer to -Online version.

	.NOTES
		Name: Get-PendingRebootStatus
		Author: theSysadminChannel
		Version: 1.2
		DateCreated: 2018-Jun-6

	.LINK
		https://thesysadminchannel.com/remotely-check-pending-reboot-status-powershell -


	.PARAMETER ComputerName
		By default it will check the local computer.

	.EXAMPLE
		Get-PendingRebootStatus -ComputerName PAC-DC01, PAC-WIN1001

		Description:
		Check the computers PAC-DC01 and PAC-WIN1001 if there are any pending reboots.

	.VERSION
		ATS-1.0		02/12/2024	Rwhicks@AlliedTechUsa
			Modifed Formating. Added Verbose Messages to Script
#>

	[CmdletBinding()]
	Param
	(
		[Parameter( Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0 )]
		[string[]]  $ComputerName = $env:COMPUTERNAME
	)


	Begin
	{
		Write-Host "`nBEGIN: $( $MyInvocation.Mycommand )" -foregroundcolor Green
	}

	PROCESS
	{
		Foreach ( $Computer in $ComputerName )
		{
			Try
			{
				$PendingReboot = $false

				$HKLM = [UInt32] '0x80000002'
				$WMI_Reg = [WMIClass] "\$Computer\root\default:StdRegProv"

				if ( $WMI_Reg )
				{
					if (( $WMI_Reg.EnumKey( $HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\')).sNames -contains 'RebootPending' )
					{
						$PendingReboot = $true
					}

					if (( $WMI_Reg.EnumKey( $HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\')).sNames -contains 'RebootRequired' )
					{
						$PendingReboot = $true
					}

					#Checking for SCCM namespace
					$SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore

					if ( $SCCM_Namespace )
					{
						if (( [WmiClass]"\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities" ).DetermineIfRebootPending().RebootPending -eq $true )
						{
							$PendingReboot = $true
						}
					}

					[PSCustomObject]@{
						ComputerName  = $Computer.ToUpper()
						PendingReboot = $PendingReboot
					}
				}
			}
			catch
			{
				Write-Error $_.Exception.Message
			}

			finally
			{
				#Clearing Variables # Changed to Remove-Variable RWHICKS 02/12/2024
				Remove-Variable -Name WMI_Reg -ErrorAction SilentlyContinue
				Remove-Variable -Name SCCM_Namespace -ErrorAction SilentlyContinue
			}
		}
	}
}



function Test-RegPropertyExists
{
	<#
	.SYNOPSIS
		Tests if a Property is in A Registry Key

	.DESCRIPTION
		Returns a [Bool] Value

	.EXAMPLE
		Test-RegPropertyExists -RegKey [Microsoft.Win32.RegistryKey] $Key -Name "DisplayName"
	.LINK
		https://github.com/PowerShell/PowerShell/issues/10875

	.NOTES
		Author: Rwhicks@AlliedTechUsa.com
		Copyright 2024 Allied Technology Services L.L.C.

	.Revision
		1.0		02/02/2024


#>

	[CmdletBinding()]

	param
	(
		[Parameter(Mandatory = $true)]
		[Microsoft.Win32.RegistryKey] $RegKey,

		[Parameter(Mandatory = $true)]
		[String] $Name
	)

	return [Bool](( [PSCustomObject] $RegKey).PSObject.Properties.Name -contains $Name )
}



function Remove-LocalUserCompletely
{
	<#
		.SYNOPSIS
		   Remove local user Account and data from windows 10/11

		.DESCRIPTION
			Deletes the account from the local account database
			Deletes the profile directory of this account
			Deletes the account profile from the registry

		.EXAMPLE
			Remove-LocalUserCompletely -Name 'Bob'

			# Delet all None Administrator Accounts

			$users = Get-LocalUser | ? Name -NotIn Administrator, DefaultAccount, DevToolsUser, Guest, sshd, User, WDAGUtilityAccount

			foreach ($user in $users)
			{
				Remove-LocalUserCompletely -Name $user.Name
			}

		.LINK
			https://stackoverflow.com/questions/62656577/remove-local-user-and-data-from-windows-10-using-powershell	See Answer #3
			https://superuser.com/questions/1569479/delete-local-accounts-with-powershell-script/1570605#1570605

		.REVISION
			Rev: 1.0 	Author:  Rwhicks@AlliedTechUsa.com 		01/23/2024

		.NOTES
	#>

	[cmdletbinding()]
	param
	(
		[parameter(ValueFromPipelineByPropertyName)]
		$Name
	)

	process
	{
		Try
		{
			Write-Host "Removing Local User: $($Name)"

			$user = Get-LocalUser -Name $Name

			# Remove the user from the account database
			Remove-LocalUser -SID $user.SID

			Write-Host 'Removing Profile Directory and Registy Profile'

			# Remove the profile of the user (both, profile directory and profile in the registry)
			Get-CimInstance -Class Win32_UserProfile | Where-Object SID -eq $user.SID | Remove-CimInstance

			return $true
		}
		Catch
		{
			return $false
		}
	}
}



function Get-ItemExists
{
	<#
		.SYNOPSIS
		   Determines if an object Exists

		.DESCRIPTION

		.EXAMPLE
			$foo
			# Enter the variable name minus the $ (Dollar Sign)

			if ( Get-ItemExists -Item 'foo' )
			{
				True Flow
			}else
			{
				False Flow
			}

			Result = $false


		.LINK
			https://stackoverflow.com/questions/3159949/in-powershell-how-do-i-test-whether-or-not-a-specific-variable-exists-in-global
				https://stackoverflow.com/users/615422/vertigoray

		.NOTES
			Author:  Rwhicks@AlliedTechUsa.com

			Rev: 1.0	01/21/2024

	#>

	[cmdletbinding()]
	param
	(
		[parameter(Mandatory = $True, Position = 0)]
		[String]
		$Item
	)

	if ( Get-Variable $Item -Scope 'Global' -ErrorAction 'Ignore' )
	{
		return $true
	}

	return $false
}



#################
# Makes a Folder if it Does not Exist
#################
function New-Folder
{
	[cmdletbinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[string] $Path
	)

	if ( !( Test-Path -Path $Path ))
	{
		[System.IO.DirectoryInfo] $Folder = New-Item -ItemType directory -Path $Path

		Return $Folder
	}

	Return Get-Item -Path $Path
}



#################
# Start-Operations
#################
function Start-Operations
{
	[cmdletbinding()]
	param()

	$Error.Clear()

	$global:stopwatch = New-Object System.Diagnostics.Stopwatch
	$stopwatch.Start()

	$LogFolder = 'C:\Tmp'
	# Make Sure Path to Log in exists
	if ( !( Test-Path -Path $LogFolder ))
	{
		New-Folder -Path $LogFolder
	}

	$Cmd = Get-Item -path $MyInvocation.ScriptName
	Set-Location -Path $Cmd.Directory.FullName

	$ScriptObj = Get-Item -Path $MyInvocation.ScriptName
	$Name = $ScriptObj.Name.Replace( $ScriptObj.Extension, '' )

	$Global:LogFile_Gbl = 'C:\Tmp\' + $Name + '.Log'

	if ( Test-Path -Path $Global:LogFile_Gbl )
	{
		Remove-Item -Path $Global:LogFile_Gbl
	}

	Write-HostLog "`nRunning Script: $($ScriptObj.Name)`n"
}


#################
# Stop-Operations
#################
function Stop-Operations
{
	[cmdletbinding()]
	param()

	if ( $Error.Count -gt 0 )
	{
		$Count = 0

		Write-HostLog "`nList of Errors:`n" -ForegroundColor 'Magenta'

		Foreach ( $Item in $Error )
		{
			$Count++
			Write-HostLog "`n$($Count)`n$($Item)`n"
		}
	}

	$stopwatch.Stop()

	if ( $Stopwatch.Elapsed.TotalMinutes -gt 1.0 )
	{
		Write-HostLog "Script Ran For: $($stopwatch.Elapsed.TotalMinutes) Minutes"
	}
	else
	{
		Write-HostLog "`nScript Ran For: $($stopwatch.Elapsed.TotalSeconds) Seconds`n"
	}
}



function Write-WarningHostLog
{
	<#
		.SYNOPSIS
		   Writes Data to WARNING and a Log File

		.DESCRIPTION
			Writes to the location Stored in: $Global:LogFile_Gbl Variable

		.EXAMPLE

			Write-WarningHostLog( "Stuff Again" )

		.LINK

		.NOTES

			Rev: 1.2	Author:  Rwhicks@AlliedTechUsa.com	01/24/2024
				Changed the $Txt 	param to allow: Pipeline, Unnamed and Named Input

	#>

	[cmdletbinding()]

	param
	(
		[parameter( Mandatory = $True, Position = 0, ValueFromPipeline = $true )]
		[Alias( 'Msg', 'Message' )]
		[System.String] $Txt
	)

	Begin
	{
 }

	Process
	{
		Try
		{
			$Host.UI.WriteWarningLine( $Txt )
		}
		Catch
		{
			# Some platforms cannot utilize Write-Host (Azure Functions, for instance). Fall back to Write-Output
			Write-Warning $( $Txt )
		}

		if ( $Global:LogFile_Gbl )
		{
			Out-File -FilePath $Global:LogFile_Gbl -InputObject $Txt -Appen
		}
		else
		{
			Write-WarningHostLog( 'Warning: Variable, Global:LogFile_Gbl, PATH IS NOT SET' )
		}
	}
}



function Write-ErrorHostLog
{
	<#
		.SYNOPSIS
		   Writes Data to ERROR and a Log File

		.DESCRIPTION
			Writes to the location Stored in: $Global:LogFile_Gbl Variable

		.EXAMPLE
			0ut-Log "Stuff $MoreStuff"

			Write-HostLog -Txt "Stuff Again"

			Get-Command | Write-HostLog

		.LINK

		.NOTES

			Rev: 1.2	Author:  Rwhicks@AlliedTechUsa.com	01/24/2024
				Changed the $Txt 	param to allow: Pipeline, Unnamed and Named Input

	#>

	[cmdletbinding()]

	param
	(
		[parameter( Mandatory = $True, Position = 0, ValueFromPipeline = $true )]
		[Alias( 'Msg', 'Message' )]
		[System.String] $Txt
	)

	Begin
	{
 }

	Process
	{
		Try
		{
			$Host.UI.WriteErrorLine( $Txt )
		}
		Catch
		{
			# Some platforms cannot utilize Write-Host (Azure Functions, for instance). Fall back to Write-Output
			Write-Error $( $Txt )
		}

		if ( $Global:LogFile_Gbl )
		{
			Out-File -FilePath $Global:LogFile_Gbl -InputObject $Txt -Appen
		}
		else
		{
			Write-WarningHostLog( 'Warning: Variable, Global:LogFile_Gbl, PATH IS NOT SET' )
		}
	}
}



function Write-HostLog
{
	<#
		.SYNOPSIS
		   Writes Data to the Console and a Log File

		.DESCRIPTION
			Writes to the location Stored in: $Global:LogFile_Gbl Variable

		.EXAMPLE
			0ut-Log "Stuff $MoreStuff"

			Write-HostLog -Txt "Stuff Again"

			Get-Command | Write-HostLog

		.LINK

		.NOTES

			Rev: 1.2	Author:  Rwhicks@AlliedTechUsa.com	01/24/2024
				Changed the $Txt 	param to allow: Pipeline, Unnamed and Named Input

	#>

	[cmdletbinding()]

	param
	(
		[parameter( Mandatory = $True, Position = 0, ValueFromPipeline = $true )]
		[Alias( 'Msg', 'Message' )]
		[System.String] $Txt,

		[parameter( Mandatory = $false, Position = 1, ValueFromPipeline = $true )]
		[System.ConsoleColor] $ForegroundColor = $Host.UI.RawUI.ForegroundColor,

		[parameter( Mandatory = $false, Position = 2, ValueFromPipeline = $true )]
		[System.ConsoleColor] $BackgroundColor = $Host.UI.RawUI.BackgroundColor
	)

	Begin
	{
	}

	Process
	{
		Try
		{
			$Host.UI.WriteLine( $ForegroundColor, $BackgroundColor, $Txt )
		}
		Catch
		{
			# Some platforms cannot utilize Write-Host (Azure Functions, for instance). Fall back to Write-Output
			Write-Output $( $Txt )
		}

		if ( $Global:LogFile_Gbl )
		{
			Out-File -FilePath $Global:LogFile_Gbl -InputObject $Txt -Appen
		}
		else
		{
			$Host.UI.WriteErrorLine( 'Warning: Variable, Global:LogFile_Gbl, PATH IS NOT SET' )
		}
	}
}



#################
# This Will Cause the Host Shell To Exit
#################
function Exit-WithCode
{
	[cmdletbinding()]
	param
	(
		[parameter( Mandatory = $false)]
		[int64] $exitcode = 1603		# Default is: MSI Unknown error Code
	)

	if ( 0 -ne $exitcode)
	{
		Write-WarningHostLog "`nExiting With Code: $( $exitcode )"
	}
	else
	{
		Write-HostLog "`nExiting With Code: $( $exitcode )"
	}

	$host.SetShouldExit( $exitcode )
	Exit $exitcode
}



#################
# 	Ref: 1		#
#################
function Resolve-Error ( $ErrorRecord = $Error[0] )
{
	[cmdletbinding()]

	$ErrorRecord | Format-List * -Force
	$ErrorRecord.InvocationInfo | Format-List *
	$Exception = $ErrorRecord.Exception

	for ( $i = 0; $Exception; $i++, ( $Exception = $Exception.InnerException ))
	{
		"$i" * 80
		$Exception | Format-List * -Force
	}
}


#################
#
#################
Function Test-IsFolderEmpty
{
	[cmdletbinding()]
	param
	(
		[parameter( ValueFromPipeline, ValueFromPipelineByPropertyName )]

		[ValidateScript(
			{
				if ( Test-Path $_ )
				{
					$True
				}
				else
				{
					Throw "Cannot Validate Path: $_"
				}
			})]

		[string] $Path
	)

	Process
	{
		$Count = ( Get-Item -path $Path ).GetFileSystemInfos().Count

		return ( $Count -eq 0 )
	} #endof Process

} #endof Function




#################
# 				#
#################
function Remove-EmptyFolders
{
	[cmdletbinding()]
	param
	(
		[System.IO.DirectoryInfo[]] $Paths = @(),

		[String[]] $Exclude = @()
	)

	Try
	{
		[int] $DeletedCount = 0
		[int] $SkippedCount = 0
		[int] $FilesNotFound = 0

		if ( !( $Paths ) -or ( $Paths.count -eq 0 ))
		{
			Return @( $DeletedCount, $SkippedCount )
		}

		[array]::Reverse( $Paths )  # Peforms an Inplace operation

		foreach ( $Dir in $Paths )
		{
			[bool] $IsContinue = $false

			ForEach ( $Item in $Exclude )
			{
				if ( ( $Dir | Where-Object { $_.FullName -contains $Item } ) )
				{
					$IsContinue = $true
					Write-HostLog "`nThis Folder has been Excluded From Empty Folder Removal`n`t$($Dir.FullName)"
					break
				}
			}

			if ( $IsContinue)
			{
				Continue
   }

			if ( Test-IsFolderEmpty -Path $Dir.FullName  )
			{
				try
				{
					if ( !( Test-Path -Path $Dir.FullName ))
					{
						$FilesNotFound++
						Continue
					}

					Remove-Item -Force -Path $Dir.FullName -ErrorAction Stop
				}
				catch
				{
					$SkippedCount++
					Continue
				}

				$DeletedCount++
			}
		}

		Return @( $DeletedCount, $SkippedCount, $FilesNotFound)
	}
	Catch
	{
		Write-HostLog "`nError Occurred While Deleting Folder:"
		Resolve-Error( $PSItem )
	}
}




#################
# Event Timer that prints dots on the screen to show progress
#################
function New-EventTimerDots
{
	[cmdletbinding()]
	param
	(
		[int] $Interval = ( 1000 / 10 ) # 10th of Minute
	)

	[int] $Counter = 0

	Register-ObjectEvent -InputObject $Timer -EventName Elapsed -SourceIdentifier TimerEvent -Action {
		$Counter++

		If ( $Counter -lt 80 )
		{
			Write-Host '.' -NoNewline
		}
		else
		{
			Write-Host '.'
		}
	}

	Return [Timers.Timer] $Timer
}














