<#
.SYNOPSIS
    Get-ADUserLastLogon gets the last logon timestamp of an Active Directory user.

.DESCRIPTION
    Each domain controller is queried separately to calculate the last logon from all results of all DCs.
    Depending on the number of domain controllers this may take some time.

.EXAMPLE
    Get-ADUserLastLogon.ps1 -samAccountName s.stollane

    Accepts a single user SAM account name

.EXAMPLE
    Get-ADUserLastLogon.ps1 -samAccountName "b.simpson","p.griffin"

    Accepts an array of user SAM account names

.EXAMPLE
    Get-AdUser -Filter 'Enabled -eq $true' | Get-ADUserLastLogon.ps1
    
    Gets all enabled AD user accounts and pipes the output to the script, returning logon dates for all users

.NOTES
    Version 1.2: Updates to include extra user details for analysis
    Version 1.1: Initial release, don't ask about 1.0
#>


[CmdletBinding()]
param

(

    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName)]
    [Alias("UserName", "User")]
    [string[]]$samAccountName

)

begin {
    $result = @()
}
process {
    Import-Module ActiveDirectory

    $UserLogonName = $samAccountName

    foreach ($user in $UserLogonName) {
    
        $resultlogon = @()

        # Get user to test for existence
        $dn = Get-AdUser -Identity $user -Properties distinguishedName | Select-Object -ExpandProperty distinguishedName
    
        # Check user exists
        If ($dn) {
        
            # Last login is per DC, get all DCs in domain
            $getdc = (Get-ADDomainController -Filter *).Name

            Write-Debug "Querying against $($getdc.count) Domain Controllers"

            # Get user details from each DC
            foreach ($dc in $getdc) {
                Write-Debug "Retrieving login date for $user on $dc"
                Try {

                    $aduser = Get-ADUser $user -Server $dc -Properties lastlogon,whenCreated,Description -ErrorAction Stop

                    $resultlogon += New-Object -TypeName PSObject -Property ([ordered]@{

                            'DisplayName'    = $aduser.Name
                            'samAccountName' = $adUser.samAccountName
                            'DC'             = $dc
                            'LastLogon'      = [datetime]::FromFileTime($aduser.'lastLogon') 
                            'Description'    = $aduser.Description
                            'whenCreated'    = $aduser.whenCreated

                        })

                }

                Catch {
                    Write-Warning "No reports from $($dc)"
                }

            }

            if ($DebugPreference -ne "SilentlyContinue") {
                foreach ($entry in $resultlogon) {
                    Write-Debug $entry
                }
            }

            # Check if user has logged into against DC otherwise blank login date 
            If ($null -EQ ($resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' })) {

                Write-Debug "No reports for user $($aduser.samAccountName). Possible reason: No first login."
                try {
                    $resultlogon[0].LastLogon = $null
                } catch {
                    Add-Member -InputObject $resultlogon[0] -Name LastLogon -Value $null
                }
                $result += $resultlogon[0]

            }
            else {
                # Select last login based on descending date order
                $result += $resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' } | Sort-Object LastLogon -Descending | Select-Object -First 1
            }
        }

        else

        { Write-Error "User '$user' not found. Check entered username." }

    }

}
end {
    return $result
}
