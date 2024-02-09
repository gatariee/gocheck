function Get-DomainComputer {
<#
.SYNOPSIS

Return all computers or specific computer objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all computer objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Unconstrained

Switch. Return computer objects that have unconstrained delegation.

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER Printers

Switch. Return only printers.

.PARAMETER SPN

Return computers with a specific service principal name, wildcards accepted.

.PARAMETER OperatingSystem

Return computers with a specific operating system, wildcards accepted.

.PARAMETER ServicePack

Return computers with a specific service pack, wildcards accepted.

.PARAMETER SiteName

Return computers in the specific AD Site name, wildcards accepted.

.PARAMETER Ping

Switch. Ping each host to ensure it's up before enumerating.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainComputer

Returns the current computers in current domain.

.EXAMPLE

Get-DomainComputer -SPN mssql* -Domain testlab.local

Returns all MS SQL servers in the testlab.local domain.

.EXAMPLE

Get-DomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname

Return the dns hostnames of servers trusted for delegation.

.EXAMPLE

Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained

Search the specified OU for computeres that allow unconstrained delegation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainComputer -Credential $Cred

.OUTPUTS

PowerView.Computer

Custom PSObject with translated computer property fields.

PowerView.Computer.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}
