# Defining the custom class for CIM instance classes
class CimClassInfo {
    [System.String]$ClassName
    [System.Collections.Generic.List[System.String]]$Methods
    [System.Collections.Generic.List[System.String]]$Properties

    CimClassInfo([System.String]$ClassName) {
        $this.ClassName = $ClassName
        $this.Methods = [System.Collections.Generic.List[System.String]]::new()
        $this.Properties = [System.Collections.Generic.List[System.String]]::new()
    }
}

# Defining the custom class for namespaces
class NamespaceInfo {
    [System.String]$NamespaceName
    [System.Collections.Generic.List[CimClassInfo]]$Classes

    NamespaceInfo([System.String]$NamespaceName) {
        $this.NamespaceName = $NamespaceName
        $this.Classes = [System.Collections.Generic.List[CimClassInfo]]::new()
    }
}

function Get-NamespaceInfo {
    [OutputType([System.Collections.Generic.List[NamespaceInfo]])]
    param (
        [System.String]$RootNamespace = 'root',
        [System.String]$OutputFile = $null
    )

    # Initialize a list to hold NamespaceInfo objects
    $NamespaceInfos = [System.Collections.Generic.List[NamespaceInfo]]::new()

    # Initialize a list to hold namespaces
    $Namespaces = [System.Collections.Generic.List[System.String]]::new()
    $Namespaces.Add($RootNamespace)

    # Initialize an index to track the current namespace
    $Index = 0

    # Loop through namespaces
    while ($Index -lt $Namespaces.Count) {
        # Get the current namespace
        $CurrentNamespace = $Namespaces[$Index]

        # Create a new NamespaceInfo object
        $NamespaceInfo = [NamespaceInfo]::new($CurrentNamespace)

        # Get child namespaces of the current namespace
        $ChildNamespaces = Get-CimInstance -Namespace $CurrentNamespace -ClassName __Namespace

        # Add child namespaces to the list
        foreach ($ChildNamespace in $ChildNamespaces.Name) {
            $Namespaces.Add("$CurrentNamespace\$ChildNamespace")
        }

        # Get classes in the current namespace
        $Classes = Get-CimClass -Namespace $CurrentNamespace

        # Add classes to the NamespaceInfo object
        foreach ($Class in $Classes) {
            # Create a new CimClassInfo object
            $CimClassInfo = [CimClassInfo]::new($Class.CimClassName)

            # Get methods of the class
            $Methods = ($Class.CimClassMethods).Name

            # Add methods to the CimClassInfo object
            foreach ($Method in $Methods) {
                $CimClassInfo.Methods.Add($Method)
            }

            # Get properties of the class
            $Properties = ($Class.CimClassProperties).Name

            # Add properties to the CimClassInfo object
            foreach ($Property in $Properties) {
                $CimClassInfo.Properties.Add($Property)
            }

            # Add the CimClassInfo object to the NamespaceInfo object
            $NamespaceInfo.Classes.Add($CimClassInfo)
        }

        # Add the NamespaceInfo object to the list
        $NamespaceInfos.Add($NamespaceInfo)

        # Move to the next namespace
        $Index++
    }

    # Export to JSON too if OutputFile is specified
    if ($OutputFile) {
        $NamespaceInfos | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputFile
    }

    return $NamespaceInfos
}

$NamespaceInfo = Get-NamespaceInfo -RootNamespace 'root' -OutputFile 'NamespaceInfo.json'
$NamespaceInfo
