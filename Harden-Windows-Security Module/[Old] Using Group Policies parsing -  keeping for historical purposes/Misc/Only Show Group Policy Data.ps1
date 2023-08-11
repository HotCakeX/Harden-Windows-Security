
# Load the xml file into a variable
$GroupPolicyXmlContent = [xml](Get-Content -Path ".\GPResult.xml" -ErrorAction Stop)


# An array to store each Group Policy "<q6:Policy>" element as a separate object
$PoliciesOutput = @()
# Use dot notation to access the Group Policy elements
$GroupPolicyXmlContent.Rsop.ComputerResults.ExtensionData.Extension.Policy | Where-Object { $null -ne $_.name } | ForEach-Object {   
    # All the sub-elements of the "<q6:Policy>" that we need to verify
    $PoliciesOutput += [PSCustomObject]@{
        Name                 = $_.Name
        State                = $_.State
        Category             = $_.Category
        DropDownListName     = $_.DropDownList.Name
        DropDownListState    = $_.DropDownList.State
        DropDownListValue    = $_.DropDownList.Value.Name
        CheckboxName         = $_.Checkbox.Name
        CheckboxState        = $_.Checkbox.State
        Numeric              = $_.Numeric
        NumericName          = $_.Numeric.Name
        NumericState         = $_.Numeric.State
        NumericValue         = $_.Numeric.Value
        ListBox              = $_.ListBox
        ListBoxName          = $_.ListBox.Name
        ListBoxState         = $_.ListBox.State
        ListBoxExplicitValue = $_.ListBox.ExplicitValue
        ListBoxAdditive      = $_.ListBox.Additive
        ListBoxValue         = $_.ListBox.Value
        MultiTextName        = $_.MultiText.Name
        MultiTextState       = $_.MultiText.State
        MultiTextValue       = $_.MultiText.Value
        EditTextName         = $_.EditText.Name
        EditTextState        = $_.EditText.State
        EditTextValue        = $_.EditText.Value
    }
}


# Shows the Group Policies policies
# $PoliciesOutput

# An array to store Group Policy Firewall settings as an object
$FirewallPoliciesOutput = @()
# Use dot notation to access the Group Policy elements - sometimes the type is q4 or q3 or q7, so using wildcard for the number
$FirewallGroupPolicySettings = $GroupPolicyXmlContent.Rsop.ComputerResults.ExtensionData.Extension | Where-Object { $_.type -like 'q*:WindowsFirewallSettings' } 

$FirewallPoliciesOutput += [PSCustomObject]@{
    GlobalSettingsPolicyVersion      = $FirewallGroupPolicySettings.GlobalSettings.PolicyVersion.Value

    DomainDefaultInboundAction       = $FirewallGroupPolicySettings.DomainProfile.DefaultInboundAction.value
    DomainDefaultOutboundAction      = $FirewallGroupPolicySettings.DomainProfile.DefaultOutboundAction.value
    DomainDisableNotifications       = $FirewallGroupPolicySettings.DomainProfile.DisableNotifications.value
    DomainDoNotAllowExceptions       = $FirewallGroupPolicySettings.DomainProfile.DoNotAllowExceptions.value
    DomainEnableFirewall             = $FirewallGroupPolicySettings.DomainProfile.EnableFirewall.value
    DomainLogFilePath                = $FirewallGroupPolicySettings.DomainProfile.LogFilePath.value
    DomainLogFileSize                = $FirewallGroupPolicySettings.DomainProfile.LogFileSize.value        
    DomainLogDroppedPackets          = $FirewallGroupPolicySettings.DomainProfile.LogDroppedPackets.value
    DomainLogSuccessfulConnections   = $FirewallGroupPolicySettings.DomainProfile.LogSuccessfulConnections.value
        
    PublicAllowLocalIPsecPolicyMerge = $FirewallGroupPolicySettings.PublicProfile.AllowLocalIPsecPolicyMerge.value
    PublicAllowLocalPolicyMerge      = $FirewallGroupPolicySettings.PublicProfile.AllowLocalPolicyMerge.value
    PublicDefaultInboundAction       = $FirewallGroupPolicySettings.PublicProfile.DefaultInboundAction.value
    PublicDefaultOutboundAction      = $FirewallGroupPolicySettings.PublicProfile.DefaultOutboundAction.value
    PublicDisableNotifications       = $FirewallGroupPolicySettings.PublicProfile.DisableNotifications.value
    PublicDoNotAllowExceptions       = $FirewallGroupPolicySettings.PublicProfile.DoNotAllowExceptions.value
    PublicEnableFirewall             = $FirewallGroupPolicySettings.PublicProfile.EnableFirewall.value
    PublicLogFilePath                = $FirewallGroupPolicySettings.PublicProfile.LogFilePath.value
    PublicLogFileSize                = $FirewallGroupPolicySettings.PublicProfile.LogFileSize.value        
    PublicLogDroppedPackets          = $FirewallGroupPolicySettings.PublicProfile.LogDroppedPackets.value
    PublicLogSuccessfulConnections   = $FirewallGroupPolicySettings.PublicProfile.LogSuccessfulConnections.value        

    #PrivateAllowLocalIPsecPolicyMerge = $FirewallGroupPolicySettings.PrivateProfile.AllowLocalIPsecPolicyMerge.value
    # PrivateAllowLocalPolicyMerge      = $FirewallGroupPolicySettings.PrivateProfile.AllowLocalPolicyMerge.value
    PrivateDefaultInboundAction      = $FirewallGroupPolicySettings.PrivateProfile.DefaultInboundAction.value
    PrivateDefaultOutboundAction     = $FirewallGroupPolicySettings.PrivateProfile.DefaultOutboundAction.value
    PrivateDisableNotifications      = $FirewallGroupPolicySettings.PrivateProfile.DisableNotifications.value
    #  PrivateDoNotAllowExceptions       = $FirewallGroupPolicySettings.PrivateProfile.DoNotAllowExceptions.value
    PrivateEnableFirewall            = $FirewallGroupPolicySettings.PrivateProfile.EnableFirewall.value
    PrivateLogFilePath               = $FirewallGroupPolicySettings.PrivateProfile.LogFilePath.value
    PrivateLogFileSize               = $FirewallGroupPolicySettings.PrivateProfile.LogFileSize.value        
    PrivateLogDroppedPackets         = $FirewallGroupPolicySettings.PrivateProfile.LogDroppedPackets.value
    PrivateLogSuccessfulConnections  = $FirewallGroupPolicySettings.PrivateProfile.LogSuccessfulConnections.value
}


# Shows the Group Policies Firewall settings/policies
$FirewallPoliciesOutput         
