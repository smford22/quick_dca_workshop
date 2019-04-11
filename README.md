The following is a quick workshop to demonstrate Detect Correct Automate with Chef Software. You should have the following tools installed:

- [chef workstation]() 
- [git]() 
- Code editor like [VSCode]() or [Sublime Text]()

## Create a compliance profile 
In this section we will create a basic Windows compliance profile
1. mkdir `~/src`
2. `inspec init profile <yourcompany>_windows_baseline`
3. `cd <yourcompany>_windows_baseline`
4. open the profile in your Editor of choice
5. rename `controls/example.rb` to `controls/password_policy.rb`
6. Edit the `inspec.yml` with the following:

```yaml
name: <yourcompany>_windows_baseline
title: <yourcompany> Windows Baseline
maintainer: The Authors
copyright: The Authors
copyright_email: you@example.com
license: Apache-2.0
summary: A Baseline Compliance Profile for Windows
version: 0.1.0
supports:
  - os-family: windows
```

7. open `controls/password_policy.rb` and add the following code...

```ruby
title 'Password Policy'

control 'cis-enforce-password-history-1.1.1' do
  impact 0.7
  title '1.1.1 Set Enforce password history to 24 or more passwords'
  desc 'Set Enforce password history to 24 or more passwords'
  describe security_policy do
    its('PasswordHistorySize') { should be >= 24 }
  end
end

control 'cis-maximum-password-age-1.1.2' do
  impact 0.7
  title '1.1.2 Set Maximum password age to 60 or fewer days, but not 0'
  desc 'Set Maximum password age to 60 or fewer days, but not 0'
  describe security_policy do
    its('MaximumPasswordAge') { should be <= 60 }
    its('MaximumPasswordAge') { should be > 0 }
  end
end

control 'cis-minimum-password-age-1.1.3' do
  impact 0.7
  title '1.1.3 Set Minimum password age to 1 or more days'
  desc 'Set Minimum password age to 1 or more days'
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

control 'cis-minimum-password-length-1.1.4' do
  impact 0.7
  title '1.1.4 Set Minimum password length to 14 or more characters'
  desc 'Set Minimum password length to 14 or more characters'
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

control 'cis-password-complexity-1.1.6' do
  impact 0.7
  title '1.1.6 Set Store passwords using reversible encryption to Disabled'
  desc 'Set Store passwords using reversible encryption to Disabled'
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end
```

8. create a new file `controls/access_config.rb` with the following content:

```ruby
title 'Windows Access Configuration'

control 'windows-base-100' do
  impact 1.0
  title 'Verify the Windows folder permissions are properly set'
  desc 'Verify the Windows folder permissions are properly set'
  describe file('c:/windows') do
    it { should be_directory }
    # it { should_not be_readable }
    # it { should_not be_writable.by('Administrator') }
  end
end

## NTLM

control 'windows-base-101' do
  impact 1.0
  title 'Safe DLL Search Mode is Enabled'
  desc '
    cannot be managed via group policy
    @link: https://msdn.microsoft.com/en-us/library/ms682586(v=vs.85).aspx
    @link: https://technet.microsoft.com/en-us/library/dd277307.aspx
  '
  describe registry_key('HKLM\System\CurrentControlSet\Control\Session Manager') do
    it { should exist }
    it { should_not have_property_value('SafeDllSearchMode', :type_dword, '0') }
  end
end

# MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
# Ensure voulmes are using the NTFS file systems
control 'windows-base-102' do
  impact 1.0
  title 'Anonymous Access to Windows Shares and Named Pipes is Disallowed'
  desc 'Anonymous Access to Windows Shares and Named Pipes is Disallowed'
  tag cis: ['windows_2012r2:2.3.11.8', 'windows_2016:2.3.10.9']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

control 'windows-base-103' do
  impact 1.0
  title 'All Shares are Configured to Prevent Anonymous Access'
  desc 'All Shares are Configured to Prevent Anonymous Access'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('NullSessionShares') { should eq [''] }
  end
end

control 'windows-base-104' do
  impact 1.0
  title 'Force Encrypted Windows Network Passwords'
  desc 'Force Encrypted Windows Network Passwords'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

control 'windows-base-105' do
  title 'SMB1 to Windows Shares is disabled'
  desc 'All Windows Shares are Configured to disable the SMB1 protocol'
  impact 1.0
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('SMB1') { should eq 0 }
  end
end

## LSA Authentication
# @link: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326(v=vs.85).aspx

control 'windows-base-201' do
  impact 1.0
  title 'Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled'
  desc '
    @link: http://support.microsoft.com/en-us/kb/823659
  '
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('LmCompatibilityLevel') { should eq 4 }
  end
end

control 'windows-base-202' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Clients'
  desc 'Enable Strong Encryption for Windows Network Sessions on Clients'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NtlmMinClientSec') { should eq 537_395_200 }
  end
end

control 'windows-base-203' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Servers'
  desc 'Enable Strong Encryption for Windows Network Sessions on Servers'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NtlmMinServerSec') { should eq 537_395_200 }
  end
end
```

9. Run `inspec check .` to validate your profile syntax

## Create a Windows Hardening Cookbook with Chef
In this next section you will create a windows Hardening cookbook that remediates the contols we created in the previous section

1. cd `~/src`
2. `chef generate cookbook <yourcompany>_windows_hardening`
3. `cd <yourcompany>_windows_hardening` 
4. open `<yourcompany>_windows_hardening` in your editor
5. generate a recipe to remediate password_policy controls `chef generate recipe password_policy`
6. Edit `recipes/password_policy.rb` with the following content:

```ruby
#
# Cookbook:: <yourcompany>_windows_hardening
# Recipe:: password_policy
#
# Copyright:: 2019, The Authors, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Set Enforce password history to 24 or more passwords
# cis: enforce-password-history 1.1.1
password_policy 'password_history' do
  policy_command 'uniquepw'
  value 24
  action :set
end

# Set Minimum password age to 1 or more days
# cis: minimum-password-age 1.1.3
password_policy 'password_age' do
  policy_command 'minpwage'
  value 1
  action :set
end

# Set Minimum password length to 14 or more characters
# cis: minimum-password-length 1.1.4
password_policy 'password_length' do
  policy_command 'minpwlen'
  value 14
  action :set
end
```

7. Generate a recipe to remediate access_config `chef generate recipe access_config` 
8. Edit `recipes/access_config.rb` with the following content:
   
```ruby
return unless node['platform_family'] == 'windows'

# Anonymous Access to Windows Shares and Named Pipes is Disallowed
# windows-baseline: windows-base-102
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'RestrictNullSessAccess',
    type: :dword,
    data: 1
  }]
  action :create_if_missing
end

# All Shares are Configured to Prevent Anonymous Access
# windows-baseline: windows-base-103
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'NullSessionShares',
    type: :multi_string,
    data: ['']
  }]
  action :create_if_missing
end

# Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled
# windows-baseline: windows-base-103
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 4
  }]
  action :create
end

# Enable Strong Encryption for Windows Network Sessions on Clients
# windows-baseline: windows-base-201
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NtlmMinClientSec',
    type: :dword,
    data: 537_395_200
  }]
  action :create
end

# Enable Strong Encryption for Windows Network Sessions on Servers
# windows-baseline: windows-base-202
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NtlmMinServerSec',
    type: :dword,
    data: 537_395_200
  }]
  action :create
end

if node['windows_hardening']['smbv1']['disable'] == true
  registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
    values [{
      name: 'SMB1',
      type: :dword,
      data: 0
    }]
    action :create_if_missing
  end
end
```
