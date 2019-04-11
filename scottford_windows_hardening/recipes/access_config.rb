#
# Cookbook:: scottford_windows_hardening
# Recipe:: access_config
#
# Copyright:: 2019, The Authors, All Rights Reserved.
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


registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'SMB1',
    type: :dword,
    data: 0
  }]
  action :create_if_missing
end