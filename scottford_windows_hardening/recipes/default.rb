#
# Cookbook:: scottford_windows_hardening
# Recipe:: default
#
# Copyright:: 2019, The Authors, All Rights Reserved.

include_recipe 'scottford_windows_hardening::access_config'
include_recipe 'scottford_windows_hardening::password_policy'