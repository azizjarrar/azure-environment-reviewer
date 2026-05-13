targetScope = 'resourceGroup'
param location string = resourceGroup().location

@secure()
param adminPassword string

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'test-vm-nsg'
  location: location
  properties: { securityRules: [] }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'test-vm-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.99.0.0/16'] }
    subnets: [{ name: 'default', properties: { addressPrefix: '10.99.1.0/24', networkSecurityGroup: { id: nsg.id } } }]
  }
}

resource pip 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'test-vm-pip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'test-vm-nic'
  location: location
  properties: {
    ipConfigurations: [{
      name: 'ipconfig1'
      properties: {
        subnet: { id: '${vnet.id}/subnets/default' }
        publicIPAddress: { id: pip.id }
        privateIPAllocationMethod: 'Dynamic'
      }
    }]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'test-vm'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    osProfile: {
      computerName: 'testvm'
      adminUsername: 'azureadmin'
      adminPassword: adminPassword
      linuxConfiguration: { disablePasswordAuthentication: false }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-focal'
        sku: '20_04-lts-gen2'
        version: 'latest'
      }
      osDisk: { createOption: 'FromImage', managedDisk: { storageAccountType: 'Standard_LRS' }, deleteOption: 'Delete' }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id }] }
  }
}
