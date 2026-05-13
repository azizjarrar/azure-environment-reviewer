'use strict';

const findingEngine = require('../src/services/findingEngine');
const assert = require('assert');

/**
 * Basic test suite for the Finding Engine.
 * Run with: node test/findingEngine.test.js
 */

const testIAM = () => {
  console.log('Running IAM tests...');
  const mockResults = {
    iam: [
      { type: 'RoleAssignment', roleName: 'Owner', principalId: 'u1', scope: '/sub' },
      { type: 'RoleAssignment', roleName: 'Owner', principalId: 'u2', scope: '/sub' },
      { type: 'RoleAssignment', roleName: 'Owner', principalId: 'u3', scope: '/sub' },
      { type: 'RoleAssignment', roleName: 'Owner', principalId: 'u4', scope: '/sub' },
      { type: 'RoleAssignment', roleName: 'Owner', principalId: 'guest1', principalType: 'Guest', scope: '/sub' },
      { type: 'ClassicAdministrator', name: 'Legacy Admin', emailAddress: 'admin@old.com', role: 'Co-Administrator' }
    ]
  };

  const findings = findingEngine.analyze(mockResults);
  
  const hasIAM001 = findings.some(f => f.id === 'IAM-001');
  const hasIAM002 = findings.some(f => f.id === 'IAM-002');
  const hasIAM004 = findings.some(f => f.id === 'IAM-004');

  assert(hasIAM001, 'Should detect excessive owners (IAM-001)');
  assert(hasIAM002, 'Should detect guest with elevated role (IAM-002)');
  assert(hasIAM004, 'Should detect classic admins (IAM-004)');
  
  console.log('✅ IAM tests passed');
};

const testNetworking = () => {
  console.log('Running Networking tests...');
  const mockResults = {
    networking: [
      {
        type: 'NetworkSecurityGroup',
        name: 'nsg-open',
        rules: [
          {
            name: 'allow-ssh',
            access: 'Allow',
            direction: 'Inbound',
            sourceAddressPrefix: '*',
            destinationPortRange: '22',
            priority: 100
          }
        ]
      },
      {
        type: 'VirtualNetwork',
        name: 'vnet-1',
        subnets: [
          { name: 'subnet-unprotected', addressPrefix: '10.0.0.0/24', nsgId: null }
        ]
      }
    ]
  };

  const findings = findingEngine.analyze(mockResults);
  
  const hasNET001 = findings.some(f => f.id === 'NET-001');
  const hasNET002 = findings.some(f => f.id === 'NET-002');

  assert(hasNET001, 'Should detect open SSH port (NET-001)');
  assert(hasNET002, 'Should detect subnet without NSG (NET-002)');
  
  console.log('✅ Networking tests passed');
};

const testStorage = () => {
  console.log('Running Storage tests...');
  const mockResults = {
    storage: [
      {
        type: 'StorageAccount',
        name: 'unsecurestorage',
        allowBlobPublicAccess: true,
        enableHttpsTrafficOnly: false,
        minimumTlsVersion: 'TLS1_0'
      }
    ]
  };

  const findings = findingEngine.analyze(mockResults);
  
  const hasSTG001 = findings.some(f => f.id === 'STG-001');
  const hasSTG002 = findings.some(f => f.id === 'STG-002');
  const hasSTG003 = findings.some(f => f.id === 'STG-003');

  assert(hasSTG001, 'Should detect public blob access (STG-001)');
  assert(hasSTG002, 'Should detect HTTP allowed (STG-002)');
  assert(hasSTG003, 'Should detect weak TLS (STG-003)');
  
  console.log('✅ Storage tests passed');
};

try {
  testIAM();
  testNetworking();
  testStorage();
  console.log('\n✨ All Finding Engine tests passed! ✨');
} catch (err) {
  console.error('\n❌ Test failed:');
  console.error(err.message);
  process.exit(1);
}
