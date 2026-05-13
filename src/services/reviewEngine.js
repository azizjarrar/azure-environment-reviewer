const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const findingEngine = require('./findingEngine');
const Review        = require('../models/Review');
const ReviewSection = require('../models/ReviewSection');

/**
 * Drains a paged Azure SDK async iterator into a flat array.
 * Swallows errors silently so a permission-denied resource doesn't abort the whole scan.
 * @param {AsyncIterable} pagedIterator - The Azure SDK async iterator
 * @returns {Promise<Array>} - Flat array of collected items
 */
async function collectPages(pagedIterator) {
  const results = [];
  try {
    for await (const item of pagedIterator) results.push(item);
  } catch (err) {
    // We swallow errors here because in many Azure environments, the auditing Service Principal
    // might have Reader access but lack permission for specific sub-resources or hidden types.
    // Rather than crashing the entire scan, we just return what we could get.
  }
  return results;
}

/**
 * Audit IAM and RBAC configurations.
 * @param {Object} clients - Azure SDK clients
 * @param {string} subscriptionId - Target subscription ID
 * @returns {Promise<Array>} - Collected IAM resources and findings
 */
async function checkIAM(clients, subscriptionId) {
  const resources = [];
  const scope = `/subscriptions/${subscriptionId}`;

  const assignments = await collectPages(
    clients.authorization.roleAssignments.listForScope(scope)
  );
  const definitions = await collectPages(
    clients.authorization.roleDefinitions.list(scope)
  );

  const defMap = {};
  for (const d of definitions) defMap[d.id] = { name: d.roleName, type: d.roleType };

  for (const a of assignments) {
    const def = defMap[a.roleDefinitionId] || {};
    resources.push({
      type:          'RoleAssignment',
      principalId:   a.principalId,
      principalType: a.principalType || 'Unknown',
      roleName:      def.name || a.roleDefinitionId,
      roleType:      def.type || null,
      scope:         a.scope,
      condition:     a.condition || null,
      createdOn:     a.createdOn || null,
      updatedOn:     a.updatedOn || null,
    });
  }

  // Custom role definitions — flag for overly broad permissions
  for (const d of definitions) {
    if (d.roleType === 'CustomRole') {
      resources.push({
        type:             'CustomRoleDefinition',
        name:             d.roleName,
        description:      d.description || null,
        assignableScopes: d.assignableScopes || [],
        actions:          d.permissions?.[0]?.actions || [],
        notActions:       d.permissions?.[0]?.notActions || [],
        dataActions:      d.permissions?.[0]?.dataActions || [],
        notDataActions:   d.permissions?.[0]?.notDataActions || [],
      });
    }
  }

  // Classic administrators (legacy co-admin / account admin)
  try {
    const classicAdmins = await collectPages(
      clients.authorization.classicAdministrators.list()
    );
    for (const ca of classicAdmins) {
      resources.push({
        type:       'ClassicAdministrator',
        name:       ca.name,
        emailAddress: ca.emailAddress || null,
        role:       ca.role || null,
      });
    }
  } catch { /* skip */ }

  // User-Assigned Managed Identities
  try {
    const mis = await collectPages(
      clients.resources.resources.list({
        filter: "resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'"
      })
    );
    for (const mi of mis) {
      resources.push({
        type:          'ManagedIdentity',
        name:          mi.name,
        location:      mi.location,
        resourceGroup: mi.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
      });
    }
  } catch { /* skip */ }

  // Deny Assignments — explicit deny rules that override role assignments
  try {
    const denyList = await collectPages(
      clients.authorization.denyAssignments.listForSubscription()
    );
    for (const da of denyList) {
      resources.push({
        type:                    'DenyAssignment',
        name:                    da.denyAssignmentName || da.name,
        scope:                   da.scope || null,
        isSystemProtected:       da.isSystemProtected ?? null,
        doNotApplyToChildScopes: da.doNotApplyToChildScopes ?? null,
        principalCount:          (da.principals || []).length,
        excludePrincipalCount:   (da.excludePrincipals || []).length,
        deniedActions:           (da.permissions || []).flatMap(p => p.actions || []),
        deniedNotActions:        (da.permissions || []).flatMap(p => p.notActions || []),
      });
    }
  } catch { /* deny assignments may not be accessible with current permissions */ }

  // PIM — Active role assignment schedules (time-bound active assignments)
  try {
    const activeSchedules = await collectPages(
      clients.authorization.roleAssignmentSchedules.listForScope(scope)
    );
    for (const s of activeSchedules) {
      resources.push({
        type:             'PIMActiveAssignment',
        principalId:      s.principalId || null,
        principalType:    s.principalType || null,
        roleDefinitionId: s.roleDefinitionId || null,
        scope:            s.scope || null,
        assignmentType:   s.assignmentType || null,  // Assigned (direct) vs Activated (via PIM)
        memberType:       s.memberType || null,       // Direct / Group / ServicePrincipal
        startDateTime:    s.startDateTime || null,
        endDateTime:      s.endDateTime || null,      // null = permanent
        status:           s.status || null,
      });
    }
  } catch { /* PIM may not be enabled or requires additional permissions */ }

  // PIM — Eligible role schedules (who can elevate to which role)
  try {
    const eligibleSchedules = await collectPages(
      clients.authorization.roleEligibilitySchedules.listForScope(scope)
    );
    for (const s of eligibleSchedules) {
      resources.push({
        type:             'PIMEligibleAssignment',
        principalId:      s.principalId || null,
        principalType:    s.principalType || null,
        roleDefinitionId: s.roleDefinitionId || null,
        scope:            s.scope || null,
        memberType:       s.memberType || null,
        startDateTime:    s.startDateTime || null,
        endDateTime:      s.endDateTime || null,
        status:           s.status || null,
      });
    }
  } catch { /* PIM may not be enabled or requires additional permissions */ }

  return resources;
}

// ─── 2. Networking ──────────────────────────────────────────────────────────
async function checkNetworking(clients) {
  const resources = [];

  // NSGs — custom + default rules
  const nsgs = await collectPages(clients.network.networkSecurityGroups.listAll());
  for (const nsg of nsgs) {
    const mapRule = r => ({
      name:                      r.name,
      direction:                 r.direction,
      access:                    r.access,
      priority:                  r.priority,
      protocol:                  r.protocol,
      sourceAddressPrefix:       r.sourceAddressPrefix,
      sourceAddressPrefixes:     r.sourceAddressPrefixes || [],
      destinationAddressPrefix:  r.destinationAddressPrefix,
      destinationPortRange:      r.destinationPortRange,
      destinationPortRanges:     r.destinationPortRanges || [],
    });
    resources.push({
      type:                'NetworkSecurityGroup',
      name:                nsg.name,
      location:            nsg.location,
      resourceGroup:       nsg.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
      rules:               (nsg.securityRules || []).map(mapRule),
      defaultRules:        (nsg.defaultSecurityRules || []).map(mapRule),
      subnetAssociations:  (nsg.subnets || []).map(s => s.id),
      nicAssociations:     (nsg.networkInterfaces || []).map(n => n.id),
    });
  }

  // Public IPs
  const publicIPs = await collectPages(clients.network.publicIPAddresses.listAll());
  for (const ip of publicIPs) {
    resources.push({
      type:              'PublicIPAddress',
      name:              ip.name,
      location:          ip.location,
      ipAddress:         ip.ipAddress || 'unallocated',
      sku:               ip.sku?.name || null,
      allocationMethod:  ip.publicIPAllocationMethod || null,
      attached:          !!ip.ipConfiguration,
      attachedTo:        ip.ipConfiguration?.id || null,
      ddosProtection:    ip.ddosSettings?.protectionMode || null,
    });
  }

  // Virtual Networks
  try {
    const vnets = await collectPages(clients.network.virtualNetworks.listAll());
    for (const vnet of vnets) {
      resources.push({
        type:             'VirtualNetwork',
        name:             vnet.name,
        location:         vnet.location,
        addressSpaces:    vnet.addressSpace?.addressPrefixes || [],
        ddosProtection:   vnet.enableDdosProtection ?? false,
        vmProtection:     vnet.enableVmProtection ?? false,
        peerings:         (vnet.virtualNetworkPeerings || []).map(p => ({
          name:                 p.name,
          remoteVnet:           p.remoteVirtualNetwork?.id || null,
          state:                p.peeringState || null,
          allowForwardedTraffic: p.allowForwardedTraffic ?? false,
          allowGatewayTransit:  p.allowGatewayTransit ?? false,
          useRemoteGateways:    p.useRemoteGateways ?? false,
        })),
        subnets:          (vnet.subnets || []).map(s => ({
          name:           s.name,
          addressPrefix:  s.addressPrefix || null,
          nsgId:          s.networkSecurityGroup?.id || null,
          routeTableId:   s.routeTable?.id || null,
          privateEndpointNetworkPolicies: s.privateEndpointNetworkPolicies || null,
          serviceEndpoints: (s.serviceEndpoints || []).map(e => e.service),
        })),
      });
    }
  } catch { /* skip */ }

  // Azure Firewalls
  try {
    const firewalls = await collectPages(clients.network.azureFirewalls.listAll());
    for (const fw of firewalls) {
      resources.push({
        type:             'AzureFirewall',
        name:             fw.name,
        location:         fw.location,
        sku:              fw.sku?.name || null,
        tier:             fw.sku?.tier || null,
        threatIntelMode:  fw.threatIntelMode || null,
        provisioningState: fw.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Application Gateways
  try {
    const appGateways = await collectPages(clients.network.applicationGateways.listAll());
    for (const ag of appGateways) {
      resources.push({
        type:              'ApplicationGateway',
        name:              ag.name,
        location:          ag.location,
        sku:               ag.sku?.name || null,
        tier:              ag.sku?.tier || null,
        wafEnabled:        ag.webApplicationFirewallConfiguration?.enabled ?? false,
        wafMode:           ag.webApplicationFirewallConfiguration?.firewallMode || null,
        sslPolicy:         ag.sslPolicy?.policyName || null,
        provisioningState: ag.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Load Balancers
  try {
    const lbs = await collectPages(clients.network.loadBalancers.listAll());
    for (const lb of lbs) {
      resources.push({
        type:     'LoadBalancer',
        name:     lb.name,
        location: lb.location,
        sku:      lb.sku?.name || null,
        frontendIPs: (lb.frontendIPConfigurations || []).map(f => ({
          name:      f.name,
          publicIP:  f.publicIPAddress?.id || null,
          privateIP: f.privateIPAddress || null,
        })),
        probeCount:          (lb.probes || []).length,
        loadBalancingRules:  (lb.loadBalancingRules || []).length,
        inboundNatRules:     (lb.inboundNatRules || []).length,
      });
    }
  } catch { /* skip */ }

  // VPN Gateways
  try {
    const vpnGateways = await collectPages(clients.network.virtualNetworkGateways.listAll());
    for (const gw of vpnGateways) {
      resources.push({
        type:              'VPNGateway',
        name:              gw.name,
        location:          gw.location,
        gatewayType:       gw.gatewayType || null,
        vpnType:           gw.vpnType || null,
        sku:               gw.sku?.name || null,
        enableBgp:         gw.enableBgp ?? false,
        activeActive:      gw.activeActive ?? false,
        provisioningState: gw.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Private Endpoints
  try {
    const pes = await collectPages(clients.network.privateEndpoints.listBySubscription());
    for (const pe of pes) {
      resources.push({
        type:             'PrivateEndpoint',
        name:             pe.name,
        location:         pe.location,
        resourceGroup:    pe.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        subnetId:         pe.subnet?.id || null,
        targetResourceId: pe.privateLinkServiceConnections?.[0]?.privateLinkServiceId || null,
        groupIds:         pe.privateLinkServiceConnections?.[0]?.groupIds || [],
        connectionState:  pe.privateLinkServiceConnections?.[0]?.privateLinkServiceConnectionState?.status || null,
        provisioningState: pe.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Route Tables
  try {
    const rts = await collectPages(clients.network.routeTables.listAll());
    for (const rt of rts) {
      resources.push({
        type:          'RouteTable',
        name:          rt.name,
        location:      rt.location,
        resourceGroup: rt.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        routes:        (rt.routes || []).map(r => ({
          name:             r.name,
          addressPrefix:    r.addressPrefix || null,
          nextHopType:      r.nextHopType || null,
          nextHopIpAddress: r.nextHopIpAddress || null,
        })),
        disableBgpRoutePropagation: rt.disableBgpRoutePropagation ?? false,
        subnetCount:   (rt.subnets || []).length,
      });
    }
  } catch { /* skip */ }

  // Bastion Hosts
  try {
    const bastions = await collectPages(clients.network.bastionHosts.listAll());
    for (const b of bastions) {
      resources.push({
        type:              'BastionHost',
        name:              b.name,
        location:          b.location,
        resourceGroup:     b.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        sku:               b.sku?.name || null,
        scaleUnits:        b.scaleUnits || null,
        provisioningState: b.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // DDoS Protection Plans
  try {
    const ddosPlans = await collectPages(clients.network.ddosProtectionPlans.list());
    for (const d of ddosPlans) {
      resources.push({
        type:                'DDoSProtectionPlan',
        name:                d.name,
        location:            d.location,
        resourceGroup:       d.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        virtualNetworkCount: (d.virtualNetworks || []).length,
        provisioningState:   d.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Network Interfaces — flag any with a directly-attached public IP
  try {
    const nics = await collectPages(clients.network.networkInterfaces.listAll());
    for (const nic of nics) {
      const publicIpConfigs = (nic.ipConfigurations || []).filter(ip => ip.publicIPAddress);
      resources.push({
        type:                  'NetworkInterface',
        name:                  nic.name,
        location:              nic.location,
        resourceGroup:         nic.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        attachedToVm:          nic.virtualMachine?.id || null,
        nsgId:                 nic.networkSecurityGroup?.id || null,
        hasPublicIp:           publicIpConfigs.length > 0,
        publicIpIds:           publicIpConfigs.map(ip => ip.publicIPAddress.id),
        enableIpForwarding:    nic.enableIPForwarding ?? false,
        acceleratedNetworking: nic.enableAcceleratedNetworking ?? false,
      });
    }
  } catch { /* skip */ }

  // Network Watchers + NSG Flow Logs
  try {
    const watchers = await collectPages(clients.network.networkWatchers.listAll());
    for (const nw of watchers) {
      const nwRg = nw.id?.split('/resourceGroups/')[1]?.split('/')[0];
      if (!nwRg) continue;
      try {
        const flowLogs = await collectPages(clients.network.flowLogs.list(nwRg, nw.name));
        for (const fl of flowLogs) {
          resources.push({
            type:             'NSGFlowLog',
            name:             fl.name,
            location:         fl.location,
            targetNsgId:      fl.targetResourceId || null,
            enabled:          fl.enabled ?? false,
            retentionDays:    fl.retentionPolicy?.days ?? null,
            retentionEnabled: fl.retentionPolicy?.enabled ?? false,
            storageAccountId: fl.storageId || null,
            trafficAnalyticsEnabled: fl.flowAnalyticsConfiguration?.networkWatcherFlowAnalyticsConfiguration?.enabled ?? false,
          });
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }

  // WAF Policies (standalone — separate from Application Gateway inline WAF)
  try {
    const wafPolicies = await collectPages(clients.network.webApplicationFirewallPolicies.listAll());
    for (const waf of wafPolicies) {
      resources.push({
        type:              'WAFPolicy',
        name:              waf.name,
        location:          waf.location,
        resourceGroup:     waf.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        policyState:       waf.policySettings?.state || null,         // Enabled / Disabled
        policyMode:        waf.policySettings?.mode || null,          // Detection / Prevention
        requestBodyCheck:  waf.policySettings?.requestBodyCheck ?? null,
        maxRequestBodySizeInKb: waf.policySettings?.maxRequestBodySizeInKb || null,
        managedRules:      (waf.managedRules?.managedRuleSets || []).map(r => ({
          ruleSetType:    r.ruleSetType,
          ruleSetVersion: r.ruleSetVersion,
        })),
        customRuleCount:   (waf.customRules || []).length,
        provisioningState: waf.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Azure Firewall Policies (IDPS, threat intelligence — separate from AzureFirewall resource)
  try {
    const firewallPolicies = await collectPages(clients.network.firewallPolicies.listAll());
    for (const fp of firewallPolicies) {
      resources.push({
        type:             'FirewallPolicy',
        name:             fp.name,
        location:         fp.location,
        resourceGroup:    fp.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        threatIntelMode:  fp.threatIntelMode || null,  // Alert / Deny / Off
        idpsMode:         fp.intrusionDetection?.mode || null,  // Alert / Deny / Off
        dnsProxy:         fp.dnsSettings?.enableProxy ?? false,
        dnsServers:       fp.dnsSettings?.servers || [],
        sku:              fp.sku?.tier || null,
        provisioningState: fp.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // ExpressRoute Circuits (hybrid on-premises connectivity)
  try {
    const erCircuits = await collectPages(clients.network.expressRouteCircuits.list());
    for (const er of erCircuits) {
      resources.push({
        type:                            'ExpressRouteCircuit',
        name:                            er.name,
        location:                        er.location,
        resourceGroup:                   er.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        skuName:                         er.sku?.name || null,
        skuTier:                         er.sku?.tier || null,   // Local / Standard / Premium
        skuFamily:                       er.sku?.family || null, // MeteredData / UnlimitedData
        serviceProviderName:             er.serviceProviderProperties?.serviceProviderName || null,
        peeringLocation:                 er.serviceProviderProperties?.peeringLocation || null,
        bandwidthInMbps:                 er.serviceProviderProperties?.bandwidthInMbps || null,
        circuitProvisioningState:        er.circuitProvisioningState || null,
        serviceProviderProvisioningState: er.serviceProviderProvisioningState || null,
        peerings:                        (er.peerings || []).map(p => ({
          name:        p.name,
          peeringType: p.peeringType,
          state:       p.state,
        })),
        globalReachEnabled:              er.globalReachEnabled ?? false,
      });
    }
  } catch { /* skip */ }

  // Service Endpoint Policies (restrict service endpoints to specific resources)
  try {
    const sePolicies = await collectPages(clients.network.serviceEndpointPolicies.list());
    for (const sep of sePolicies) {
      resources.push({
        type:          'ServiceEndpointPolicy',
        name:          sep.name,
        location:      sep.location,
        resourceGroup: sep.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        subnetCount:   (sep.subnets || []).length,
        definitions:   (sep.serviceEndpointPolicyDefinitions || []).map(d => ({
          service:          d.service || null,
          resourceCount:    (d.serviceResources || []).length,
        })),
        provisioningState: sep.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // NAT Gateways (outbound connectivity — important for egress traffic audit)
  try {
    const natGateways = await collectPages(clients.network.natGateways.listAll());
    for (const nat of natGateways) {
      resources.push({
        type:                 'NATGateway',
        name:                 nat.name,
        location:             nat.location,
        resourceGroup:        nat.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        sku:                  nat.sku?.name || null,
        idleTimeoutInMinutes: nat.idleTimeoutInMinutes || null,
        publicIpAddressCount: (nat.publicIpAddresses || []).length,
        publicIpPrefixCount:  (nat.publicIpPrefixes || []).length,
        subnetCount:          (nat.subnets || []).length,
        provisioningState:    nat.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  return resources;
}

// ─── 3. Storage ─────────────────────────────────────────────────────────────
async function checkStorage(clients) {
  const resources = [];

  const accounts = await collectPages(clients.storage.storageAccounts.list());
  for (const a of accounts) {
    const rgName = a.id.split('/resourceGroups/')[1].split('/')[0];
    const resource = {
      type:                           'StorageAccount',
      name:                           a.name,
      location:                       a.location,
      kind:                           a.kind,
      sku:                            a.sku?.name,
      allowBlobPublicAccess:          a.allowBlobPublicAccess ?? true,
      publicNetworkAccess:            a.publicNetworkAccess || 'Enabled',
      networkDefaultAction:           a.networkRuleSet?.defaultAction || 'Allow',
      enableHttpsTrafficOnly:         a.enableHttpsTrafficOnly ?? false,
      minimumTlsVersion:              a.minimumTlsVersion || 'TLS1_0',
      allowSharedKeyAccess:           a.allowSharedKeyAccess ?? true,
      requireInfrastructureEncryption: a.encryption?.requireInfrastructureEncryption ?? false,
      blobSoftDeleteEnabled:          null,
      blobSoftDeleteRetentionDays:    null,
      containers: [],
    };

    try {
      const blobService = await clients.storage.blobServices.getServiceProperties(rgName, a.name);
      resource.blobSoftDeleteEnabled      = blobService.deleteRetentionPolicy?.enabled ?? false;
      resource.blobSoftDeleteRetentionDays = blobService.deleteRetentionPolicy?.days ?? null;
    } catch { /* skip accounts where blob properties are inaccessible */ }

    try {
      const containers = await collectPages(clients.storage.blobContainers.list(rgName, a.name));
      resource.containers = containers.map(c => ({
        name:            c.name,
        publicAccess:    c.publicAccess || 'None',
        hasImmutability: c.hasImmutabilityPolicy ?? false,
        hasLegalHold:    c.hasLegalHold ?? false,
        leaseStatus:     c.leaseStatus || null,
        leaseState:      c.leaseState || null,
      }));
    } catch { /* skip accounts where container listing is inaccessible */ }

    // File Shares (SMB / NFS)
    try {
      const shares = await collectPages(clients.storage.fileShares.list(rgName, a.name));
      resource.fileShares = shares.map(s => ({
        name:             s.name,
        shareQuotaGb:     s.shareQuota || null,
        enabledProtocols: s.enabledProtocols || 'SMB',  // SMB or NFS
        accessTier:       s.accessTier || null,
        snapshotCount:    s.snapshotCount || null,
        deleted:          s.deleted ?? false,
        leaseStatus:      s.leaseStatus || null,
      }));
    } catch { resource.fileShares = []; }

    // Encryption Scopes (per-container or per-blob CMK vs PMK)
    try {
      const scopes = await collectPages(clients.storage.encryptionScopes.list(rgName, a.name));
      resource.encryptionScopes = scopes.map(s => ({
        name:                          s.name,
        keyType:                       s.keyVaultProperties ? 'CustomerManagedKey' : 'MicrosoftManagedKey',
        keyVaultUri:                   s.keyVaultProperties?.keyUri || null,
        state:                         s.state || null,  // Enabled / Disabled
        requireInfrastructureEncryption: s.requireInfrastructureEncryption ?? false,
        creationTime:                  s.creationTime || null,
      }));
    } catch { resource.encryptionScopes = []; }

    // Lifecycle Management Policy (data retention and tiering rules)
    try {
      const lcp = await clients.storage.managementPolicies.get(rgName, a.name, 'default');
      resource.lifecyclePolicy = {
        ruleCount: (lcp.policy?.rules || []).length,
        rules:     (lcp.policy?.rules || []).map(r => ({
          name:               r.name,
          enabled:            r.enabled ?? true,
          tierToCoolDays:     r.definition?.actions?.baseBlob?.tierToCool?.daysAfterModificationGreaterThan || null,
          tierToArchiveDays:  r.definition?.actions?.baseBlob?.tierToArchive?.daysAfterModificationGreaterThan || null,
          deleteAfterDays:    r.definition?.actions?.baseBlob?.delete?.daysAfterModificationGreaterThan || null,
          snapshotDeleteDays: r.definition?.actions?.snapshot?.delete?.daysAfterCreationGreaterThan || null,
        })),
      };
    } catch { resource.lifecyclePolicy = null; }

    // SFTP Local Users (password / key auth for SFTP-enabled accounts)
    try {
      const localUsers = await collectPages(clients.storage.localUsersOperations.list(rgName, a.name));
      resource.localUsers = localUsers.map(u => ({
        name:             u.name,
        hasSshPassword:   u.hasSshPassword ?? false,
        hasSshKey:        u.hasSshKey ?? false,
        hasSharedKey:     u.hasSharedKey ?? false,
        homeDirectory:    u.homeDirectory || null,
        permissionScopes: (u.permissionScopes || []).map(ps => ({
          permissions:  ps.permissions,
          service:      ps.service,
          resourceName: ps.resourceName,
        })),
      }));
    } catch { resource.localUsers = []; }

    resources.push(resource);
  }

  return resources;
}

// ─── 4. Compute ─────────────────────────────────────────────────────────────
async function checkCompute(clients) {
  const resources = [];

  // Virtual Machines
  const vms = await collectPages(clients.compute.virtualMachines.listAll());
  for (const vm of vms) {
    const osDisk = vm.storageProfile?.osDisk || {};
    const resource = {
      type:                    'VirtualMachine',
      name:                    vm.name,
      location:                vm.location,
      size:                    vm.hardwareProfile?.vmSize || null,
      osType:                  osDisk.osType || null,
      osDiskType:              osDisk.vhd ? 'unmanaged' : 'managed',
      diskEncryptionExtension: false,
    };
    try {
      const rgName = vm.id.split('/resourceGroups/')[1].split('/')[0];
      const extensions = await collectPages(
        clients.compute.virtualMachineExtensions.list(rgName, vm.name)
      );
      resource.diskEncryptionExtension = extensions.some(e =>
        e.virtualMachineExtensionType === 'AzureDiskEncryption' ||
        e.virtualMachineExtensionType === 'AzureDiskEncryptionForLinux'
      );
    } catch { /* skip */ }
    resources.push(resource);
  }

  // App Services + Function Apps
  try {
    const webApps = await collectPages(clients.web.webApps.list());
    for (const app of webApps) {
      const rgName = app.id?.split('/resourceGroups/')[1]?.split('/')[0] || '';
      let authEnabled = null;
      try {
        const auth = await clients.web.webApps.getAuthSettings(rgName, app.name);
        authEnabled = auth.enabled ?? null;
      } catch { /* skip */ }
      resources.push({
        type:             app.kind?.includes('functionapp') ? 'FunctionApp' : 'AppService',
        name:             app.name,
        location:         app.location,
        kind:             app.kind || null,
        state:            app.state || null,
        httpsOnly:        app.httpsOnly ?? false,
        clientCertEnabled: app.clientCertEnabled ?? false,
        publicNetworkAccess: app.publicNetworkAccess || 'Enabled',
        ftpsState:        app.siteConfig?.ftpsState || null,
        minTlsVersion:    app.siteConfig?.minTlsVersion || null,
        http20Enabled:    app.siteConfig?.http20Enabled ?? false,
        authEnabled,
      });
    }
  } catch { /* skip */ }

  // Container Instances (ACI)
  try {
    const containerGroups = await collectPages(clients.containerInstance.containerGroups.list());
    for (const cg of containerGroups) {
      resources.push({
        type:          'ContainerInstance',
        name:          cg.name,
        location:      cg.location,
        osType:        cg.osType || null,
        restartPolicy: cg.restartPolicy || null,
        ipAddress:     cg.ipAddress?.ip || null,
        publicIP:      cg.ipAddress?.type === 'Public',
        containers:    (cg.containers || []).map(c => ({
          name:   c.name,
          image:  c.image,
          cpu:    c.resources?.requests?.cpu || null,
          memory: c.resources?.requests?.memoryInGB || null,
        })),
      });
    }
  } catch { /* skip */ }

  // Container Apps
  try {
    const containerApps = await collectPages(clients.containerApps.containerApps.list());
    for (const app of containerApps) {
      resources.push({
        type:              'ContainerApp',
        name:              app.name,
        location:          app.location,
        provisioningState: app.provisioningState || null,
        ingressExternal:   app.configuration?.ingress?.external ?? null,
        ingressTargetPort: app.configuration?.ingress?.targetPort || null,
        latestRevision:    app.latestRevisionName || null,
      });
    }
  } catch { /* skip */ }

  // AKS Clusters + node pool details
  try {
    const clusters = await collectPages(clients.aks.managedClusters.list());
    for (const cluster of clusters) {
      const rgName = cluster.id?.split('/resourceGroups/')[1]?.split('/')[0] || '';
      let nodePools = [];
      try {
        const pools = await collectPages(clients.aks.agentPools.list(rgName, cluster.name));
        nodePools = pools.map(p => ({
          name:              p.name,
          osType:            p.osType || null,
          vmSize:            p.vmSize || null,
          count:             p.count ?? null,
          mode:              p.mode || null,
          osDiskSizeGb:      p.osDiskSizeGb || null,
          enableAutoScaling: p.enableAutoScaling ?? false,
          enableNodePublicIp: p.enableNodePublicIp ?? false,
          nodeTaints:        p.nodeTaints || [],
          provisioningState: p.provisioningState || null,
        }));
      } catch { /* skip — insufficient permission on node pools */ }

      resources.push({
        type:                  'AKSCluster',
        name:                  cluster.name,
        location:              cluster.location,
        kubernetesVersion:     cluster.kubernetesVersion || null,
        provisioningState:     cluster.provisioningState || null,
        rbacEnabled:           cluster.enableRbac ?? null,
        nodeCount:             cluster.agentPoolProfiles?.[0]?.count || null,
        networkPlugin:         cluster.networkProfile?.networkPlugin || null,
        networkPolicy:         cluster.networkProfile?.networkPolicy || null,
        apiServerPublicAccess: !(cluster.apiServerAccessProfile?.enablePrivateCluster ?? false),
        authorizedIpRanges:    cluster.apiServerAccessProfile?.authorizedIpRanges || [],
        aadEnabled:            !!(cluster.aadProfile),
        nodePools,
      });
    }
  } catch { /* skip */ }

  // Managed Disks
  try {
    const disks = await collectPages(clients.compute.disks.list());
    for (const d of disks) {
      resources.push({
        type:                'ManagedDisk',
        name:                d.name,
        location:            d.location,
        diskSizeGb:          d.diskSizeGB || null,
        osType:              d.osType || null,
        diskState:           d.diskState || null,
        encryptionType:      d.encryption?.type || null,
        diskEncryptionSetId: d.encryption?.diskEncryptionSetId || null,
        publicNetworkAccess: d.publicNetworkAccess || null,
        networkAccessPolicy: d.networkAccessPolicy || null,
        sku:                 d.sku?.name || null,
      });
    }
  } catch { /* skip */ }

  // VM Scale Sets
  try {
    const scaleSets = await collectPages(clients.compute.virtualMachineScaleSets.listAll());
    for (const ss of scaleSets) {
      resources.push({
        type:              'VMScaleSet',
        name:              ss.name,
        location:          ss.location,
        sku:               ss.sku?.name || null,
        capacity:          ss.sku?.capacity ?? null,
        provisioningState: ss.provisioningState || null,
        upgradePolicy:     ss.upgradePolicy?.mode || null,
        overprovision:     ss.overprovision ?? null,
      });
    }
  } catch { /* skip */ }

  // SQL Servers + Databases
  try {
    const sqlServers = await collectPages(clients.sql.servers.list());
    for (const server of sqlServers) {
      const rgName = server.id?.split('/resourceGroups/')[1]?.split('/')[0] || '';
      const sqlResource = {
        type:                'SQLServer',
        name:                server.name,
        location:            server.location,
        fqdn:                server.fullyQualifiedDomainName || null,
        version:             server.version || null,
        publicNetworkAccess: server.publicNetworkAccess || null,
        minimalTlsVersion:   server.minimalTlsVersion || null,
        databases:           [],
        auditingEnabled:     null,
        firewallRules:       [],
        adAdminConfigured:   false,
      };

      try {
        const dbs = await collectPages(clients.sql.databases.listByServer(rgName, server.name));
        sqlResource.databases = await Promise.all(
          dbs.filter(db => db.name !== 'master').map(async db => {
            const [tde, dm, backup, labels] = await Promise.all([
              clients.sql.transparentDataEncryptions.get(rgName, server.name, db.name).catch(() => null),
              clients.sql.dataMaskingPolicies.get(rgName, server.name, db.name, 'Default').catch(() => null),
              clients.sql.backupShortTermRetentionPolicies.get(rgName, server.name, db.name, 'default').catch(() => null),
              collectPages(clients.sql.sensitivityLabels.listCurrentByDatabase(rgName, server.name, db.name)).catch(() => []),
            ]);
            return {
              name:                 db.name,
              status:               db.status || null,
              sku:                  db.sku?.name || null,
              zoneRedundant:        db.zoneRedundant ?? null,
              tdeEnabled:           tde ? tde.status === 'Enabled' : null,
              dataMaskingEnabled:   dm ? dm.dataMaskingState === 'Enabled' : null,
              backupRetentionDays:  backup?.retentionDays || null,
              sensitivityLabelCount: labels.length,
            };
          })
        );
      } catch { /* skip */ }

      try {
        const audit = await clients.sql.serverBlobAuditingPolicies.get(rgName, server.name);
        sqlResource.auditingEnabled = audit.state === 'Enabled';
      } catch { /* skip */ }

      try {
        const fwRules = await collectPages(clients.sql.firewallRules.listByServer(rgName, server.name));
        sqlResource.firewallRules = fwRules.map(r => ({
          name:                  r.name,
          startIpAddress:        r.startIpAddress,
          endIpAddress:          r.endIpAddress,
          allowAllAzureServices: r.startIpAddress === '0.0.0.0' && r.endIpAddress === '0.0.0.0',
        }));
      } catch { /* skip */ }

      try {
        const admins = await collectPages(
          clients.sql.serverAzureADAdministrators.listByServer(rgName, server.name)
        );
        sqlResource.adAdminConfigured = admins.length > 0;
      } catch { /* skip */ }

      // Security posture — run all per-server checks in parallel
      const [threatDetect, atp, va, aadOnly, encProtector, vnetRules, connPolicy] = await Promise.all([
        clients.sql.serverSecurityAlertPolicies.get(rgName, server.name, 'Default').catch(() => null),
        clients.sql.serverAdvancedThreatProtectionSettings.get(rgName, server.name, 'Default').catch(() => null),
        clients.sql.serverVulnerabilityAssessments.get(rgName, server.name, 'default').catch(() => null),
        clients.sql.serverAzureADOnlyAuthentications.get(rgName, server.name, 'Default').catch(() => null),
        clients.sql.encryptionProtectors.get(rgName, server.name, 'current').catch(() => null),
        collectPages(clients.sql.virtualNetworkRules.listByServer(rgName, server.name)).catch(() => []),
        clients.sql.serverConnectionPolicies.get(rgName, server.name, 'default').catch(() => null),
      ]);

      sqlResource.threatDetectionEnabled  = threatDetect ? threatDetect.state === 'Enabled' : null;
      sqlResource.threatDetectionEmails   = threatDetect?.emailAddresses || [];
      sqlResource.atpEnabled              = atp ? atp.state === 'Enabled' : null;
      sqlResource.vaStorageConfigured     = !!(va?.storageContainerPath);
      sqlResource.aadOnlyAuthEnabled      = aadOnly?.azureAdOnlyAuthentication ?? null;
      sqlResource.tdeKeyType              = encProtector?.serverKeyType || null;  // ServiceManaged vs AzureKeyVault
      sqlResource.tdeKeyUri               = encProtector?.uri || null;
      sqlResource.vnetRules               = vnetRules.map(r => ({
        name:     r.name,
        subnetId: r.virtualNetworkSubnetId,
        state:    r.state || null,
      }));
      sqlResource.connectionPolicy        = connPolicy?.connectionType || null;  // Default / Proxy / Redirect

      resources.push(sqlResource);
    }
  } catch { /* skip */ }

  // SQL Managed Instances
  try {
    const managedInstances = await collectPages(clients.sql.managedInstances.list());
    for (const mi of managedInstances) {
      resources.push({
        type:                'SQLManagedInstance',
        name:                mi.name,
        location:            mi.location,
        sku:                 mi.sku?.name || null,
        vCores:              mi.vCores || null,
        storageSizeInGb:     mi.storageSizeInGB || null,
        publicDataEndpointEnabled: mi.publicDataEndpointEnabled ?? false,
        minimalTlsVersion:   mi.minimalTlsVersion || null,
        proxyOverride:       mi.proxyOverride || null,
        provisioningState:   mi.provisioningState || null,
        subnetId:            mi.subnetId || null,
        licenseType:         mi.licenseType || null,
        zoneRedundant:       mi.zoneRedundant ?? false,
      });
    }
  } catch { /* skip — not all subscriptions have SQL MI */ }

  // Container Registries
  try {
    const registries = await collectPages(clients.containerRegistry.registries.list());
    for (const reg of registries) {
      resources.push({
        type:                 'ContainerRegistry',
        name:                 reg.name,
        location:             reg.location,
        sku:                  reg.sku?.name || null,
        loginServer:          reg.loginServer || null,
        adminUserEnabled:     reg.adminUserEnabled ?? false,
        publicNetworkAccess:  reg.publicNetworkAccess || null,
        networkDefaultAction: reg.networkRuleSet?.defaultAction || null,
        encryptionStatus:     reg.encryption?.status || null,
        zoneRedundancy:       reg.zoneRedundancy || null,
        provisioningState:    reg.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Snapshots (unencrypted or public-access snapshots are a data exfiltration risk)
  try {
    const snapshots = await collectPages(clients.compute.snapshots.list());
    for (const snap of snapshots) {
      resources.push({
        type:                'Snapshot',
        name:                snap.name,
        location:            snap.location,
        resourceGroup:       snap.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        diskSizeGb:          snap.diskSizeGB || null,
        osType:              snap.osType || null,
        encryptionType:      snap.encryption?.type || null,
        diskEncryptionSetId: snap.encryption?.diskEncryptionSetId || null,
        publicNetworkAccess: snap.publicNetworkAccess || null,  // Enabled / Disabled
        networkAccessPolicy: snap.networkAccessPolicy || null,
        timeCreated:         snap.timeCreated || null,
      });
    }
  } catch { /* skip */ }

  // Disk Encryption Sets (CMK usage for managed disks)
  try {
    const encSets = await collectPages(clients.compute.diskEncryptionSets.list());
    for (const des of encSets) {
      resources.push({
        type:                              'DiskEncryptionSet',
        name:                             des.name,
        location:                         des.location,
        resourceGroup:                    des.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        encryptionType:                   des.encryptionType || null,
        keyVaultKeyUrl:                   des.activeKey?.keyUrl || null,
        rotationToLatestKeyVersionEnabled: des.rotationToLatestKeyVersionEnabled ?? false,
        autoKeyRotationError:             des.autoKeyRotationError?.message || null,
        provisioningState:                des.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // Disk Accesses (private endpoints for disk import/export — prevents public export)
  try {
    const diskAccesses = await collectPages(clients.compute.diskAccesses.list());
    for (const da of diskAccesses) {
      resources.push({
        type:                         'DiskAccess',
        name:                         da.name,
        location:                     da.location,
        resourceGroup:                da.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        privateEndpointConnectionCount: (da.privateEndpointConnections || []).length,
        provisioningState:            da.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // SSH Public Keys (centrally managed — audit their existence and distribution)
  try {
    const sshKeys = await collectPages(clients.compute.sshPublicKeys.listBySubscription());
    for (const key of sshKeys) {
      resources.push({
        type:          'SSHPublicKey',
        name:          key.name,
        location:      key.location,
        resourceGroup: key.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        hasPublicKey:  !!key.publicKey,
      });
    }
  } catch { /* skip */ }

  // App Service Plans (tier determines compute isolation — Isolated = ASE, Shared = multi-tenant)
  try {
    const plans = await collectPages(clients.web.appServicePlans.list());
    for (const plan of plans) {
      resources.push({
        type:              'AppServicePlan',
        name:              plan.name,
        location:          plan.location,
        resourceGroup:     plan.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        sku:               plan.sku?.name || null,
        tier:              plan.sku?.tier || null,  // Free / Shared / Basic / Standard / Premium / Isolated
        kind:              plan.kind || null,
        numberOfWorkers:   plan.numberOfWorkers || null,
        numberOfSites:     plan.numberOfSites || null,
        isXenon:           plan.isXenon ?? false,
        perSiteScaling:    plan.perSiteScaling ?? false,
        provisioningState: plan.provisioningState || null,
      });
    }
  } catch { /* skip */ }

  // App Service Certificates (SSL/TLS — expiry and Key Vault binding)
  try {
    const certs = await collectPages(clients.web.certificates.list());
    for (const cert of certs) {
      resources.push({
        type:               'AppServiceCertificate',
        name:               cert.name,
        location:           cert.location,
        resourceGroup:      cert.id?.split('/resourceGroups/')[1]?.split('/')[0] || '',
        subjectName:        cert.subjectName || null,
        expirationDate:     cert.expirationDate || null,
        issuer:             cert.issuer || null,
        thumbprint:         cert.thumbprint || null,
        keyVaultId:         cert.keyVaultId || null,
        keyVaultSecretName: cert.keyVaultSecretName || null,
        hostNameCount:      (cert.hostNames || []).length,
      });
    }
  } catch { /* skip */ }

  return resources;
}

// ─── 5. Security Center / Defender ──────────────────────────────────────────
async function checkSecurityCenter(clients, subscriptionId) {
  const resources = [];

  try {
    const scores = await collectPages(clients.security.secureScores.list());

    for (const s of scores) {
      resources.push({
        type:         'SecureScore',
        name:         s.displayName || s.name,
        currentScore: s.current ?? null,
        maxScore:     s.max ?? null,
        percentage:   s.percentage != null ? Math.round(s.percentage * 100) : null,
      });
    }
  } catch { /* Defender may not be enabled */ }

  try {
    // assessments.list() returns human-readable displayName values;
    // the older tasks.list() returns internal class names like GenericSecurityTask.
    const scope = `/subscriptions/${subscriptionId}`;
    const assessments = await collectPages(clients.security.assessments.list(scope));
    for (const r of assessments) {
      if (r.status?.code !== 'Healthy') {
        resources.push({
          type:         'SecurityRecommendation',
          name:         r.displayName || r.name,
          status:       r.status?.code || 'Unknown',
          resourceId:   r.resourceDetails?.Id || null,
          resourceName: r.resourceDetails?.ResourceName || null,
          resourceType: r.resourceDetails?.ResourceType || null,
        });
      }
    }
  } catch { /* skip */ }

  try {
    const alerts = await collectPages(clients.security.alerts.list());
    for (const a of alerts) {
      resources.push({
        type:            'SecurityAlert',
        name:            a.alertDisplayName || a.name,
        severity:        a.severity,
        status:          a.status,
        intent:          a.intent || null,
        description:     a.description || null,
        remediationSteps: a.remediationSteps || [],
        resourceId:      a.resourceIdentifiers?.[0]?.azureResourceId || null,
        startTimeUtc:    a.startTimeUtc || null,
      });
    }
  } catch { /* skip */ }

  // Secure score per control (granular breakdown)
  try {
    const controls = await collectPages(clients.security.secureScoreControls.list());
    for (const c of controls) {
      resources.push({
        type:             'SecureScoreControl',
        name:             c.displayName || c.name,
        currentScore:     c.score?.current ?? null,
        maxScore:         c.score?.max ?? null,
        healthyResources: c.healthyResourceCount ?? null,
        unhealthyResources: c.unhealthyResourceCount ?? null,
        notApplicable:    c.notApplicableResourceCount ?? null,
      });
    }
  } catch { /* skip */ }

  // Defender for Cloud workload protection plans
  try {
    const pricings = await collectPages(clients.security.pricings.list());
    for (const p of pricings) {
      resources.push({
        type:        'DefenderPlan',
        name:        p.name,
        pricingTier: p.pricingTier || null,
        subPlan:     p.subPlan || null,
      });
    }
  } catch { /* skip */ }

  // Security contacts
  try {
    const contacts = await collectPages(clients.security.securityContacts.list());
    for (const c of contacts) {
      resources.push({
        type:                'SecurityContact',
        name:                c.name,
        email:               c.email || null,
        phone:               c.phone || null,
        alertNotifications:  c.alertNotifications || null,
        notificationsByRole: c.notificationsByRole?.state || null,
      });
    }
  } catch { /* skip */ }

  // Regulatory compliance standards (CIS, PCI-DSS, ISO 27001, etc.)
  try {
    const standards = await collectPages(clients.security.regulatoryComplianceStandards.list());
    for (const s of standards) {
      resources.push({
        type:                'RegulatoryCompliance',
        name:                s.name,
        state:               s.state || null,
        passedControls:      s.passedControls ?? null,
        failedControls:      s.failedControls ?? null,
        skippedControls:     s.skippedControls ?? null,
        unsupportedControls: s.unsupportedControls ?? null,
      });
    }
  } catch { /* skip */ }

  // JIT Network Access Policies (Just-In-Time VM access — avoids always-open management ports)
  try {
    const jitPolicies = await collectPages(
      clients.security.jitNetworkAccessPolicies.listBySubscription()
    );
    for (const jit of jitPolicies) {
      resources.push({
        type:              'JITNetworkAccessPolicy',
        name:              jit.name,
        location:          jit.location,
        provisioningState: jit.provisioningState || null,
        vmCount:           (jit.virtualMachines || []).length,
        virtualMachines:   (jit.virtualMachines || []).map(vm => ({
          id:    vm.id,
          ports: (vm.ports || []).map(p => ({
            number:                     p.number,
            protocol:                   p.protocol,
            allowedSourceAddressPrefix: p.allowedSourceAddressPrefix || null,
            maxRequestAccessDuration:   p.maxRequestAccessDuration || null,
          })),
        })),
      });
    }
  } catch { /* JIT may not be configured or requires Defender for Servers */ }

  // Auto-Provisioning Settings (is the Defender monitoring agent auto-deployed to VMs?)
  try {
    const autoProvisions = await collectPages(clients.security.autoProvisioningSettings.list());
    for (const ap of autoProvisions) {
      resources.push({
        type:          'AutoProvisioningSetting',
        name:          ap.name,
        autoProvision: ap.autoProvision || null,  // 'On' or 'Off'
      });
    }
  } catch { /* skip */ }

  // Adaptive Application Controls (ML-based application allowlisting on VMs)
  try {
    const appControls = await clients.security.adaptiveApplicationControls.list();
    for (const group of (appControls?.value || [])) {
      resources.push({
        type:                 'AdaptiveApplicationControl',
        id:                   group.id || null,
        location:             group.location || null,
        enforcementMode:      group.enforcementMode || null,      // Audit / Enforce / None
        configurationStatus:  group.configurationStatus || null,  // Configured / NotConfigured / InProgress
        recommendationStatus: group.recommendationStatus || null, // Recommended / NotRecommended
        vmCount:              (group.vms || []).length,
        sourceSystemCount:    (group.sourceSystem || []).length,
      });
    }
  } catch { /* skip — requires Defender for Servers P2 */ }

  // Defender Workspace Settings (which Log Analytics workspace Defender reports to)
  try {
    const wsSettings = await collectPages(clients.security.workspaceSettings.list());
    for (const ws of wsSettings) {
      resources.push({
        type:        'DefenderWorkspaceSetting',
        name:        ws.name,
        workspaceId: ws.workspaceId || null,
        scope:       ws.scope || null,
      });
    }
  } catch { /* skip */ }

  // Alert Suppression Rules (silenced alerts — should be reviewed for abuse)
  try {
    const suppressions = await collectPages(clients.security.alertsSuppressionRules.list());
    for (const rule of suppressions) {
      resources.push({
        type:              'AlertSuppressionRule',
        name:              rule.name,
        alertType:         rule.alertType || null,
        state:             rule.state || null,           // Enabled / Disabled / Expired
        reason:            rule.reason || null,
        comment:           rule.comment || null,
        expirationDateUtc: rule.expirationDateUtc || null,
      });
    }
  } catch { /* skip */ }

  return resources;
}

// ─── 6. Key Vault ───────────────────────────────────────────────────────────
const { SecretClient }      = require('@azure/keyvault-secrets');
const { KeyClient }         = require('@azure/keyvault-keys');
const { CertificateClient } = require('@azure/keyvault-certificates');

async function checkKeyVault(clients) {
  const resources = [];

  const vaultList = await collectPages(clients.keyvault.vaults.list());

  for (const v of vaultList) {
    const rgName = v.id.split('/resourceGroups/')[1].split('/')[0];

    // Get full vault properties (list() only returns name/location/id)
    let props = {};
    try {
      const full = await clients.keyvault.vaults.get(rgName, v.name);
      props = full.properties || {};
    } catch { /* insufficient permissions — proceed with what we have */ }

    const vaultUrl = props.vaultUri || `https://${v.name}.vault.azure.net`;

    const resource = {
      type:                    'KeyVault',
      name:                    v.name,
      location:                v.location,
      sku:                     props.sku?.name || null,
      // Security posture
      softDeleteEnabled:       props.enableSoftDelete ?? false,
      purgeProtectionEnabled:  props.enablePurgeProtection ?? false,
      softDeleteRetentionDays: props.softDeleteRetentionInDays ?? null,
      enableRbacAuthorization: props.enableRbacAuthorization ?? false,
      // Access policies (only populated when not using RBAC mode)
      accessPolicies: (props.accessPolicies || []).map(p => ({
        tenantId:    p.tenantId,
        objectId:    p.objectId,
        permissions: {
          keys:         p.permissions?.keys || [],
          secrets:      p.permissions?.secrets || [],
          certificates: p.permissions?.certificates || [],
        },
      })),
      // Network / firewall
      networkDefaultAction:     props.networkAcls?.defaultAction || 'Allow',
      networkBypass:            props.networkAcls?.bypass || null,
      ipRules:                  (props.networkAcls?.ipRules || []).map(r => r.value),
      privateEndpointCount:     (props.privateEndpointConnections || []).length,
      publicNetworkAccess:      props.publicNetworkAccess || 'Enabled',
      // Data plane — secrets / keys / certs
      secrets:      [],
      keys:         [],
      certificates: [],
    };

    // Secrets metadata (no values — just name + expiry)
    try {
      const secretClient = new SecretClient(vaultUrl, clients.credential);
      const secrets = await collectPages(secretClient.listPropertiesOfSecrets());
      resource.secrets = secrets.map(s => ({
        name:        s.name,
        enabled:     s.enabled ?? null,
        expiresOn:   s.expiresOn || null,
        createdOn:   s.createdOn || null,
        updatedOn:   s.updatedOn || null,
      }));
    } catch { /* no data plane access */ }

    // Keys metadata
    try {
      const keyClient = new KeyClient(vaultUrl, clients.credential);
      const keys = await collectPages(keyClient.listPropertiesOfKeys());
      resource.keys = keys.map(k => ({
        name:      k.name,
        enabled:   k.enabled ?? null,
        expiresOn: k.expiresOn || null,
        createdOn: k.createdOn || null,
        keyType:   k.keyType || null,
      }));
    } catch { /* no data plane access */ }

    // Certificates metadata
    try {
      const certClient = new CertificateClient(vaultUrl, clients.credential);
      const certs = await collectPages(certClient.listPropertiesOfCertificates());
      resource.certificates = certs.map(c => ({
        name:      c.name,
        enabled:   c.enabled ?? null,
        expiresOn: c.expiresOn || null,
        createdOn: c.createdOn || null,
      }));
    } catch { /* no data plane access */ }

    resources.push(resource);
  }

  return resources;
}

// ─── 7. Monitor / Logging ───────────────────────────────────────────────────
const { OperationalInsightsManagementClient } = require('@azure/arm-operationalinsights');

async function checkMonitor(clients, subscriptionId) {
  const resources = [];

  // Activity Log Alerts
  try {
    const alerts = await collectPages(
      clients.monitor.activityLogAlerts.listBySubscriptionId(subscriptionId)
    );
    for (const a of alerts) {
      resources.push({
        type:           'ActivityLogAlert',
        name:           a.name,
        location:       a.location,
        enabled:        a.enabled ?? true,
        scopes:         a.scopes || [],
        conditions:     (a.condition?.allOf || []).map(c => ({
          field: c.field,
          equals: c.equals,
        })),
        actionGroupIds: (a.actions?.actionGroups || []).map(g => g.actionGroupId),
      });
    }
  } catch { /* skip */ }

  // Log Profiles (subscription-level activity log export)
  try {
    const profiles = await collectPages(clients.monitor.logProfiles.list());
    for (const p of profiles) {
      resources.push({
        type:              'LogProfile',
        name:              p.name,
        locations:         p.locations || [],
        categories:        p.categories || [],
        retentionEnabled:  p.retentionPolicy?.enabled ?? false,
        retentionDays:     p.retentionPolicy?.days ?? null,
        storageAccountId:  p.storageAccountId || null,
        serviceBusRuleId:  p.serviceBusRuleId || null,
      });
    }
  } catch { /* skip */ }

  // Metric Alerts
  try {
    const metricAlerts = await collectPages(
      clients.monitor.metricAlerts.listBySubscription()
    );
    for (const ma of metricAlerts) {
      resources.push({
        type:              'MetricAlert',
        name:              ma.name,
        location:          ma.location,
        enabled:           ma.enabled ?? true,
        severity:          ma.severity ?? null,
        evaluationFrequency: ma.evaluationFrequency || null,
        windowSize:        ma.windowSize || null,
        scopes:            ma.scopes || [],
        criteriaType:      ma.criteria?.odataType || null,
        autoMitigate:      ma.autoMitigate ?? null,
      });
    }
  } catch { /* skip */ }

  // Action Groups
  try {
    const actionGroups = await collectPages(
      clients.monitor.actionGroups.listBySubscriptionId(subscriptionId)
    );
    for (const ag of actionGroups) {
      resources.push({
        type:             'ActionGroup',
        name:             ag.name,
        location:         ag.location,
        enabled:          ag.enabled ?? true,
        emailReceivers:   (ag.emailReceivers || []).map(r => ({ name: r.name, address: r.emailAddress })),
        smsReceivers:     (ag.smsReceivers || []).length,
        webhookReceivers: (ag.webhookReceivers || []).length,
        azureAppPushReceivers: (ag.azureAppPushReceivers || []).length,
      });
    }
  } catch { /* skip */ }

  // Log Analytics Workspaces
  try {
    const laClient = new OperationalInsightsManagementClient(clients.credential, subscriptionId);
    const workspaces = await collectPages(laClient.workspaces.list());
    for (const ws of workspaces) {
      resources.push({
        type:              'LogAnalyticsWorkspace',
        name:              ws.name,
        location:          ws.location,
        sku:               ws.sku?.name || null,
        retentionDays:     ws.retentionInDays ?? null,
        dailyQuotaGb:      ws.workspaceCapping?.dailyQuotaGb ?? null,
        provisioningState: ws.provisioningState || null,
        publicNetworkAccessIngestion: ws.publicNetworkAccessForIngestion || null,
        publicNetworkAccessQuery:     ws.publicNetworkAccessForQuery || null,
      });
    }
  } catch { /* skip */ }

  // Subscription-level diagnostic settings (activity log routing)
  try {
    const subDiagSettings = await collectPages(
      clients.monitor.diagnosticSettings.list(`/subscriptions/${subscriptionId}`)
    );
    for (const ds of subDiagSettings) {
      resources.push({
        type:               'DiagnosticSetting',
        name:               ds.name,
        resourceScope:      'subscription',
        workspaceId:        ds.workspaceId || null,
        storageAccountId:   ds.storageAccountId || null,
        eventHubAuthRuleId: ds.eventHubAuthorizationRuleId || null,
        logs:               (ds.logs || []).map(l => ({ category: l.category, enabled: l.enabled })),
      });
    }
  } catch { /* skip */ }

  // Scheduled Query Rules (Log Analytics-based detection — SIEM-style alerts)
  try {
    const sqrList = await collectPages(
      clients.monitor.scheduledQueryRules.listBySubscription()
    );
    for (const sqr of sqrList) {
      resources.push({
        type:                'ScheduledQueryRule',
        name:                sqr.name,
        location:            sqr.location,
        enabled:             sqr.enabled ?? true,
        severity:            sqr.severity ?? null,          // 0=Critical .. 4=Verbose
        evaluationFrequency: sqr.evaluationFrequency || null,
        windowSize:          sqr.windowSize || null,
        targetResourceTypes: sqr.targetResourceTypes || [],
        scopes:              sqr.scopes || [],
        autoMitigate:        sqr.autoMitigate ?? null,
        actionGroupCount:    (sqr.actions?.actionGroups || []).length,
      });
    }
  } catch { /* skip */ }

  // Data Collection Rules (agent-based monitoring — which resources send data where)
  try {
    const dcrList = await collectPages(
      clients.monitor.dataCollectionRules.listBySubscription()
    );
    for (const dcr of dcrList) {
      resources.push({
        type:              'DataCollectionRule',
        name:              dcr.name,
        location:          dcr.location,
        description:       dcr.description || null,
        provisioningState: dcr.provisioningState || null,
        dataSourceCount:   Object.keys(dcr.dataSources || {}).length,
        destinationCount:  Object.keys(dcr.destinations || {}).length,
        dataFlowCount:     (dcr.dataFlows || []).length,
      });
    }
  } catch { /* skip */ }

  return resources;
}

// ─── 8. Resource Groups ──────────────────────────────────────────────────────
async function checkResourceGroups(clients) {
  const results = [];

  const rgs = await collectPages(clients.resources.resourceGroups.list());

  for (const rg of rgs) {
    const rgResources = await collectPages(
      clients.resources.resources.listByResourceGroup(rg.name)
    );

    results.push({
      type:          'ResourceGroup',
      name:          rg.name,
      location:      rg.location,
      tagCount:      Object.keys(rg.tags || {}).length,
      resourceCount: rgResources.length,
      resources:     rgResources.map(r => ({
        name:              r.name,
        resourceType:      r.type,
        location:          r.location || null,
        kind:              r.kind || null,
        provisioningState: r.properties?.provisioningState || null,
      })),
    });
  }

  return results;
}

// ─── 9. Azure Policy ─────────────────────────────────────────────────────────
async function checkPolicy(clients, subscriptionId) {
  const resources = [];
  const scope = `/subscriptions/${subscriptionId}`;

  // Policy assignments at subscription scope
  try {
    const assignments = await collectPages(clients.policy.policyAssignments.list(scope));
    for (const a of assignments) {
      resources.push({
        type:               'PolicyAssignment',
        name:               a.name,
        displayName:        a.displayName || null,
        policyDefinitionId: a.policyDefinitionId || null,
        scope:              a.scope || null,
        enforcementMode:    a.enforcementMode || null,
      });
    }
  } catch { /* skip */ }

  // Custom policy definitions
  try {
    const defs = await collectPages(clients.policy.policyDefinitions.list());
    for (const d of defs.filter(d => d.policyType === 'Custom')) {
      resources.push({
        type:        'CustomPolicyDefinition',
        name:        d.name,
        displayName: d.displayName || null,
        description: d.description || null,
        mode:        d.mode || null,
      });
    }
  } catch { /* skip */ }

  // Custom initiatives (policy set definitions)
  try {
    const initiatives = await collectPages(clients.policy.policySetDefinitions.list());
    for (const i of initiatives.filter(i => i.policyType === 'Custom')) {
      resources.push({
        type:        'CustomInitiative',
        name:        i.name,
        displayName: i.displayName || null,
        policyCount: (i.policyDefinitions || []).length,
      });
    }
  } catch { /* skip */ }

  return resources;
}

// ─── Scan directory helpers ───────────────────────────────────────────────────

/**
 * Generates a unique scan directory path and a corresponding review ID.
 * @param {string} subscriptionId - The Azure subscription ID.
 * @returns {Object} - { scanDir, reviewId }
 */
function buildScanDir(subscriptionId) {
  const reviewId = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
  const dateStr  = new Date().toISOString().replace(/:/g, '-').replace(/\..+$/, '');
  const folder   = `${reviewId}_${dateStr}`;
  return { scanDir: path.join(__dirname, '../../output', subscriptionId, folder), reviewId };
}

/**
 * Finds the most recent scan directory for a given subscription.
 * @param {string} subscriptionId - The Azure subscription ID.
 * @returns {string|null} - The absolute path to the latest scan directory, or null if none found.
 */
function findLatestScanDir(subscriptionId) {
  const subDir = path.join(__dirname, '../../output', subscriptionId);
  if (!fs.existsSync(subDir)) return null;
  const folders = fs.readdirSync(subDir)
    .filter(f => fs.statSync(path.join(subDir, f)).isDirectory())
    .sort();
  if (!folders.length) return null;
  return path.join(subDir, folders[folders.length - 1]);
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

/**
 * The main entry point for running a full environment audit.
 * Coordinates data collection across all requested sections, saves the results to disk,
 * and executes the finding engine to generate structured security findings.
 * 
 * @param {Object} clients - Pre-built Azure SDK clients.
 * @param {string} subscriptionId - Target subscription GUID.
 * @param {string[]|'all'} sections - Which sections to audit.
 * @param {Function} onProgress - Optional callback for real-time progress events (SSE).
 * @param {Object} opts - Additional options { name, userId }.
 */
async function runReview(clients, subscriptionId, sections = 'all', onProgress = null, opts = {}) {
  const { name = 'Unnamed Review', userId = null } = opts;
  const emit = e => { if (onProgress) onProgress(e); };
  const all  = sections === 'all';
  const want = s => all || sections.includes(s);

  // Build scan directory ID and create Review doc before sections run so the
  // review appears in the list as 'running' immediately.
  const { scanDir, reviewId } = buildScanDir(subscriptionId);

  let reviewDoc = null;
  if (userId) {
    try {
      reviewDoc = await Review.create({ reviewId, name, userId, subscriptionId, scanDir, status: 'running' });
      emit({ type: 'scan_init', reviewId, name, createdAt: reviewDoc.createdAt });
    } catch (e) {
      console.error('[review] DB: failed to create Review doc:', e.message);
    }
  }

  const SECTION_LABELS = {
    iam:            'IAM / RBAC',
    networking:     'Networking',
    storage:        'Storage',
    compute:        'Compute',
    securityCenter: 'Security Center',
    keyVault:       'Key Vault',
    monitor:        'Monitor / Logging',
    resourceGroups: 'Resource Groups',
    policy:         'Azure Policy',
  };

  const results = {};
  const errors  = {};

  const run = async (key, fn) => {
    if (!want(key)) return;
    const label = SECTION_LABELS[key];
    emit({ type: 'start', section: key, label });
    console.log(`[review] Running ${key}...`);
    try {
      // Each section audit is isolated. A failure in one domain (e.g. insufficient 
      // permissions for Key Vault) will NOT stop the audit of other domains.
      results[key] = await fn();
      console.log(`[review] ${key} — ${results[key].length} resource(s)`);
      emit({ type: 'section_done', section: key, label, resources: results[key] });
    } catch (err) {
      console.error(`[review] ${key} failed:`, err.message);
      errors[key]  = err.message;
      results[key] = [];
      emit({ type: 'section_error', section: key, label, error: err.message });
    }
  };

  await run('iam',            () => checkIAM(clients, subscriptionId));
  await run('networking',     () => checkNetworking(clients));
  await run('storage',        () => checkStorage(clients));
  await run('compute',        () => checkCompute(clients));
  await run('securityCenter', () => checkSecurityCenter(clients, subscriptionId));
  await run('keyVault',       () => checkKeyVault(clients));
  await run('monitor',        () => checkMonitor(clients, subscriptionId));
  await run('resourceGroups', () => checkResourceGroups(clients));
  await run('policy',         () => checkPolicy(clients, subscriptionId));

  const allResources = Object.values(results).flat();
  const generatedAt  = new Date().toISOString();

  const summary = {
    total:     allResources.length,
    bySection: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [k, v.length])
    ),
  };

  // ── Findings Analysis ─────────────────────────────────────────
  const findings = findingEngine.analyze(results);

  const fullDump = { generatedAt, subscriptionId, scanDir, reviewId, sectionsRun: Object.keys(results), errors, summary, resources: allResources };

  // ── Update Review doc ─────────────────────────────────────────
  if (reviewDoc) {
    try {
      await Review.findByIdAndUpdate(reviewDoc._id, {
        status:      'complete',
        summary,
        findings,
        sectionsRun: Object.keys(results),
        errors,
      });

      await ReviewSection.bulkWrite(
        Object.entries(results).map(([key, data]) => ({
          updateOne: {
            filter: { reviewId, key },
            update: { $set: { data } },
            upsert: true,
          },
        }))
      );
    } catch (e) {
      console.error('[review] DB: failed to update Review doc:', e.message);
    }
  }

  emit({ type: 'complete', summary, resources: allResources, generatedAt, scanDir, reviewId });

  return fullDump;
}

module.exports = {
  runReview,
  findLatestScanDir,
  checkIAM,
  checkNetworking,
  checkStorage,
  checkCompute,
  checkSecurityCenter,
  checkKeyVault,
  checkMonitor,
  checkResourceGroups,
  checkPolicy,
};
