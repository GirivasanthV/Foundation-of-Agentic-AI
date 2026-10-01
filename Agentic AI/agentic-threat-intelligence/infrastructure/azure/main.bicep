@description('Azure region for project resources')
param location string = resourceGroup().location

@description('Short unique prefix, for example sentinelgiri')
param prefix string

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs'
  location: location
  properties: {
    retentionInDays: 30
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take(replace('${prefix}evidence', '-', ''), 24)
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: storage::default
  name: 'evidence'
  properties: {
    publicAccess: 'None'
  }
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: take(replace('${prefix}acr', '-', ''), 50)
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
  }
}

output storageAccountName string = storage.name
output containerRegistryName string = registry.name
output logAnalyticsWorkspace string = logAnalytics.name

