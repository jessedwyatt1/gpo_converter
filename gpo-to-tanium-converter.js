const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

let nextPriority = 100;

/**
 * Converts Group Policy Backup files to Tanium Policy JSON format
 * Usage: node gpo-to-tanium-converter.js <inputDirectory> <outputDirectory>
 */
async function main() {
  try {
    // Get command line arguments
    const args = process.argv.slice(2);
    if (args.length < 2) {
      console.error('Usage: node gpo-to-tanium-converter.js <inputDirectory> <outputDirectory>');
      process.exit(1);
    }

    const inputDirectory = args[0];
    const outputDirectory = args[1];

    // Ensure output directory exists
    if (!fs.existsSync(outputDirectory)) {
      fs.mkdirSync(outputDirectory, { recursive: true });
    }

    // Process all subdirectories in the input directory
    const items = await readdir(inputDirectory);
    let processedCount = 0;
    let attemptedCount = 0;
    
    for (const item of items) {
      const itemPath = path.join(inputDirectory, item);
      const itemStat = await stat(itemPath);
      
      if (itemStat.isDirectory() && item.includes('{')) {
        // This directory should contain a GPO backup
        try {
          attemptedCount++;
          await processGpoBackup(itemPath, outputDirectory);
          processedCount++;
          console.log(`Processed ${processedCount}/${attemptedCount} policies: ${item}`);
        } catch (err) {
          console.error(`Error processing ${itemPath}: ${err.message}`);
        }
      }
    }
    
    console.log(`Successfully converted ${processedCount}/${attemptedCount} GPO backups to Tanium policies.`);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  }
}

/**
 * Process a single GPO backup directory and convert it to Tanium policy
 */
async function processGpoBackup(backupDir, outputDir) {
  // Find gpreport.xml or manifest.xml
  const possibleReportFiles = ['gpreport.xml', 'Manifest.xml', 'DomainSysvol/GPO/GPO.xml'];
  let reportFilePath = null;
  let reportContent = null;

  for (const fileName of possibleReportFiles) {
    const filePath = path.join(backupDir, fileName);
    if (fs.existsSync(filePath)) {
      reportFilePath = filePath;
      break;
    }
  }

  if (!reportFilePath) {
    throw new Error(`No report file (gpreport.xml or Manifest.xml) found in ${backupDir}`);
  }

  // Read the file as a buffer first to handle encoding issues
  const fileBuffer = await readFile(reportFilePath);
  
  // Try to detect BOM and remove it if present
  let xmlContent;
  if (fileBuffer[0] === 0xEF && fileBuffer[1] === 0xBB && fileBuffer[2] === 0xBF) {
    // UTF-8 BOM
    xmlContent = fileBuffer.slice(3).toString('utf8');
  } else if (fileBuffer[0] === 0xFE && fileBuffer[1] === 0xFF) {
    // UTF-16 BE BOM
    xmlContent = fileBuffer.slice(2).toString('utf16be');
  } else if (fileBuffer[0] === 0xFF && fileBuffer[1] === 0xFE) {
    // UTF-16 LE BOM
    xmlContent = fileBuffer.slice(2).toString('utf16le');
  } else {
    // No BOM detected, try different encodings
    try {
      xmlContent = fileBuffer.toString('utf8');
      // Quick validation check - if it doesn't start with '<', it's probably wrong encoding
      if (!xmlContent.trim().startsWith('<')) {
        xmlContent = fileBuffer.toString('utf16le');
      }
    } catch (e) {
      // Fallback to UTF-16 LE
      xmlContent = fileBuffer.toString('utf16le');
    }
  }

  // Parse XML content
  const parser = new xml2js.Parser({ 
    explicitArray: false,
    // More tolerant parsing options
    trim: true,
    normalize: true,
    explicitRoot: true
  });
  
  // Try to parse the XML
  let gpoData;
  try {
    gpoData = await parser.parseStringPromise(xmlContent);
  } catch (err) {
    // If parsing fails, try to clean the content
    console.warn(`XML parsing failed for ${backupDir}, attempting to clean XML content: ${err.message}`);
    const cleanedXml = cleanXmlContent(xmlContent);
    try {
      gpoData = await parser.parseStringPromise(cleanedXml);
    } catch (innerErr) {
      throw new Error(`Failed to parse GPO XML after cleaning: ${innerErr.message}`);
    }
  }
  
  // Read additional metadata if available from bkupInfo.xml
  let backupMetadata = {};
  const bkupInfoPath = path.join(backupDir, 'bkupInfo.xml');
  if (fs.existsSync(bkupInfoPath)) {
    try {
      const bkupBuffer = await readFile(bkupInfoPath);
      let bkupContent;
      
      // Try to handle encoding for bkupInfo.xml too
      if (bkupBuffer[0] === 0xEF && bkupBuffer[1] === 0xBB && bkupBuffer[2] === 0xBF) {
        bkupContent = bkupBuffer.slice(3).toString('utf8');
      } else if (bkupBuffer[0] === 0xFE && bkupBuffer[1] === 0xFF) {
        bkupContent = bkupBuffer.slice(2).toString('utf16be');
      } else if (bkupBuffer[0] === 0xFF && bkupBuffer[1] === 0xFE) {
        bkupContent = bkupBuffer.slice(2).toString('utf16le');
      } else {
        // Try UTF-16LE first based on error pattern
        try {
          bkupContent = bkupBuffer.toString('utf16le');
          if (!bkupContent.trim().startsWith('<')) {
            bkupContent = bkupBuffer.toString('utf8');
          }
        } catch (e) {
          bkupContent = bkupBuffer.toString('utf8');
        }
      }
      
      try {
        const bkupInfo = await parser.parseStringPromise(bkupContent);
        backupMetadata = bkupInfo.BackupInst || {};
      } catch (err) {
        console.warn(`Failed to parse bkupInfo.xml in ${backupDir}: ${err.message}`);
      }
    } catch (err) {
      console.warn(`Failed to read bkupInfo.xml in ${backupDir}: ${err.message}`);
    }
  }
  
  // Extract policy settings
  const policyItems = extractPolicyItems(gpoData, backupDir);
  
  // Create Tanium policy JSON
  const taniumPolicy = createTaniumPolicy(gpoData, backupMetadata, policyItems);
  
  // Save the converted policy
  const outputFilename = `${sanitizeFilename(taniumPolicy.name)}.json`;
  const outputPath = path.join(outputDir, outputFilename);
  await writeFile(outputPath, JSON.stringify(taniumPolicy, null, 2));
  
  return outputPath;
}

/**
 * Helper function to clean XML content
 */
function cleanXmlContent(xmlContent) {
  // Remove any BOM or invalid characters at the beginning
  let cleaned = xmlContent.trim();
  
  // If it doesn't start with '<', find the first '<' and start from there
  if (!cleaned.startsWith('<')) {
    const firstTagIndex = cleaned.indexOf('<');
    if (firstTagIndex !== -1) {
      cleaned = cleaned.substring(firstTagIndex);
    }
  }
  
  // Remove any illegal XML characters
  cleaned = cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  
  return cleaned;
}

/**
 * Extract policy items from GPO data
 */
function extractPolicyItems(gpoData, backupDir) {
  const policyItems = [];
  
  // Check for valid GPO structure
  if (!gpoData || (!gpoData.GPO && !gpoData.GroupPolicyBackupScheme)) {
    return policyItems;
  }

  // Handle different possible XML structures
  let gpo = gpoData.GPO || (gpoData.GroupPolicyBackupScheme && 
                           gpoData.GroupPolicyBackupScheme.GroupPolicyObject);
  
  if (!gpo) {
    return policyItems;
  }
  
  // Process Computer Policies
  if (gpo.Computer && gpo.Computer.ExtensionData) {
    processPolicyExtensions(gpo.Computer.ExtensionData, policyItems, 'Computer');
  }
  
  // Process User Policies
  if (gpo.User && gpo.User.ExtensionData) {
    processPolicyExtensions(gpo.User.ExtensionData, policyItems, 'User');
  }

  // Process Registry.pol files directly if available
  if (backupDir) {
    const regPolPaths = [
      path.join(backupDir, 'DomainSysvol', 'GPO', 'Machine', 'registry.pol'),
      path.join(backupDir, 'DomainSysvol', 'GPO', 'User', 'registry.pol')
    ];

    for (const polPath of regPolPaths) {
      if (fs.existsSync(polPath)) {
        try {
          const machinePolicy = polPath.includes('Machine');
          extractPolicyItemsFromRegPolBinary(polPath, policyItems, machinePolicy);
        } catch (err) {
          console.warn(`Failed to process registry.pol at ${polPath}: ${err.message}`);
        }
      }
    }
  }
  
  // Clean up policy items - fix registry paths, values, etc.
  cleanPolicyItems(policyItems);
  
  // Remove any duplicate or invalid policy items
  return deduplicateAndCleanPolicyItems(policyItems);
}

/**
 * Clean up policy items to fix common issues
 */
function cleanPolicyItems(policyItems) {
  if (!policyItems || !policyItems.length) return;
  
  policyItems.forEach(item => {
    if (!item.kvps || !item.kvps.length) return;
    
    // Fix policy names - remove brackets or complete them
    if (item.name) {
      if (item.name.includes('[') && !item.name.includes(']')) {
        // Add missing closing bracket
        item.name = item.name + ']';
      }
      
      // Simplify policy names that are too complex
      if (item.name.startsWith('Registry Setting - [') && item.name.length > 50) {
        // Extract a more readable name from the registry path
        const pathInName = item.name.replace('Registry Setting - [', '').replace(']', '');
        const pathParts = pathInName.split('\\');
        const lastTwoParts = pathParts.slice(-2);
        item.name = lastTwoParts.join(' ');
      } else if (item.name.startsWith('Registry Setting - [')) {
        // Remove the "Registry Setting - [" prefix to make a cleaner name
        const pathInName = item.name.replace('Registry Setting - [', '').replace(']', '');
        const pathParts = pathInName.split('\\');
        const lastPart = pathParts[pathParts.length - 1] || 'Setting';
        item.name = lastPart;
      }
    }
    
    item.kvps.forEach(kvp => {
      // Fix registry keys
      if (kvp.key) {
        // Remove square brackets from the beginning/end of registry keys
        kvp.key = kvp.key.replace(/^\s*\[(.+)\]\s*$/, '$1');
        kvp.key = kvp.key.replace(/^\[/, '').replace(/\]$/, '');
        
        // Remove trailing semicolons and Unicode control characters
        kvp.key = kvp.key.replace(/;+$/, '');
        kvp.key = kvp.key.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
        
        // Remove Unicode replacement characters
        kvp.key = kvp.key.replace(/�/g, '');
        
        // Split the key if it contains semicolons (common conversion issue)
        if (kvp.key.includes(';')) {
          const parts = kvp.key.split(';');
          // Take just the registry path part
          kvp.key = parts[0];
        }
      }
      
      // Fix value names - CRITICAL FIX FOR THE ISSUE
      if (kvp.valueName) {
        // If valueName is a full registry path, extract just the last part
        if (kvp.valueName.includes('\\') && kvp.valueName.startsWith('Software\\')) {
          const parts = kvp.valueName.split('\\');
          // Use last part as value name or "Setting" if empty
          kvp.valueName = parts[parts.length - 1] || 'Setting';
        }
        
        // Remove square brackets
        kvp.valueName = kvp.valueName.replace(/^\s*\[(.+)\]\s*$/, '$1');
        kvp.valueName = kvp.valueName.replace(/^\[/, '').replace(/\]$/, '');
        
        // Remove Unicode control characters
        kvp.valueName = kvp.valueName.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
        
        // Remove Unicode replacement characters
        kvp.valueName = kvp.valueName.replace(/�/g, '');
        
        // If value name still has special formatting issues, simplify it
        if (kvp.valueName.includes(';') || kvp.valueName.includes('\\u')) {
          // Use a generic value name
          kvp.valueName = 'Setting';
        }
        
        // If valueName and key are identical full paths, use a default value name
        if (kvp.valueName === kvp.key) {
          kvp.valueName = 'Enabled';
        }
        
        // If valueName is a GUID, use a more generic name
        if (/^\{[0-9a-f-]+\}$/i.test(kvp.valueName)) {
          kvp.valueName = 'ItemData';
        }
        
        // Self-reference check - if valueName is the last segment of the key path
        const keyParts = kvp.key.split('\\');
        const lastKeyPart = keyParts[keyParts.length - 1];
        if (kvp.valueName === lastKeyPart) {
          kvp.valueName = 'Enabled';
        }
      }
      
      // Fix values - remove Unicode escape sequences and provide default values when empty
      if (typeof kvp.value === 'string') {
        // Remove Unicode escape sequences
        if (kvp.value.includes('\\u')) {
          // For numeric values (common control characters), convert to a basic number
          if (/\\u00[0-9a-f]{2}/.test(kvp.value)) {
            kvp.value = "1";
            // Also change type to DWORD when appropriate
            if (kvp.lgpoType === "ENFORCE_REG_SZ") {
              kvp.lgpoType = "ENFORCE_REG_DWORD";
            }
          } else {
            // For other escape sequences, convert to empty string
            kvp.value = "";
          }
        }
      }
      
      // Provide default values based on type and state
      if (kvp.value === "" && kvp.lgpoType === "ENFORCE_REG_DWORD") {
        // For DWORD registry keys with empty values, default to 1 for enabled policies
        kvp.value = item.state === "enabled" ? "1" : "0";
      } else if (kvp.value === "" && kvp.lgpoType === "ENFORCE_REG_SZ") {
        // IMPORTANT: For certificate and security settings, convert to DWORD for better compatibility
        if (kvp.key.includes('\\SystemCertificates\\') || 
            kvp.key.includes('\\Safer\\') ||
            kvp.key.includes('\\Security\\')) {
          kvp.value = "1";
          kvp.lgpoType = "ENFORCE_REG_DWORD";
        }
      }
      
      // Fix presentation IDs
      if (kvp.presentationId) {
        // Simplify complex presentation IDs
        if (kvp.presentationId.includes(';') || 
            kvp.presentationId.includes('[') || 
            kvp.presentationId.includes('\\u') ||
            kvp.presentationId.length > 60) {
          // Create a simpler presentation ID based on cleaned key and value name
          const simplePath = item.categoryPath ? item.categoryPath.join('/') : 'Registry';
          // Extract the last part of the key for a cleaner ID
          const keyParts = kvp.key.split('\\');
          const lastKeyPart = keyParts[keyParts.length - 1] || 'key';
          
          // Create a shorter, more readable ID
          kvp.presentationId = `${simplePath}:${lastKeyPart}`;
        }
      }
      
      // Fix key path for certificate store settings
      if (kvp.key.includes('\\SystemCertificates\\')) {
        const parts = kvp.key.split('\\');
        // Check if the last part is one of the expected certificate store names but no container exists.
        const store = parts[parts.length - 1];
        if (['Disallowed', 'TrustedPublisher'].includes(store) && parts.length === 5) { 
          // Append a default container ("Certificates") if missing.
          kvp.key += '\\Certificates';
        }
        
        // Re-split the key after appending if needed.
        const newParts = kvp.key.split('\\');
        // Use the last two parts for category and type
        const category = newParts[newParts.length - 2].toLowerCase();
        const type = newParts[newParts.length - 1].toLowerCase();
        // Generate a complete presentation ID
        kvp.presentationId = `windows:registry/windef:usersettings:${category}:${type}`;
      }
      
      // Fix CodeIdentifiers settings
      if (kvp.key.includes('\\Safer\\CodeIdentifiers')) {
        // Always use DWORD for CodeIdentifiers settings
        kvp.value = "1";
        kvp.lgpoType = "ENFORCE_REG_DWORD";
        
        // Use ItemData for GUID path settings
        if (kvp.key.includes('{') && kvp.key.includes('}')) {
          kvp.valueName = 'ItemData';
        } else {
          // Use Enabled for other CodeIdentifiers settings
          kvp.valueName = 'Enabled';
        }
      }

      // Standardize presentationId format
      if (kvp.presentationId) {
        // Convert to lowercase for consistency
        kvp.presentationId = kvp.presentationId.toLowerCase();
        
        // Remove curly braces to ensure a valid format for Tanium
        kvp.presentationId = kvp.presentationId.replace(/[{}]/g, '');
        
        // If it's a registry setting without a proper presentation ID, create one
        if (kvp.key.toLowerCase().includes('\\microsoft\\systemcertificates\\')) {
          const category = kvp.key.split('\\').slice(-2)[0].toLowerCase();
          const type = kvp.key.split('\\').slice(-1)[0].toLowerCase();
          kvp.presentationId = `windows:registry/windef:usersettings:${category}:${type}`;
        }
      }

      // Ensure proper categoryPath for registry settings
      if (item.categoryPath && item.categoryPath.length === 2) {
        if (item.categoryPath[0] === 'windows:Registry') {
          // Add a third level for registry settings if missing
          const category = kvp.key.split('\\').slice(-2)[0];
          if (!item.categoryPath[2]) {
            item.categoryPath.push(category);
          }
        }
      }

      // Standardize registry values
      if (kvp.lgpoType === 'ENFORCE_REG_DWORD') {
        // Ensure DWORD values are numbers, not strings
        kvp.value = parseInt(kvp.value) || 1;
      }
    });

    // If the categoryPath is built only from the XML it might be missing details.
    // -----------------------------------------------
    // Existing logic to add a third level for registry settings if missing
    if (item.categoryPath && item.categoryPath.length === 2) {
      const kvp = item.kvps[0];
      if (kvp && kvp.key) {
        const parts = kvp.key.split('\\');
        // Use the second-to-last part of the registry key if available:
        if (parts.length >= 2 && !item.categoryPath[2]) {
          item.categoryPath.push(parts[parts.length - 2]);
        }
      }
    }
    
    // NEW: If the policy item is certificate-store–related and the categoryPath
    // only has three parts (e.g. ["windows:Registry", "windef:UserSettings", "Disallowed"]),
    // then attempt to pull the missing container from the registry key.
    if (
      item.categoryPath &&
      item.categoryPath.length === 3 &&
      (item.categoryPath[2].toLowerCase() === 'disallowed' ||
        item.categoryPath[2].toLowerCase() === 'trustedpublisher')
    ) {
      const kvp = item.kvps[0];
      if (kvp && kvp.key && kvp.key.includes('SystemCertificates')) {
        const parts = kvp.key.split('\\');
        // Expecting a key like:
        // "Software\Policies\Microsoft\SystemCertificates\Disallowed\Certificates"
        if (parts.length >= 6) {
          // Update the third element to be the store (in lowercase)
          item.categoryPath[2] = parts[4].toLowerCase();
          // And add the container as a fourth element
          item.categoryPath.push(parts[5].toLowerCase());
        }
      }
    }
  });
}

/**
 * Remove duplicate policy items and fix any remaining issues
 */
function deduplicateAndCleanPolicyItems(policyItems) {
  if (!policyItems || !policyItems.length) return [];
  
  const uniquePolicyItems = [];
  const seenKeys = new Set();
  const seenNames = new Set();
  
  // First pass: fix key mismatches and policy names
  policyItems.forEach(item => {
    if (!item.kvps || !item.kvps.length) return;
    
    // If name contains a path but doesn't match key, fix it
    if (item.name && item.name.startsWith('Registry Setting - [')) {
      const pathInName = item.name.replace('Registry Setting - [', '').replace(/\]$/, '');
      const kvp = item.kvps[0];
      
      // If there's a mismatch between name and key, decide which to trust
      if (pathInName !== kvp.key) {
        // Check which path is more specific/complete
        const nameHasMoreSegments = pathInName.split('\\').length > kvp.key.split('\\').length;
        const nameHasGuid = pathInName.includes('{') && pathInName.includes('}');
        const keyHasGuid = kvp.key.includes('{') && kvp.key.includes('}');
        
        // Use path from name if it seems more complete
        if ((nameHasMoreSegments || nameHasGuid) && !keyHasGuid) {
          kvp.key = pathInName;
        }
        
        // Create a better name from the final key
        const keyParts = kvp.key.split('\\');
        const lastTwoParts = keyParts.slice(-2);
        item.name = lastTwoParts.join(' ');
      } else {
        // Still simplify the name even if it matches
        const keyParts = kvp.key.split('\\');
        const lastTwoParts = keyParts.slice(-2);
        item.name = lastTwoParts.join(' ');
      }
    }
  });
  
  // Add missing certificate store entries
  const certificateStores = new Map();
  
  // Collect all existing certificate stores
  policyItems.forEach(item => {
    if (!item.kvps || !item.kvps.length) return;
    
    const kvp = item.kvps[0];
    if (kvp.key.includes('\\SystemCertificates\\')) {
      const keyParts = kvp.key.split('\\');
      const storeIndex = keyParts.findIndex(part => part === 'SystemCertificates');
      if (storeIndex !== -1 && storeIndex + 1 < keyParts.length) {
        const certificateStore = keyParts[storeIndex + 1]; // e.g., "Disallowed", "TrustedPublisher"
        const certificateContainer = keyParts[storeIndex + 2]; // e.g., "Certificates", "CRLs", "CTLs"
        
        if (certificateStore && certificateContainer) {
          const storeKey = certificateStore;
          if (!certificateStores.has(storeKey)) {
            certificateStores.set(storeKey, new Set());
          }
          certificateStores.get(storeKey).add(certificateContainer);
        }
      }
    }
  });
  
  // Add missing containers for each store
  const newItems = [];
  certificateStores.forEach((containers, store) => {
    const standardContainers = ['Certificates', 'CRLs', 'CTLs'];
    
    standardContainers.forEach(container => {
      if (!containers.has(container)) {
        // Create a new policy item for the missing container
        newItems.push({
          state: "enabled",
          name: `${store} ${container}`,
          kvps: [{
            key: `Software\\Policies\\Microsoft\\SystemCertificates\\${store}\\${container}`,
            valueName: "Enabled",
            value: 1,  // Changed from "1" to 1
            delete: false,
            lgpoType: "ENFORCE_REG_DWORD",
            presentationId: `windows:registry/windef:usersettings:${store.toLowerCase()}:${container.toLowerCase()}`
          }],
          categoryPath: ["windows:Registry", "windef:UserSettings", store],
          hasLgpo: true
        });
      }
    });
  });
  
  // Add the new items to the policy items
  policyItems.push(...newItems);
  
  // Fix CodeIdentifiers paths
  policyItems.forEach(item => {
    if (item.kvps && item.kvps.length > 0) {
      const kvp = item.kvps[0];
      if (kvp.key.includes('\\Safer\\CodeIdentifiers\\')) {
        // Ensure proper category path for CodeIdentifiers
        const pathMatch = kvp.key.match(/\\CodeIdentifiers\\([^\\]+)\\Paths/);
        if (pathMatch) {
          item.categoryPath = ["windows:Registry", "windef:UserSettings", "CodeIdentifiers"];
        }
        
        // Fix presentation ID format
        if (kvp.presentationId) {
          kvp.presentationId = kvp.presentationId.toLowerCase().replace(/\\/g, '/');
        }
        
        // Ensure value is number for DWORD
        if (kvp.lgpoType === 'ENFORCE_REG_DWORD') {
          kvp.value = 1;
        }
      }
    }
  });
  
  // Second pass: remove duplicates and invalid items
  for (const item of policyItems) {
    // Skip items without KVPs
    if (!item.kvps || !item.kvps.length) continue;
    
    // Generate a unique key for this policy item
    const itemKey = `${item.name}|${item.state}|${JSON.stringify(item.categoryPath)}`;
    
    // Skip duplicate policy items
    if (seenNames.has(itemKey)) continue;
    seenNames.add(itemKey);
    
    // Create a new item with cleaned KVPs
    const cleanedItem = {
      ...item,
      kvps: []
    };
    
    // Only keep unique KVPs (avoid duplicate registry settings)
    for (const kvp of item.kvps) {
      const kvpKey = `${kvp.key}|${kvp.valueName}`;
      
      // Skip duplicate KVPs
      if (seenKeys.has(kvpKey)) continue;
      seenKeys.add(kvpKey);
      
      // Skip self-referential KVPs or other invalid configurations
      if (kvp.key === kvp.valueName) continue;
      
      // Skip if valueName is a full registry path identical to another key
      if (kvp.valueName.includes('\\') && 
          Array.from(seenKeys).some(k => k.split('|')[0] === kvp.valueName)) {
        continue;
      }
      
      // Skip if the value contains Unicode control characters and isn't fixed
      if (typeof kvp.value === 'string' && kvp.value.includes('\\u')) {
        // Fix it one more time
        kvp.value = "1";
        kvp.lgpoType = "ENFORCE_REG_DWORD";
      }
      
      // Clean the KVP one more time for safety
      const cleanedKvp = {
        ...kvp,
        // Ensure value name is reasonable - not a full path
        valueName: kvp.valueName.includes('\\') ? 
          kvp.valueName.split('\\').pop() || 'Setting' : 
          kvp.valueName
      };
      
      cleanedItem.kvps.push(cleanedKvp);
    }
    
    // Only add the item if it has at least one valid KVP
    if (cleanedItem.kvps.length > 0) {
      uniquePolicyItems.push(cleanedItem);
    }
  }
  
  return uniquePolicyItems;
}

/**
 * Extracts registry settings from binary registry.pol files
 * Registry.pol format: 
 * - Header: 'PReg' signature + version
 * - Entries: series of key/value entries
 */
function extractPolicyItemsFromRegPolBinary(polPath, policyItems, isMachinePolicy = true) {
  try {
    // Read file as binary buffer
    const buffer = fs.readFileSync(polPath);
    
    // Verify 'PReg' signature (first 4 bytes)
    if (buffer.slice(0, 4).toString() !== 'PReg') {
      console.warn(`Registry.pol file at ${polPath} doesn't have valid PReg signature`);
      return;
    }
    
    // Registry.pol parsing is complex - we'll do a simplified version
    // that tries to extract registry keys and values
    let offset = 4; // Skip 'PReg' signature
    
    while (offset < buffer.length) {
      try {
        // Find next entry by looking for '[' character
        let entryStart = buffer.indexOf('[', offset);
        if (entryStart === -1) break;
        
        // Find the end of this entry by looking for ']'
        let entryEnd = buffer.indexOf(']', entryStart);
        if (entryEnd === -1) break;
        
        // Extract the registry key path
        let keyPath = buffer.slice(entryStart + 1, entryEnd).toString('utf8');
        keyPath = keyPath.replace(/\0/g, ''); // Remove null bytes
        
        // Skip to the value name
        offset = entryEnd + 1;
        
        // Try to find semicolons that separate fields
        let semicolonPos1 = buffer.indexOf(';', offset);
        if (semicolonPos1 === -1) break;
        
        // Extract value name
        let valueName = buffer.slice(offset, semicolonPos1).toString('utf8');
        valueName = valueName.replace(/\0/g, ''); // Remove null bytes
        
        // Move past the semicolon
        offset = semicolonPos1 + 1;
        
        // Find the next semicolon
        let semicolonPos2 = buffer.indexOf(';', offset);
        if (semicolonPos2 === -1) break;
        
        // Extract value type as a string
        let valueType = buffer.slice(offset, semicolonPos2).toString('utf8');
        valueType = valueType.replace(/\0/g, ''); // Remove null bytes
        
        // Move past the semicolon
        offset = semicolonPos2 + 1;
        
        // Find the next semicolon
        let semicolonPos3 = buffer.indexOf(';', offset);
        if (semicolonPos3 === -1) break;
        
        // Extract value - for simplicity, we'll just get it as string
        let value = buffer.slice(offset, semicolonPos3).toString('utf8');
        value = value.replace(/\0/g, ''); // Remove null bytes
        
        // Create a policy item for this registry setting
        const policyItem = {
          state: 'enabled',
          name: `Registry Setting - ${valueName || 'Default'}`,
          kvps: [{
            key: keyPath,
            valueName: valueName || '(Default)',
            value: value || '',
            delete: false,
            lgpoType: convertRegTypeForTanium(valueType),
            presentationId: `${isMachinePolicy ? 'Machine' : 'User'}:${keyPath}:${valueName || 'Default'}`
          }],
          categoryPath: ['windows:Registry', isMachinePolicy ? 'windef:MachineSettings' : 'windef:UserSettings'],
          hasLgpo: true
        };
        
        // Add to our collection
        policyItems.push(policyItem);
        
        // Move past this entry
        offset = semicolonPos3 + 1;
      } catch (entryErr) {
        // If there's an error parsing one entry, try to continue with the next
        console.warn(`Error parsing entry in ${polPath}: ${entryErr.message}`);
        offset += 10; // Skip ahead a bit
      }
    }
  } catch (err) {
    console.warn(`Error reading registry.pol binary file at ${polPath}: ${err.message}`);
  }
}

/**
 * Helper function to convert registry type string to Tanium type
 */
function convertRegTypeForTanium(regTypeStr) {
  const regTypeMap = {
    'REG_SZ': 'ENFORCE_REG_SZ',
    'REG_EXPAND_SZ': 'ENFORCE_REG_EXPAND_SZ',
    'REG_BINARY': 'ENFORCE_REG_BINARY',
    'REG_DWORD': 'ENFORCE_REG_DWORD',
    'REG_MULTI_SZ': 'ENFORCE_REG_MULTI_SZ',
    'REG_QWORD': 'ENFORCE_REG_QWORD',
    'REG_NONE': 'ENFORCE_REG_NONE',
    'REG_DWORD_BIG_ENDIAN': 'ENFORCE_REG_DWORD'
  };
  
  return regTypeMap[regTypeStr] || 'ENFORCE_REG_SZ';
}

/**
 * Process policy extensions from GPO data
 */
function processPolicyExtensions(extensionData, policyItems, policyType) {
  if (!extensionData) return;

  // Handle case where there's a single extension or multiple extensions
  const extensions = Array.isArray(extensionData) ? extensionData : [extensionData];
  
  extensions.forEach(extension => {
    if (!extension || !extension.Extension) return;
    
    // Registry settings - different possible structures
    if (extension.Extension['q1:Policy'] || 
        extension.Extension['q4:Policy'] ||
        extension.Extension.Policy) {
      
      const policies = extension.Extension['q1:Policy'] || 
                      extension.Extension['q4:Policy'] ||
                      extension.Extension.Policy;
                      
      if (!policies) return;
      
      const policyArray = Array.isArray(policies) ? policies : [policies];
      
      policyArray.forEach(policy => {
        if (!policy) return;
        
        // Extract name and state with flexible property access
        const policyName = policy['q1:Name'] || policy['q4:Name'] || policy.Name || 'Unknown Policy';
        let policyState = (policy['q1:State'] || policy['q4:State'] || policy.State || '').toLowerCase();
        
        if (!policyState) {
          // Try to infer state from other fields
          policyState = 'enabled';
        }
        
        const policyItem = {
          state: policyState,
          name: policyName,
          kvps: [],
          categoryPath: getCategoryPath(policy['q1:Category'] || policy['q4:Category'] || policy.Category || ''),
          hasLgpo: true
        };
        
        // Build registry key (this helper already exists)
        const regKey = buildRegistryKeyFromCategory(policyItem.categoryPath);
        // Create a simple value name based on the policy name
        const valueName = getValueNameFromPolicyName(policyItem.name);
        
        policyItem.kvps.push({
          key: regKey,
          valueName: valueName,
          value: policyItem.state === 'enabled' ? "1" : "0",
          delete: false,
          lgpoType: "ENFORCE_REG_DWORD",
          // Updated presentationId generation using consistent delimiters and lower-case
          presentationId: `${policyItem.categoryPath.map(x => x.toLowerCase()).join(':')}:${valueName.toLowerCase()}`
        });
        
        policyItems.push(policyItem);
      });
    }
    
    // Internet Explorer settings
    if (extension.Extension['q3:InternetSettings'] ||
        extension.Extension.InternetSettings) {
      extractInternetExplorerSettings(
        extension.Extension['q3:InternetSettings'] || extension.Extension.InternetSettings, 
        policyItems
      );
    }
    
    // Windows Registry settings
    if (extension.Extension['q2:RegistrySettings'] ||
        extension.Extension.RegistrySettings) {
      extractRegistrySettings(
        extension.Extension['q2:RegistrySettings'] || extension.Extension.RegistrySettings, 
        policyItems
      );
    }
  });
}

/**
 * Extract Internet Explorer specific settings
 */
function extractInternetExplorerSettings(ieSettings, policyItems) {
  if (!ieSettings) return;
  
  const ieOptions = ieSettings['q3:InternetOptions'] || 
                   ieSettings.InternetOptions || 
                   ieSettings;
                   
  if (!ieOptions) return;
  
  // Try to navigate to IE10 settings or any version available
  const ieVersionSettings = ieOptions['q3:IE10'] || 
                          ieOptions.IE10 || 
                          Object.values(ieOptions).find(v => typeof v === 'object') ||
                          ieOptions;
                          
  if (!ieVersionSettings || !ieVersionSettings.Properties) return;
  
  const regSettings = ieVersionSettings.Properties.Reg || 
                     (ieVersionSettings.Properties && ieVersionSettings.Properties['q3:Reg']);
                     
  if (!regSettings) return;
  
  // Handle both array and single object
  const regArray = Array.isArray(regSettings) ? regSettings : [regSettings];
  
  regArray.forEach(reg => {
    // Skip disabled settings
    if ((reg.$ && reg.$.disabled === '1') || 
        (reg.disabled && reg.disabled === '1')) {
      return;
    }
    
    // Extract properties with flexible access
    const props = reg.$ || reg;
    const id = props.id || 'Setting';
    const key = props.key || props.hive || '';
    // FIXED: Use just the name part, not the full path
    const name = (props.name || '').split('\\').pop() || 'Setting';
    const value = props.value || '';
    const type = props.type || 'REG_SZ';
    
    const policyName = `Internet Explorer - ${id}`;
    const policyItem = {
      state: 'enabled',
      name: policyName,
      kvps: [{
        key: key,
        valueName: name,
        value: value,
        delete: false,
        lgpoType: getRegTypeForTanium(type),
        presentationId: `IE:${id}:${name}`
      }],
      categoryPath: ['windows:WindowsComponents', 'windef:InternetExplorer'],
      hasLgpo: true
    };
    
    policyItems.push(policyItem);
  });
}

/**
 * Extract Windows Registry settings
 */
function extractRegistrySettings(regSettings, policyItems) {
  if (!regSettings) return;
  
  const registryCollection = regSettings['q2:RegistrySettings'] || 
                           regSettings.RegistrySettings || 
                           regSettings;
                           
  if (!registryCollection) return;
  
  const collection = registryCollection['q2:Collection'] || 
                    registryCollection.Collection;
                    
  if (collection) {
    processRegistryCollections(collection, policyItems);
  }
}

/**
 * Process registry collections recursively
 */
function processRegistryCollections(collection, policyItems, parentPath = []) {
  if (!collection) return;
  
  // Handle both single and array collections
  const collections = Array.isArray(collection) ? collection : [collection];
  
  collections.forEach(coll => {
    // Extract collection name with flexible property access
    const props = coll.$ || coll;
    const collName = props.name || 'Unknown';
    
    const currentPath = [...parentPath, collName];
    
    // Process registry items
    const registryItems = coll['q2:Registry'] || coll.Registry;
    
    if (registryItems) {
      const registries = Array.isArray(registryItems) ? registryItems : [registryItems];
      
      registries.forEach(reg => {
        // Get properties with flexible access
        const regProps = reg['q2:Properties'] || reg.Properties || (reg.$ ? reg : {});
        const props = regProps.$ || regProps;
        
        if (!props) return;
        
        const regName = (reg.$ && reg.$.name) || (reg.name) || 'Value';
        const key = props.key || '';
        // FIXED: Use a simpler value name, extract from full path if needed
        let valueName = props.name || '';
        if (valueName.includes('\\')) {
          valueName = valueName.split('\\').pop() || 'Setting';
        } else if (valueName === key) {
          valueName = 'Enabled';
        }
        
        const value = props.value || '';
        const action = props.action || 'U';
        const type = props.type || 'REG_SZ';
        
        const policyItem = {
          state: 'enabled',
          name: `Registry Setting - ${regName}`,
          kvps: [{
            key: key,
            valueName: valueName,
            value: value || (type === 'REG_DWORD' ? '1' : ''),  // Default value based on type
            delete: action === 'D',
            lgpoType: getRegTypeForTanium(type),
            presentationId: `${currentPath.join('/')}:${regName}`
          }],
          categoryPath: currentPath,
          hasLgpo: true
        };
        
        policyItems.push(policyItem);
      });
    }
    
    // Recursively process sub-collections
    const subCollections = coll['q2:Collection'] || coll.Collection;
    if (subCollections) {
      processRegistryCollections(subCollections, policyItems, currentPath);
    }
  });
}

/**
 * Create the final Tanium policy JSON
 */
function createTaniumPolicy(gpoData, backupMetadata, policyItems) {
  // Set the creation and update timestamps to the current date/time
  const now = new Date().toISOString();

  // Try to get policy name from various possible locations
  let policyName = 'Converted GPO Policy';
  let policyGuid = null;
  
  if (gpoData.GPO && gpoData.GPO.Name) {
    policyName = gpoData.GPO.Name;
  } else if (
    gpoData.GroupPolicyBackupScheme &&
    gpoData.GroupPolicyBackupScheme.GroupPolicyObject &&
    gpoData.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings &&
    gpoData.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName
  ) {
    policyName = gpoData.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName;
  } else if (backupMetadata && backupMetadata.GPODisplayName) {
    policyName = backupMetadata.GPODisplayName;
  }
  
  // Remove CDATA or other wrapping if present
  if (typeof policyName === 'string') {
    policyName = policyName.replace(/^\s*\[?\s*CDATA\s*\[?\s*(.*?)\s*\]?\s*\]?\s*$/i, '$1');
    policyName = policyName.trim();
  }
  
  // Extract GUID if available
  if (gpoData.GPO && gpoData.GPO.Identifier && gpoData.GPO.Identifier.Identifier) {
    const identifier = gpoData.GPO.Identifier.Identifier;
    if (typeof identifier === 'object' && identifier._) {
      policyGuid = identifier._;
    } else if (typeof identifier === 'string') {
      policyGuid = identifier;
    } else {
      policyGuid = '';
    }
  } else if (backupMetadata && backupMetadata.GPOGuid) {
    policyGuid = backupMetadata.GPOGuid;
  }
  
  // Clean guid if needed
  if (typeof policyGuid === 'string') {
    policyGuid = policyGuid.replace(/^\s*\[?\s*CDATA\s*\[?\s*(.*?)\s*\]?\s*\]?\s*$/i, '$1');
    policyGuid = policyGuid.trim();
    policyGuid = policyGuid.replace(/[{}]/g, '');
  }
  
  // Set sequential priority for the current policy:
  const currentPriority = nextPriority;
  nextPriority++;

  // Build and return the final Tanium policy JSON
  return {
    id: null,
    created_at: now,
    updated_at: now,
    deletedAt: null,
    taniumUserId: 562,
    updatedByTaniumUserId: 562,
    changeType: "created",
    contentSetId: 105, // Using example value
    name: "GPO - " + policyName,
    description: `Converted from GPO: ${policyName} ${policyGuid ? ('(' + policyGuid + ')') : ''}`,
    version: 1,
    priority: currentPriority, // Assign sequential priority starting at 100
    typeId: 0,
    data: {
      policyItems: policyItems.length > 0 ? policyItems : [{
        state: "enabled",
        name: "Converted GPO Policy (No settings extracted)",
        kvps: [],
        categoryPath: ["windows:DefaultCategory"],
        hasLgpo: true
      }],
      useManagedDefinitions: false
    },
    isTemplate: false,
    priorityPool: 3,
    type: {
      id: 0,
      name: "admxMachine",
      initialContentSetName: "Enforce Windows",
      policyTypeContentSetName: "Enforce Windows Machine Administrative Templates",
      operatingSystem: "Windows",
      policyClass: "machine",
      endpointType: "cx",
      readPrivilege: "enforce policy read",
      writePrivilege: "enforce policy write",
      contentSetId: 105,
      policyTypeContentSetId: 276
    },
    hasEnforcements: false,
    taniumUsername: process.env.USER || "ConvertedUser",
    taniumUpdatedUsername: process.env.USER || "ConvertedUser",
    policySource: "standard"
  };
}

/**
 * Helper function to build a registry key from category path
 */
function buildRegistryKeyFromCategory(categoryPath) {
  if (!categoryPath || categoryPath.length === 0) {
    return "Software\\Policies\\Microsoft\\Windows";
  }
  
  // Extract component name from category path
  const component = categoryPath.find(part => part.includes(':')) || '';
  const componentName = component.split(':')[1] || '';
  
  if (componentName === 'InternetExplorer') {
    return "Software\\Policies\\Microsoft\\Internet Explorer";
  } else if (componentName === 'WindowsComponents') {
    return "Software\\Policies\\Microsoft\\Windows";
  }
  
  return `Software\\Policies\\Microsoft\\Windows\\${componentName}`;
}

/**
 * Helper function to get value name from policy name
 */
function getValueNameFromPolicyName(policyName) {
  if (!policyName) return 'Setting';
  
  // Convert policy name to a reasonable registry value name
  // This is FIXED to create cleaner value names
  const sanitized = policyName
    .replace(/\s+/g, '')
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/^(Disable|Enable)/, '');
    
  // If the result is empty or too short, use a default
  return sanitized.length > 2 ? sanitized : 'Setting';
}

/**
 * Helper function to parse category path
 */
function getCategoryPath(categoryString, registryKey) {
  // If the category pertains to SystemCertificates, check if additional container exists in the registryKey.
  // For example, if categoryString is "Disallowed" and the key has an extra element, use that.
  if (categoryString.trim().toLowerCase() === 'disallowed' && registryKey.includes('SystemCertificates')) {
    // Expected key format: 
    // "Software\Policies\Microsoft\SystemCertificates\Disallowed\<Container>"
    const parts = registryKey.split('\\');
    if (parts.length >= 6) {
      // Use the 5th part (index 4) as the confirmed base ("disallowed") and the 6th part as the container.
      return ['windows:Registry', 'windef:UserSettings', parts[4].toLowerCase(), parts[5].toLowerCase()];
    }
  }
  // Fall back to default behavior:
  if (!categoryString) return ['windows:DefaultCategory'];
  
  return categoryString.split('/').map((part, index) => {
    const normalizedPart = part.trim().replace(/\s+/g, '');
    if (index === 0) {
      return `windows:${normalizedPart}`;
    }
    return `windef:${normalizedPart.toLowerCase()}`;
  });
}

/**
 * Helper function to convert Windows registry types to Tanium registry types
 */
function getRegTypeForTanium(regType) {
  if (!regType) return 'ENFORCE_REG_SZ';
  
  switch (regType.toUpperCase()) {
    case 'REG_DWORD':
      return 'ENFORCE_REG_DWORD';
    case 'REG_SZ':
      return 'ENFORCE_REG_SZ';
    case 'REG_EXPAND_SZ':
      return 'ENFORCE_REG_EXPAND_SZ';
    case 'REG_MULTI_SZ':
      return 'ENFORCE_REG_MULTI_SZ';
    case 'REG_BINARY':
      return 'ENFORCE_REG_BINARY';
    case 'REG_QWORD':
      return 'ENFORCE_REG_QWORD';
    default:
      return 'ENFORCE_REG_SZ';
  }
}

/**
 * Helper function to sanitize filenames
 */
function sanitizeFilename(filename) {
  if (!filename) return 'converted_policy';
  
  return filename
    .replace(/[\/\\?%*:|"<>]/g, '-')
    .replace(/\s+/g, '_');
}

// Run the main function
main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});