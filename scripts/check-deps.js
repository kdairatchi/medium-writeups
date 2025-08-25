#!/usr/bin/env node

/**
 * ABOUTME: Dependency checker for the medium cybersecurity dashboard
 * ABOUTME: Validates package versions, security vulnerabilities, and license compliance
 */

import { promises as fs } from 'fs';
import { spawn } from 'child_process';
import path from 'path';

const CHECK_CONFIG = {
  packageFile: './package.json',
  lockFile: './package-lock.json',
  securityCheck: true,
  licenseCheck: true,
  outdatedCheck: true,
  allowedLicenses: [
    'MIT',
    'ISC', 
    'BSD-2-Clause',
    'BSD-3-Clause',
    'Apache-2.0',
    'CC0-1.0',
    'Unlicense',
  ],
};

class DependencyChecker {
  constructor() {
    this.warnings = [];
    this.errors = [];
    this.info = [];
    this.dependencies = new Map();
  }

  async check() {
    try {
      console.log('🔍 Starting dependency check...');
      
      await this.loadPackageInfo();
      await this.checkSecurity();
      await this.checkOutdated();
      await this.checkLicenses();
      await this.checkDuplicates();
      await this.generateReport();
      
      this.printSummary();
      
    } catch (error) {
      console.error('❌ Dependency check failed:', error);
      throw error;
    }
  }

  async loadPackageInfo() {
    console.log('📦 Loading package information...');
    
    try {
      // Load package.json
      const packageData = await fs.readFile(CHECK_CONFIG.packageFile, 'utf8');
      const packageJson = JSON.parse(packageData);
      
      console.log(`✅ Package: ${packageJson.name}@${packageJson.version}`);
      console.log(`📝 Dependencies: ${Object.keys(packageJson.dependencies || {}).length}`);
      console.log(`🛠️  Dev Dependencies: ${Object.keys(packageJson.devDependencies || {}).length}`);
      
      // Load lock file if it exists
      try {
        const lockData = await fs.readFile(CHECK_CONFIG.lockFile, 'utf8');
        const lockJson = JSON.parse(lockData);
        console.log(`🔒 Lock file version: ${lockJson.lockfileVersion}`);
        
        this.info.push(`Package has ${Object.keys(lockJson.packages || {}).length} locked packages`);
        
      } catch (error) {
        this.warnings.push('No package-lock.json found');
      }
      
    } catch (error) {
      this.errors.push(`Failed to load package info: ${error.message}`);
      throw error;
    }
  }

  async checkSecurity() {
    if (!CHECK_CONFIG.securityCheck) return;
    
    console.log('🔒 Checking for security vulnerabilities...');
    
    try {
      const result = await this.runCommand('npm audit --json');
      const auditData = JSON.parse(result);
      
      if (auditData.vulnerabilities) {
        const vulnCount = Object.keys(auditData.vulnerabilities).length;
        
        if (vulnCount === 0) {
          console.log('✅ No security vulnerabilities found');
        } else {
          console.log(`⚠️  Found ${vulnCount} security vulnerabilities`);
          
          // Count by severity
          const severities = {};
          Object.values(auditData.vulnerabilities).forEach(vuln => {
            const severity = vuln.severity || 'unknown';
            severities[severity] = (severities[severity] || 0) + 1;
          });
          
          Object.entries(severities).forEach(([severity, count]) => {
            const message = `${count} ${severity} vulnerability(ies)`;
            if (severity === 'critical' || severity === 'high') {
              this.errors.push(message);
            } else {
              this.warnings.push(message);
            }
            console.log(`   ${severity}: ${count}`);
          });
        }
      }
      
    } catch (error) {
      if (error.code === 1) {
        // npm audit returns exit code 1 when vulnerabilities are found
        try {
          const auditData = JSON.parse(error.stdout);
          if (auditData.metadata && auditData.metadata.vulnerabilities) {
            const total = auditData.metadata.vulnerabilities.total;
            this.warnings.push(`${total} security vulnerabilities found`);
            console.log(`⚠️  Found ${total} security vulnerabilities`);
          }
        } catch {
          this.warnings.push('Security audit completed with issues');
        }
      } else {
        this.warnings.push(`Security check failed: ${error.message}`);
      }
    }
  }

  async checkOutdated() {
    if (!CHECK_CONFIG.outdatedCheck) return;
    
    console.log('📅 Checking for outdated packages...');
    
    try {
      const result = await this.runCommand('npm outdated --json');
      const outdatedData = JSON.parse(result || '{}');
      
      const outdatedPackages = Object.keys(outdatedData);
      
      if (outdatedPackages.length === 0) {
        console.log('✅ All packages are up to date');
      } else {
        console.log(`⚠️  Found ${outdatedPackages.length} outdated packages`);
        
        outdatedPackages.slice(0, 5).forEach(pkg => {
          const info = outdatedData[pkg];
          console.log(`   ${pkg}: ${info.current} → ${info.latest}`);
        });
        
        if (outdatedPackages.length > 5) {
          console.log(`   ... and ${outdatedPackages.length - 5} more`);
        }
        
        this.info.push(`${outdatedPackages.length} packages can be updated`);
      }
      
    } catch (error) {
      if (error.code === 1) {
        // npm outdated returns exit code 1 when outdated packages are found
        this.info.push('Some packages may be outdated');
      } else {
        this.warnings.push(`Outdated check failed: ${error.message}`);
      }
    }
  }

  async checkLicenses() {
    if (!CHECK_CONFIG.licenseCheck) return;
    
    console.log('📜 Checking package licenses...');
    
    try {
      // Get list of all packages and their licenses
      const result = await this.runCommand('npm list --json --depth=0');
      const listData = JSON.parse(result);
      
      const licenses = new Map();
      const problematicPackages = [];
      
      if (listData.dependencies) {
        for (const [name, info] of Object.entries(listData.dependencies)) {
          try {
            // Get package info
            const pkgResult = await this.runCommand(`npm view ${name} license --json`);
            const license = JSON.parse(pkgResult);
            
            const licenseKey = Array.isArray(license) ? license.join(', ') : (license || 'Unknown');
            licenses.set(licenseKey, (licenses.get(licenseKey) || 0) + 1);
            
            // Check if license is allowed
            const isAllowed = CHECK_CONFIG.allowedLicenses.some(allowed => 
              licenseKey.toLowerCase().includes(allowed.toLowerCase())
            );
            
            if (!isAllowed && licenseKey !== 'Unknown') {
              problematicPackages.push({ name, license: licenseKey });
            }
            
          } catch (error) {
            this.warnings.push(`Could not check license for ${name}`);
          }
        }
      }
      
      // Report license summary
      console.log(`✅ Found ${licenses.size} different license types`);
      licenses.forEach((count, license) => {
        console.log(`   ${license}: ${count} package(s)`);
      });
      
      if (problematicPackages.length > 0) {
        console.log(`⚠️  Found ${problematicPackages.length} packages with non-standard licenses`);
        problematicPackages.forEach(({ name, license }) => {
          this.warnings.push(`${name}: ${license}`);
        });
      }
      
    } catch (error) {
      this.warnings.push(`License check failed: ${error.message}`);
    }
  }

  async checkDuplicates() {
    console.log('🔍 Checking for duplicate packages...');
    
    try {
      const result = await this.runCommand('npm list --json --all');
      const listData = JSON.parse(result);
      
      const packageVersions = new Map();
      
      const collectPackages = (deps, path = []) => {
        if (!deps) return;
        
        Object.entries(deps).forEach(([name, info]) => {
          const version = info.version;
          if (version) {
            if (!packageVersions.has(name)) {
              packageVersions.set(name, new Set());
            }
            packageVersions.get(name).add(version);
          }
          
          if (info.dependencies) {
            collectPackages(info.dependencies, [...path, name]);
          }
        });
      };
      
      collectPackages(listData.dependencies);
      
      const duplicates = Array.from(packageVersions.entries())
        .filter(([name, versions]) => versions.size > 1)
        .map(([name, versions]) => ({ name, versions: Array.from(versions) }));
      
      if (duplicates.length === 0) {
        console.log('✅ No duplicate packages found');
      } else {
        console.log(`⚠️  Found ${duplicates.length} packages with multiple versions`);
        duplicates.slice(0, 5).forEach(({ name, versions }) => {
          console.log(`   ${name}: ${versions.join(', ')}`);
          this.warnings.push(`Multiple versions of ${name}: ${versions.join(', ')}`);
        });
        
        if (duplicates.length > 5) {
          console.log(`   ... and ${duplicates.length - 5} more`);
        }
      }
      
    } catch (error) {
      this.warnings.push(`Duplicate check failed: ${error.message}`);
    }
  }

  async generateReport() {
    console.log('📊 Generating dependency report...');
    
    try {
      const report = {
        checkTime: new Date().toISOString(),
        nodeVersion: process.version,
        npmVersion: await this.runCommand('npm --version').then(v => v.trim()),
        summary: {
          errors: this.errors.length,
          warnings: this.warnings.length,
          info: this.info.length,
        },
        issues: {
          errors: this.errors,
          warnings: this.warnings,
          info: this.info,
        },
      };
      
      await fs.writeFile('dependency-report.json', JSON.stringify(report, null, 2));
      console.log('✅ Report saved to dependency-report.json');
      
    } catch (error) {
      this.warnings.push(`Failed to generate report: ${error.message}`);
    }
  }

  async runCommand(command) {
    return new Promise((resolve, reject) => {
      const child = spawn('sh', ['-c', command], { 
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf8'
      });
      
      let stdout = '';
      let stderr = '';
      
      child.stdout.on('data', (data) => {
        stdout += data;
      });
      
      child.stderr.on('data', (data) => {
        stderr += data;
      });
      
      child.on('close', (code) => {
        if (code === 0 || (code === 1 && stdout)) {
          // Some commands return code 1 but still provide valid output
          resolve(stdout.trim());
        } else {
          const error = new Error(stderr.trim() || `Command failed with code ${code}`);
          error.code = code;
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
        }
      });
    });
  }

  printSummary() {
    console.log('\\n📊 Dependency Check Summary:');
    
    if (this.errors.length > 0) {
      console.log(`❌ Errors: ${this.errors.length}`);
      this.errors.slice(0, 3).forEach(error => console.log(`   ${error}`));
      if (this.errors.length > 3) {
        console.log(`   ... and ${this.errors.length - 3} more errors`);
      }
    }
    
    if (this.warnings.length > 0) {
      console.log(`⚠️  Warnings: ${this.warnings.length}`);
      this.warnings.slice(0, 3).forEach(warning => console.log(`   ${warning}`));
      if (this.warnings.length > 3) {
        console.log(`   ... and ${this.warnings.length - 3} more warnings`);
      }
    }
    
    if (this.info.length > 0) {
      console.log(`ℹ️  Info: ${this.info.length}`);
      this.info.forEach(info => console.log(`   ${info}`));
    }
    
    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('✅ All dependency checks passed!');
    }
    
    console.log('\\n💡 Recommendations:');
    if (this.errors.length > 0) {
      console.log('   Run "npm audit fix" to address security vulnerabilities');
    }
    if (this.warnings.length > 0) {
      console.log('   Run "npm update" to update outdated packages');
    }
    console.log('   Check dependency-report.json for detailed analysis');
  }
}

// Main execution
async function main() {
  try {
    const checker = new DependencyChecker();
    await checker.check();
    
    if (checker.errors.length > 0) {
      console.log('\\n❌ Dependency check completed with errors!');
      process.exit(1);
    }
    
    console.log('\\n✅ Dependency check completed successfully!');
    
  } catch (error) {
    console.error('❌ Dependency check failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { DependencyChecker };