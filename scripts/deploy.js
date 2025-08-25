#!/usr/bin/env node

/**
 * ABOUTME: Deployment script for the medium cybersecurity dashboard
 * ABOUTME: Handles GitHub Pages deployment with optimizations
 */

import { spawn, exec } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { Builder } from './build.js';

const DEPLOY_CONFIG = {
  branch: 'gh-pages',
  buildDir: './dist',
  tempDir: './temp-deploy',
  commitMessage: 'Deploy cybersecurity dashboard',
  excludeFiles: [
    '.git',
    'node_modules',
    'scripts',
    'main.go',
    'go.mod',
    '*.log',
    'temp-deploy',
  ],
};

class Deployer {
  constructor() {
    this.warnings = [];
    this.errors = [];
  }

  async deploy() {
    try {
      console.log('🚀 Starting deployment process...');
      
      await this.validateEnvironment();
      await this.buildProject();
      await this.prepareDeployment();
      await this.deployToGitHub();
      await this.cleanup();
      
      console.log('✅ Deployment completed successfully!');
      this.printSummary();
      
    } catch (error) {
      console.error('❌ Deployment failed:', error);
      await this.cleanup();
      throw error;
    }
  }

  async validateEnvironment() {
    console.log('🔍 Validating environment...');
    
    try {
      // Check if git is available
      await this.runCommand('git --version');
      console.log('✅ Git is available');
      
      // Check if we're in a git repository
      await this.runCommand('git rev-parse --git-dir');
      console.log('✅ In a git repository');
      
      // Check for uncommitted changes
      const status = await this.runCommand('git status --porcelain');
      if (status.trim()) {
        this.warnings.push('Uncommitted changes detected');
        console.log('⚠️  Uncommitted changes detected');
      }
      
      // Check current branch
      const branch = await this.runCommand('git branch --show-current');
      console.log(`📍 Current branch: ${branch.trim()}`);
      
      // Check if remote origin exists
      try {
        const remote = await this.runCommand('git remote get-url origin');
        console.log(`🌐 Remote origin: ${remote.trim()}`);
      } catch (error) {
        this.errors.push('No remote origin configured');
        throw new Error('Git remote origin is required for deployment');
      }
      
    } catch (error) {
      this.errors.push(`Environment validation failed: ${error.message}`);
      throw error;
    }
  }

  async buildProject() {
    console.log('🏗️  Building project...');
    
    try {
      const builder = new Builder();
      await builder.build();
      
      // Verify build output
      await fs.access(DEPLOY_CONFIG.buildDir);
      console.log('✅ Build completed');
      
    } catch (error) {
      this.errors.push(`Build failed: ${error.message}`);
      throw error;
    }
  }

  async prepareDeployment() {
    console.log('📦 Preparing deployment...');
    
    try {
      // Clean temp directory
      await fs.rm(DEPLOY_CONFIG.tempDir, { recursive: true, force: true });
      await fs.mkdir(DEPLOY_CONFIG.tempDir, { recursive: true });
      
      // Copy build output to temp directory
      await this.copyDirectory(DEPLOY_CONFIG.buildDir, DEPLOY_CONFIG.tempDir);
      
      // Create .nojekyll file for GitHub Pages
      await fs.writeFile(path.join(DEPLOY_CONFIG.tempDir, '.nojekyll'), '');
      
      // Create CNAME file if needed (uncomment if you have a custom domain)
      // await fs.writeFile(path.join(DEPLOY_CONFIG.tempDir, 'CNAME'), 'your-domain.com');
      
      // Add deployment timestamp
      const deployInfo = {
        deployedAt: new Date().toISOString(),
        commit: await this.runCommand('git rev-parse HEAD').then(h => h.trim()),
        branch: await this.runCommand('git branch --show-current').then(b => b.trim()),
        nodeVersion: process.version,
      };
      
      await fs.writeFile(
        path.join(DEPLOY_CONFIG.tempDir, 'deploy-info.json'),
        JSON.stringify(deployInfo, null, 2)
      );
      
      console.log('✅ Deployment prepared');
      
    } catch (error) {
      this.errors.push(`Deployment preparation failed: ${error.message}`);
      throw error;
    }
  }

  async deployToGitHub() {
    console.log('🌐 Deploying to GitHub Pages...');
    
    try {
      const originalBranch = await this.runCommand('git branch --show-current').then(b => b.trim());
      
      // Check if gh-pages branch exists
      let branchExists = false;
      try {
        await this.runCommand(`git show-ref --verify --quiet refs/heads/${DEPLOY_CONFIG.branch}`);
        branchExists = true;
      } catch {
        branchExists = false;
      }
      
      if (branchExists) {
        // Switch to gh-pages branch
        await this.runCommand(`git checkout ${DEPLOY_CONFIG.branch}`);
        console.log(`✅ Switched to ${DEPLOY_CONFIG.branch} branch`);
        
        // Remove all files except .git
        const files = await fs.readdir('.');
        for (const file of files) {
          if (file !== '.git' && file !== DEPLOY_CONFIG.tempDir) {
            await fs.rm(file, { recursive: true, force: true });
          }
        }
        
      } else {
        // Create orphan gh-pages branch
        await this.runCommand(`git checkout --orphan ${DEPLOY_CONFIG.branch}`);
        await this.runCommand('git rm -rf .');
        console.log(`✅ Created new ${DEPLOY_CONFIG.branch} branch`);
      }
      
      // Copy files from temp directory
      const tempFiles = await fs.readdir(DEPLOY_CONFIG.tempDir);
      for (const file of tempFiles) {
        const srcPath = path.join(DEPLOY_CONFIG.tempDir, file);
        await this.copyDirectory(srcPath, file);
      }
      
      // Add and commit files
      await this.runCommand('git add -A');
      
      // Check if there are changes to commit
      const status = await this.runCommand('git status --porcelain');
      if (!status.trim()) {
        console.log('⚠️  No changes to deploy');
        await this.runCommand(`git checkout ${originalBranch}`);
        return;
      }
      
      const commitMessage = `${DEPLOY_CONFIG.commitMessage} - ${new Date().toISOString()}`;
      await this.runCommand(`git commit -m "${commitMessage}"`);
      
      // Push to remote
      await this.runCommand(`git push -u origin ${DEPLOY_CONFIG.branch}`);
      
      console.log('✅ Pushed to GitHub Pages');
      
      // Switch back to original branch
      await this.runCommand(`git checkout ${originalBranch}`);
      console.log(`✅ Switched back to ${originalBranch} branch`);
      
    } catch (error) {
      this.errors.push(`GitHub deployment failed: ${error.message}`);
      throw error;
    }
  }

  async copyDirectory(src, dest) {
    const stat = await fs.stat(src);
    
    if (stat.isDirectory()) {
      await fs.mkdir(dest, { recursive: true });
      
      const entries = await fs.readdir(src);
      for (const entry of entries) {
        const srcPath = path.join(src, entry);
        const destPath = path.join(dest, entry);
        await this.copyDirectory(srcPath, destPath);
      }
    } else {
      await fs.copyFile(src, dest);
    }
  }

  async cleanup() {
    console.log('🧹 Cleaning up...');
    
    try {
      await fs.rm(DEPLOY_CONFIG.tempDir, { recursive: true, force: true });
      console.log('✅ Cleanup completed');
    } catch (error) {
      this.warnings.push(`Cleanup failed: ${error.message}`);
    }
  }

  async runCommand(command) {
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
      });
    });
  }

  printSummary() {
    console.log('\\n📊 Deployment Summary:');
    
    if (this.errors.length > 0) {
      console.log(`❌ Errors: ${this.errors.length}`);
      this.errors.forEach(error => console.log(`   ${error}`));
    }
    
    if (this.warnings.length > 0) {
      console.log(`⚠️  Warnings: ${this.warnings.length}`);
      this.warnings.forEach(warning => console.log(`   ${warning}`));
    }
    
    if (this.errors.length === 0) {
      console.log('🎉 Deployment successful!');
      console.log('🌐 Your site should be available at: https://kdairatchi.github.io/medium-writeups/');
      console.log('⏰ GitHub Pages may take a few minutes to update');
    }
  }
}

// Main execution
async function main() {
  try {
    const deployer = new Deployer();
    await deployer.deploy();
    
    if (deployer.errors.length > 0) {
      process.exit(1);
    }
    
  } catch (error) {
    console.error('❌ Deployment failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { Deployer };